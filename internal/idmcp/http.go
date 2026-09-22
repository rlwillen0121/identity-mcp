package idmcp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const DefaultLimit = 50
const MaxLimit = 200
const MaxStalePages = 10

type HTTPError struct {
	Method string
	Path   string
	Status int
	Body   string
}

func (e *HTTPError) Error() string {
	return fmt.Sprintf("%s %s: %d %s: %s", e.Method, e.Path, e.Status, http.StatusText(e.Status), e.Body)
}

func StatusOf(err error) int {
	var he *HTTPError
	if errors.As(err, &he) {
		return he.Status
	}
	return 0
}

type Client struct {
	HTTP    *http.Client
	BaseURL string
	Header  http.Header
	// Auth, if set, supplies Authorization per request and is never stored on Header.
	Auth func() string
}

func NewClient(baseURL string, header http.Header) *Client {
	h := header.Clone()
	if h == nil {
		h = make(http.Header)
	}
	if h.Get("Accept") == "" {
		h.Set("Accept", "application/json")
	}
	return &Client{
		HTTP:    &http.Client{Timeout: 30 * time.Second},
		BaseURL: strings.TrimRight(baseURL, "/"),
		Header:  h,
	}
}

func RequireHTTPS(name, raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return fmt.Errorf("%s must be an https URL", name)
	}
	return nil
}

// ValidateOktaBaseURL validates the authority used by the production Okta
// entrypoint. Test callers should use NewClient directly with an injected
// HTTP client/server; they must not weaken the production command boundary.
// A custom endpoint is accepted only when the caller explicitly opts in.
func ValidateOktaBaseURL(raw string, allowCustom bool) error {
	if err := RequireHTTPS("OKTA_ORG_URL", raw); err != nil {
		return err
	}
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("OKTA_ORG_URL must be an https URL")
	}
	if allowCustom {
		return nil
	}
	if u.Port() != "" {
		return fmt.Errorf("OKTA_ORG_URL must not specify a port")
	}
	if p := strings.Trim(u.Path, "/"); p != "" {
		return fmt.Errorf("OKTA_ORG_URL must not include a path")
	}
	host := strings.ToLower(u.Hostname())
	for _, suffix := range []string{".okta.com", ".oktapreview.com", ".okta-emea.com", ".okta-gov.com"} {
		if strings.HasSuffix(host, suffix) && len(host) > len(suffix) {
			return nil
		}
	}
	return fmt.Errorf("OKTA_ORG_URL host %q is not a recognized Okta authority", u.Hostname())
}

// ValidateGraphBaseURL validates the authority used by the production Graph
// entrypoint. The path is restricted to the public Graph API versions while
// custom/private deployments require an explicit opt-in.
func ValidateGraphBaseURL(raw string, allowCustom bool) error {
	if err := RequireHTTPS("GRAPH_BASE_URL", raw); err != nil {
		return err
	}
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("GRAPH_BASE_URL must be an https URL")
	}
	if allowCustom {
		return nil
	}
	if u.Port() != "" {
		return fmt.Errorf("GRAPH_BASE_URL must not specify a port")
	}
	path := strings.TrimRight(u.Path, "/")
	if path != "/v1.0" && path != "/beta" {
		return fmt.Errorf("GRAPH_BASE_URL path must be /v1.0 or /beta")
	}
	// The client currently requests the public-cloud scope and token authority
	// (login.microsoftonline.com). Do not advertise sovereign Graph hosts until
	// their matching authority and resource scope are wired as one configuration.
	allowed := map[string]struct{}{"graph.microsoft.com": {}}
	if _, ok := allowed[strings.ToLower(u.Hostname())]; !ok {
		return fmt.Errorf("GRAPH_BASE_URL host %q is not a recognized Microsoft Graph authority", u.Hostname())
	}
	return nil
}

func ClampLimit(n int) int {
	if n <= 0 {
		return DefaultLimit
	}
	if n > MaxLimit {
		return MaxLimit
	}
	return n
}

// OpaqueCursor returns a pagination token. Absolute URLs are not fetched; if they
// contain query param `param` (or $skiptoken), that value is used. Otherwise they error.
func OpaqueCursor(raw, param string) (string, error) {
	if raw == "" {
		return "", nil
	}
	if !strings.Contains(raw, "://") {
		return raw, nil
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("invalid cursor")
	}
	q := u.Query()
	if param != "" {
		if v := q.Get(param); v != "" {
			return v, nil
		}
	}
	if v := q.Get("$skiptoken"); v != "" {
		return v, nil
	}
	if v := q.Get("$skipToken"); v != "" {
		return v, nil
	}
	return "", fmt.Errorf("cursor must be an opaque token, not a URL")
}

func (c *Client) GetJSON(ctx context.Context, path string, query url.Values, dest any) (http.Header, error) {
	body, hdr, err := c.Get(ctx, path, query)
	if err != nil {
		return hdr, err
	}
	if dest == nil {
		return hdr, nil
	}
	if err := json.Unmarshal(body, dest); err != nil {
		return hdr, fmt.Errorf("decode %s: %w", path, err)
	}
	return hdr, nil
}

// GetJSONWithAuth performs one request with an explicit Authorization value.
// It does not mutate Header or invoke Auth, which lets token clients safely
// retry with the exact token selected for a request.
func (c *Client) GetJSONWithAuth(ctx context.Context, path string, query url.Values, authorization string, dest any) (http.Header, error) {
	body, hdr, err := c.getWithAuth(ctx, path, query, authorization, true)
	if err != nil {
		return hdr, err
	}
	if dest == nil {
		return hdr, nil
	}
	if err := json.Unmarshal(body, dest); err != nil {
		return hdr, fmt.Errorf("decode %s: %w", path, err)
	}
	return hdr, nil
}

func (c *Client) Get(ctx context.Context, path string, query url.Values) ([]byte, http.Header, error) {
	return c.getWithAuth(ctx, path, query, "", false)
}

func (c *Client) getWithAuth(ctx context.Context, path string, query url.Values, authorization string, explicitAuth bool) ([]byte, http.Header, error) {
	if strings.Contains(path, "://") {
		return nil, nil, fmt.Errorf("refusing to fetch absolute URL %q; pass an opaque cursor", path)
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	u := c.BaseURL + path
	if len(query) > 0 {
		u += "?" + query.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, nil, err
	}
	req.Header = c.Header.Clone()
	if explicitAuth {
		req.Header.Del("Authorization")
		if authorization != "" {
			req.Header.Set("Authorization", authorization)
		}
	} else if c.Auth != nil {
		if t := c.Auth(); t != "" {
			req.Header.Set("Authorization", t)
		}
	}
	resp, err := c.doNoRedirect(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return nil, resp.Header, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		msg := strings.TrimSpace(string(body))
		if len(msg) > 800 {
			msg = msg[:800] + "…"
		}
		return body, resp.Header, &HTTPError{Method: req.Method, Path: req.URL.Path, Status: resp.StatusCode, Body: msg}
	}
	return body, resp.Header, nil
}

func (c *Client) PostForm(ctx context.Context, rawURL string, form url.Values) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, rawURL, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header = c.Header.Clone()
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if c.Auth != nil {
		if t := c.Auth(); t != "" {
			req.Header.Set("Authorization", t)
		}
	}
	// A token form contains client_secret. Never follow a redirect that could
	// replay that body to another authority (307/308 preserve method and body).
	resp, err := c.doNoRedirect(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		msg := strings.TrimSpace(string(body))
		if len(msg) > 800 {
			msg = msg[:800] + "…"
		}
		return body, &HTTPError{Method: http.MethodPost, Path: rawURL, Status: resp.StatusCode, Body: msg}
	}
	return body, nil
}

// doNoRedirect keeps credential-bearing requests on the exact URL selected by
// the caller. The per-request copy preserves any injected transport and avoids
// mutating the shared http.Client or racing with other requests.
func (c *Client) doNoRedirect(req *http.Request) (*http.Response, error) {
	httpClient := *c.HTTP
	httpClient.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}
	return httpClient.Do(req)
}

func LinkHeader(hdr http.Header, rel string) string {
	if hdr == nil {
		return ""
	}
	// Okta sends pagination as separate Link header lines (rel=self then rel=next).
	// Header.Get returns only the first line; Values joins every line.
	for _, part := range strings.Split(strings.Join(hdr.Values("Link"), ","), ",") {
		part = strings.TrimSpace(part)
		if strings.Contains(part, `rel="`+rel+`"`) {
			if i := strings.Index(part, "<"); i >= 0 {
				if j := strings.Index(part, ">"); j > i {
					return part[i+1 : j]
				}
			}
		}
	}
	return ""
}
