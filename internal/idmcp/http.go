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
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return fmt.Errorf("%s must be an https URL", name)
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

func (c *Client) Get(ctx context.Context, path string, query url.Values) ([]byte, http.Header, error) {
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
	if c.Auth != nil {
		if t := c.Auth(); t != "" {
			req.Header.Set("Authorization", t)
		}
	}
	resp, err := c.HTTP.Do(req)
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
	resp, err := c.HTTP.Do(req)
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
