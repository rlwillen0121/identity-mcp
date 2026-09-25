package idmcp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const DefaultLimit = 50
const MaxLimit = 200
const MaxStalePages = 10

type HTTPError struct {
	Method     string
	Path       string
	Status     int
	Body       string
	RetryAfter string
}

func (e *HTTPError) Error() string {
	msg := fmt.Sprintf("%s %s: %d %s: %s", e.Method, e.Path, e.Status, http.StatusText(e.Status), e.Body)
	if e.RetryAfter != "" {
		msg += "; retry after " + e.RetryAfter
	}
	return msg
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
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil {
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

func ClampSize(n, max int) int {
	if max <= 0 || max > MaxLimit {
		max = MaxLimit
	}
	if n <= 0 {
		if max < DefaultLimit {
			return max
		}
		return DefaultLimit
	}
	if n > max {
		return max
	}
	return n
}

func ParseIntCursor(s string) (int, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, nil
	}
	n, err := strconv.Atoi(s)
	if err != nil {
		return 0, fmt.Errorf("cursor must be an integer")
	}
	if n < 0 {
		return 0, fmt.Errorf("cursor must not be negative")
	}
	return n, nil
}

func NextPage(page, pages int) string {
	if pages > 0 && page < pages {
		return strconv.Itoa(page + 1)
	}
	return ""
}

func NextOffset(offset, n, limit int) string {
	if n == limit && limit > 0 {
		return strconv.Itoa(offset + n)
	}
	return ""
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
	auth := c.setAuth(req)
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, nil, redactPlain(err, auth)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return nil, resp.Header, redactPlain(err, auth)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return body, resp.Header, httpErr(req.Method, req.URL.Path, resp.StatusCode, body, resp.Header, auth)
	}
	return body, resp.Header, nil
}

func (c *Client) PostJSON(ctx context.Context, path string, body any, dest any) (http.Header, error) {
	if err := allowPostPath(path); err != nil {
		return nil, err
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	payload, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("encode json: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.BaseURL+path, bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	req.Header = c.Header.Clone()
	auth := c.setAuth(req)
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, redactPlain(err, auth)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return resp.Header, redactPlain(err, auth)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return resp.Header, httpErr(req.Method, req.URL.Path, resp.StatusCode, raw, resp.Header, auth)
	}
	if dest == nil {
		return resp.Header, nil
	}
	if err := json.Unmarshal(raw, dest); err != nil {
		return resp.Header, redactPlain(fmt.Errorf("decode %s: %w", path, err), auth)
	}
	return resp.Header, nil
}

func (c *Client) PostForm(ctx context.Context, rawURL string, form url.Values) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, rawURL, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header = c.Header.Clone()
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	auth := c.setAuth(req)
	// Copy so a 307/308 cannot replay the form body, including client_secret, to Location.
	resp, err := noRedirectClient(c.HTTP).Do(req)
	if err != nil {
		return nil, redactPlain(err, auth)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	if err != nil {
		return nil, redactPlain(err, auth)
	}
	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		// Status only: the response may echo the form body.
		return nil, redactPlain(fmt.Errorf("POST %s: %d %s", rawURL, resp.StatusCode, http.StatusText(resp.StatusCode)), auth)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return body, httpErr(http.MethodPost, rawURL, resp.StatusCode, body, resp.Header, auth)
	}
	return body, nil
}

func noRedirectClient(base *http.Client) *http.Client {
	if base == nil {
		base = &http.Client{Timeout: 30 * time.Second}
	}
	hc := *base
	hc.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}
	return &hc
}

func (c *Client) setAuth(req *http.Request) string {
	if c.Auth != nil {
		if t := c.Auth(); t != "" {
			req.Header.Set("Authorization", t)
			return t
		}
	}
	return req.Header.Get("Authorization")
}

func allowPostPath(path string) error {
	if strings.Contains(path, "://") {
		return fmt.Errorf("refusing to fetch absolute URL %q; pass an opaque cursor", path)
	}
	p, _, _ := strings.Cut(path, "?")
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	if p == "/search" || strings.HasPrefix(p, "/api/v1/search/") {
		return nil
	}
	return fmt.Errorf("refusing to POST %q; only search endpoints are allowed", path)
}

func httpErr(method, path string, status int, body []byte, hdr http.Header, auth string) *HTTPError {
	msg := redactAuth(strings.TrimSpace(string(body)), auth)
	path = redactAuth(path, auth)
	if len(msg) > 800 {
		msg = msg[:800] + "…"
	}
	retry := ""
	if hdr != nil {
		retry = hdr.Get("Retry-After")
	}
	return &HTTPError{Method: method, Path: path, Status: status, Body: msg, RetryAfter: retry}
}

func redactPlain(err error, auth string) error {
	if err == nil || auth == "" {
		return err
	}
	msg := redactAuth(err.Error(), auth)
	if msg == err.Error() {
		return err
	}
	return fmt.Errorf("%s", msg)
}

func redactAuth(msg, auth string) string {
	if msg == "" || auth == "" {
		return msg
	}
	msg = redactOne(msg, auth)
	if raw, ok := strings.CutPrefix(auth, "Bearer "); ok {
		msg = redactOne(msg, raw)
	}
	return msg
}

func redactOne(msg, secret string) string {
	if secret == "" {
		return msg
	}
	msg = strings.ReplaceAll(msg, secret, "[redacted]")
	if enc := url.QueryEscape(secret); enc != secret {
		msg = strings.ReplaceAll(msg, enc, "[redacted]")
	}
	return msg
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
