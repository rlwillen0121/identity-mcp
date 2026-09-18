package idmcp

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const DefaultLimit = 50
const MaxLimit = 200

type Client struct {
	HTTP    *http.Client
	BaseURL string
	Header  http.Header
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

func ClampLimit(n int) int {
	if n <= 0 {
		return DefaultLimit
	}
	if n > MaxLimit {
		return MaxLimit
	}
	return n
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
	u := path
	if !strings.HasPrefix(path, "http://") && !strings.HasPrefix(path, "https://") {
		if !strings.HasPrefix(path, "/") {
			path = "/" + path
		}
		u = c.BaseURL + path
	}
	if len(query) > 0 {
		if strings.Contains(u, "?") {
			u += "&" + query.Encode()
		} else {
			u += "?" + query.Encode()
		}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, nil, err
	}
	req.Header = c.Header.Clone()
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
		return body, resp.Header, fmt.Errorf("%s %s: %s: %s", req.Method, req.URL.Path, resp.Status, msg)
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
		return body, fmt.Errorf("POST %s: %s: %s", rawURL, resp.Status, msg)
	}
	return body, nil
}

func LinkHeader(hdr http.Header, rel string) string {
	for _, part := range strings.Split(hdr.Get("Link"), ",") {
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
