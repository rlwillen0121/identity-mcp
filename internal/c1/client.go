package c1

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/rlwillen0121/identity-mcp/internal/idmcp"
)

const tokenSkew = 60 * time.Second

const (
	defaultPageSize = 50
	minPageSize     = 10
	maxPageSize     = 100
	taskMaxPageSize = 10
	accessCap       = 50
	stalePageSize   = 50
	staleScanCap    = 500
)

type Config struct {
	ClientID     string
	ClientSecret string
	BaseURL      string
	TokenURL     string
	HTTP         *http.Client
}

type Client struct {
	api          *idmcp.Client
	tokenHTTP    *idmcp.Client
	tokenURL     string
	clientID     string
	clientSecret string

	mu     sync.Mutex
	token  string
	expiry time.Time
}

type tokenResponse struct {
	AccessToken string `json:"access_token"`
	ExpiresIn   int    `json:"expires_in"`
	TokenType   string `json:"token_type"`
}

// ResolveEndpoints derives missing C1 URLs from the client id hostname.
// Explicit overrides win. Parse errors happen only when a URL still needs deriving.
func ResolveEndpoints(clientID, baseURL, tokenURL string) (string, string, error) {
	baseURL = strings.TrimSpace(baseURL)
	tokenURL = strings.TrimSpace(tokenURL)
	if baseURL == "" || tokenURL == "" {
		host, err := hostFromClientID(clientID)
		if err != nil {
			return "", "", err
		}
		if baseURL == "" {
			baseURL = "https://" + host + "/api/v1"
		}
		if tokenURL == "" {
			tokenURL = "https://" + host + "/auth/v1/token"
		}
	}
	if err := idmcp.RequireHTTPS("C1_BASE_URL", baseURL); err != nil {
		return "", "", err
	}
	if err := idmcp.RequireHTTPS("C1_TOKEN_URL", tokenURL); err != nil {
		return "", "", err
	}
	return baseURL, tokenURL, nil
}

func hostFromClientID(id string) (string, error) {
	const bad = "C1_CLIENT_ID must be <random>@<hostname>/<use>"
	at := strings.Index(id, "@")
	if at <= 0 || at == len(id)-1 {
		return "", fmt.Errorf("%s", bad)
	}
	rest := id[at+1:]
	slash := strings.Index(rest, "/")
	if slash <= 0 || slash == len(rest)-1 {
		return "", fmt.Errorf("%s", bad)
	}
	host := rest[:slash]
	use := rest[slash+1:]
	if strings.TrimSpace(use) == "" || strings.ContainsAny(host, " /?#@%\\") {
		return "", fmt.Errorf("%s", bad)
	}
	// Reject encodings url.Parse would treat as userinfo or a different host.
	u, err := url.Parse("https://" + host + "/")
	if err != nil || u.User != nil || u.Hostname() != host {
		return "", fmt.Errorf("%s", bad)
	}
	return host, nil
}

// apiBase strips a trailing /api/v1 so request paths can stay /api/v1/... without doubling.
func apiBase(raw string) string {
	base := strings.TrimRight(strings.TrimSpace(raw), "/")
	base = strings.TrimSuffix(base, "/api/v1")
	return base
}

func NewClient(cfg Config) *Client {
	api := idmcp.NewClient(apiBase(cfg.BaseURL), nil)
	tokenHTTP := idmcp.NewClient("", nil)
	if cfg.HTTP != nil {
		api.HTTP = cfg.HTTP
		tokenHTTP.HTTP = cfg.HTTP
	}
	c := &Client{
		api:          api,
		tokenHTTP:    tokenHTTP,
		tokenURL:     cfg.TokenURL,
		clientID:     cfg.ClientID,
		clientSecret: cfg.ClientSecret,
	}
	c.api.Auth = c.bearer
	return c
}

func (c *Client) ensureToken(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.token != "" && time.Now().Before(c.expiry) {
		return nil
	}

	form := url.Values{}
	form.Set("client_id", c.clientID)
	form.Set("client_secret", c.clientSecret)
	form.Set("grant_type", "client_credentials")

	body, err := c.tokenHTTP.PostForm(ctx, c.tokenURL, form)
	if err != nil {
		return fmt.Errorf("c1 token: %w", err)
	}
	var tr tokenResponse
	if err := json.Unmarshal(body, &tr); err != nil {
		return fmt.Errorf("c1 token: decode: %w", err)
	}
	if tr.AccessToken == "" {
		return fmt.Errorf("c1 token: empty access_token")
	}
	ttl := time.Duration(tr.ExpiresIn)*time.Second - tokenSkew
	if ttl < 5*time.Second {
		ttl = 5 * time.Second
	}
	c.token = tr.AccessToken
	c.expiry = time.Now().Add(ttl)
	return nil
}

func (c *Client) bearer() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.token == "" {
		return ""
	}
	return "Bearer " + c.token
}

func (c *Client) scrub(err error) error {
	if err == nil {
		return nil
	}
	c.mu.Lock()
	secret := c.clientSecret
	token := c.token
	c.mu.Unlock()
	msg := redact(err.Error(), secret, token)
	if secret != "" {
		if enc := url.QueryEscape(secret); enc != secret {
			msg = strings.ReplaceAll(msg, enc, "[redacted]")
		}
	}
	if msg == err.Error() {
		return err
	}
	return fmt.Errorf("%s", msg)
}

func redact(msg, secret, token string) string {
	// Longer value first so a token that contains the secret still disappears.
	first, second := secret, token
	if len(second) > len(first) {
		first, second = second, first
	}
	if first != "" {
		msg = strings.ReplaceAll(msg, first, "[redacted]")
	}
	if second != "" {
		msg = strings.ReplaceAll(msg, second, "[redacted]")
	}
	return msg
}

func (c *Client) getRaw(ctx context.Context, path string, query url.Values) ([]byte, error) {
	if err := c.ensureToken(ctx); err != nil {
		return nil, c.scrub(err)
	}
	body, _, err := c.api.Get(ctx, path, query)
	if err != nil {
		return nil, c.scrub(err)
	}
	return body, nil
}

func (c *Client) postRaw(ctx context.Context, path string, body any) (json.RawMessage, error) {
	if err := c.ensureToken(ctx); err != nil {
		return nil, c.scrub(err)
	}
	var raw json.RawMessage
	if _, err := c.api.PostJSON(ctx, path, body, &raw); err != nil {
		return nil, c.scrub(err)
	}
	return raw, nil
}

func (c *Client) postList(ctx context.Context, path string, body any) ([]map[string]any, string, []any, error) {
	raw, err := c.postRaw(ctx, path, body)
	if err != nil {
		return nil, "", nil, err
	}
	list, next, expanded, err := decodeList(raw)
	if err != nil {
		return nil, "", nil, c.scrub(err)
	}
	return list, next, expanded, nil
}

func clampPageSize(limit int) int {
	if limit <= 0 {
		return defaultPageSize
	}
	if limit < minPageSize {
		return minPageSize
	}
	if limit > maxPageSize {
		return maxPageSize
	}
	return limit
}

func taskPageSize(limit int) int {
	n := clampPageSize(limit)
	if n > taskMaxPageSize {
		return taskMaxPageSize
	}
	return n
}

func cursor(raw string) (string, error) {
	return idmcp.OpaqueCursor(raw, "page_token")
}

func pageOf[T any](items []T, next string) idmcp.Page[T] {
	if items == nil {
		items = []T{}
	}
	return idmcp.Page[T]{Items: items, Next: next, Truncated: next != ""}
}

func searchBody(size int, token string) map[string]any {
	m := map[string]any{"pageSize": size}
	if token != "" {
		m["pageToken"] = token
	}
	return m
}

func setBody(m map[string]any, k, v string) {
	if v != "" {
		m[k] = v
	}
}

func oneOf(name, value string, allowed ...string) error {
	if value == "" {
		return nil
	}
	for _, a := range allowed {
		if value == a {
			return nil
		}
	}
	return fmt.Errorf("%s must be one of %s", name, strings.Join(allowed, ", "))
}
