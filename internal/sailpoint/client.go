package sailpoint

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/rlwillen0121/identity-mcp/internal/idmcp"
)

const tokenSkew = 60 * time.Second

// tenantLabel is one DNS label. Dots, slashes, and other host punctuation are rejected
// so a tenant cannot retarget the derived identitynow host.
var tenantLabel = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$`)

// Endpoints returns the SailPoint API base and token URL.
// When either URL is empty, tenant must be a single DNS label and the missing URL is derived.
// Explicit URLs are not forced onto identitynow.com; they only have to be https without userinfo.
func Endpoints(tenant, baseURL, tokenURL string) (string, string, error) {
	tenant = strings.TrimSpace(tenant)
	baseURL = strings.TrimSpace(baseURL)
	tokenURL = strings.TrimSpace(tokenURL)
	if baseURL == "" || tokenURL == "" {
		if !tenantLabel.MatchString(tenant) {
			return "", "", fmt.Errorf("SAILPOINT_TENANT must be a single DNS label when SAILPOINT_BASE_URL or SAILPOINT_TOKEN_URL is empty")
		}
		if baseURL == "" {
			baseURL = "https://" + tenant + ".api.identitynow.com/v2026"
		}
		if tokenURL == "" {
			tokenURL = "https://" + tenant + ".api.identitynow.com/oauth/token"
		}
	}
	if err := idmcp.RequireHTTPS("SAILPOINT_BASE_URL", baseURL); err != nil {
		return "", "", err
	}
	if err := idmcp.RequireHTTPS("SAILPOINT_TOKEN_URL", tokenURL); err != nil {
		return "", "", err
	}
	return baseURL, tokenURL, nil
}

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

func NewClient(cfg Config) *Client {
	api := idmcp.NewClient(cfg.BaseURL, nil)
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
		return c.scrubLocked(fmt.Errorf("sailpoint token: %w", err))
	}

	var tr tokenResponse
	if err := json.Unmarshal(body, &tr); err != nil {
		return c.scrubLocked(fmt.Errorf("sailpoint token: decode: %w", err))
	}
	if tr.AccessToken == "" {
		return c.scrubLocked(fmt.Errorf("sailpoint token: empty access_token"))
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
	defer c.mu.Unlock()
	return c.scrubLocked(err)
}

// scrubLocked assumes c.mu is held.
func (c *Client) scrubLocked(err error) error {
	if err == nil {
		return nil
	}
	msg := redact(err.Error(), c.clientSecret, c.token)
	if c.clientSecret != "" {
		if enc := url.QueryEscape(c.clientSecret); enc != c.clientSecret {
			msg = strings.ReplaceAll(msg, enc, "[redacted]")
		}
	}
	if msg == err.Error() {
		return err
	}
	return fmt.Errorf("%s", msg)
}

func redact(msg, secret, token string) string {
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

func (c *Client) getJSON(ctx context.Context, path string, query url.Values, dest any) error {
	if err := c.ensureToken(ctx); err != nil {
		return c.scrub(err)
	}
	_, err := c.api.GetJSON(ctx, path, query, dest)
	return c.scrub(err)
}

func (c *Client) postJSON(ctx context.Context, path string, body, dest any) error {
	if err := c.ensureToken(ctx); err != nil {
		return c.scrub(err)
	}
	_, err := c.api.PostJSON(ctx, path, body, dest)
	return c.scrub(err)
}

func collectionQuery(limit int, offsetCursor string) (url.Values, int, int, error) {
	offset, err := idmcp.ParseIntCursor(offsetCursor)
	if err != nil {
		return nil, 0, 0, err
	}
	n := idmcp.ClampLimit(limit)
	q := url.Values{}
	q.Set("limit", strconv.Itoa(n))
	q.Set("offset", strconv.Itoa(offset))
	return q, offset, n, nil
}

func pageOf[T any](items []T, offset, limit int) idmcp.Page[T] {
	if items == nil {
		items = []T{}
	}
	next := idmcp.NextOffset(offset, len(items), limit)
	return idmcp.Page[T]{Items: items, Next: next, Truncated: next != ""}
}

func setQuery(q url.Values, k, v string) {
	if v != "" {
		q.Set(k, v)
	}
}

func asString(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case json.Number:
		return t.String()
	default:
		return ""
	}
}

func firstString(m map[string]any, keys ...string) string {
	for _, k := range keys {
		if s := asString(m[k]); s != "" {
			return s
		}
	}
	return ""
}

func asMap(v any) map[string]any {
	m, _ := v.(map[string]any)
	return m
}

func withUncorrelated(filters string) string {
	f := strings.TrimSpace(filters)
	if f == "" {
		return "uncorrelated eq true"
	}
	if strings.Contains(strings.ToLower(f), "uncorrelated") {
		return f
	}
	return f + " and uncorrelated eq true"
}

func identityIDFilter(id string) (string, error) {
	if strings.Contains(id, `"`) {
		return "", fmt.Errorf("invalid identity id")
	}
	return `identityId eq "` + id + `"`, nil
}

func namedRef(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return s
	}
	var m map[string]any
	if json.Unmarshal(raw, &m) != nil {
		return ""
	}
	if n := firstString(m, "name", "displayName"); n != "" {
		return n
	}
	return firstString(m, "id")
}
