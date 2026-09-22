package entra

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/rlwillen0121/identity-mcp/internal/idmcp"
)

const (
	defaultGraphBase  = "https://graph.microsoft.com/v1.0"
	defaultGraphScope = "https://graph.microsoft.com/.default"
	tokenSkew         = 60 * time.Second

	userSelect         = "id,displayName,userPrincipalName,mail,accountEnabled,createdDateTime,userType,jobTitle,department,signInActivity"
	userSelectNoSignIn = "id,displayName,userPrincipalName,mail,accountEnabled,createdDateTime,userType,jobTitle,department"
	groupSelect        = "id,displayName,mail,securityEnabled,groupTypes,membershipRule"
	spSelect           = "id,appId,displayName,accountEnabled,servicePrincipalType,appOwnerOrganizationId"
	memberOfSelect     = "id,displayName,groupTypes"
	roleSelect         = "id,displayName,description,roleTemplateId"
	maxInactiveDays    = int64(1<<63-1) / int64(24*time.Hour)
)

func inactiveCutoff(days int) (time.Time, int, error) {
	if days <= 0 {
		days = 90
	}
	if int64(days) > maxInactiveDays {
		return time.Time{}, 0, fmt.Errorf("inactive_days must be at most %d", maxInactiveDays)
	}
	return time.Now().UTC().Add(-time.Duration(days) * 24 * time.Hour), days, nil
}

// Config constructs a Graph client. TokenURL and GraphBaseURL are injectable for tests.
type Config struct {
	TenantID     string
	ClientID     string
	ClientSecret string
	GraphBaseURL string
	TokenURL     string
	HTTP         *http.Client
}

// Client is a thin Microsoft Graph REST client using client-credentials auth.
type Client struct {
	graph        *idmcp.Client
	tokenHTTP    *idmcp.Client
	tokenURL     string
	clientID     string
	clientSecret string

	mu        sync.Mutex
	refreshMu sync.Mutex
	token     string
	expiry    time.Time
}

func NewClient(cfg Config) *Client {
	graphBase := cfg.GraphBaseURL
	if graphBase == "" {
		graphBase = defaultGraphBase
	}
	tokenURL := cfg.TokenURL
	if tokenURL == "" && cfg.TenantID != "" {
		tokenURL = fmt.Sprintf("https://login.microsoftonline.com/%s/oauth2/v2.0/token", url.PathEscape(cfg.TenantID))
	}

	hdr := make(http.Header)
	hdr.Set("ConsistencyLevel", "eventual")
	graph := idmcp.NewClient(graphBase, hdr)
	tokenHTTP := idmcp.NewClient("", nil)
	if cfg.HTTP != nil {
		graph.HTTP = cfg.HTTP
		tokenHTTP.HTTP = cfg.HTTP
	}

	c := &Client{
		graph:        graph,
		tokenHTTP:    tokenHTTP,
		tokenURL:     tokenURL,
		clientID:     cfg.ClientID,
		clientSecret: cfg.ClientSecret,
	}
	c.graph.Auth = c.bearer
	return c
}

func (c *Client) ensureToken(ctx context.Context) error {
	c.mu.Lock()
	if c.token != "" && time.Now().Before(c.expiry) {
		c.mu.Unlock()
		return nil
	}
	c.mu.Unlock()

	c.refreshMu.Lock()
	defer c.refreshMu.Unlock()
	c.mu.Lock()
	if c.token != "" && time.Now().Before(c.expiry) {
		c.mu.Unlock()
		return nil
	}
	c.mu.Unlock()

	form := url.Values{}
	form.Set("client_id", c.clientID)
	form.Set("client_secret", c.clientSecret)
	form.Set("grant_type", "client_credentials")
	form.Set("scope", defaultGraphScope)

	body, err := c.tokenHTTP.PostForm(ctx, c.tokenURL, form)
	if err != nil {
		return fmt.Errorf("entra token: %w", err)
	}

	var tr tokenResponse
	if err := json.Unmarshal(body, &tr); err != nil {
		return fmt.Errorf("entra token: decode: %w", err)
	}
	if tr.AccessToken == "" {
		return fmt.Errorf("entra token: empty access_token")
	}

	ttl := time.Duration(tr.ExpiresIn)*time.Second - tokenSkew
	if ttl < 5*time.Second {
		ttl = 5 * time.Second
	}
	c.mu.Lock()
	defer c.mu.Unlock()
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

func (c *Client) tokenForRequest(ctx context.Context) (string, error) {
	if err := c.ensureToken(ctx); err != nil {
		return "", err
	}
	c.mu.Lock()
	token := c.token
	c.mu.Unlock()
	if token == "" {
		return "", fmt.Errorf("entra token: unavailable after refresh")
	}
	return token, nil
}

func (c *Client) invalidateToken(expected string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if expected == "" || c.token != expected {
		return false
	}
	c.token = ""
	c.expiry = time.Time{}
	return true
}

func (c *Client) getJSON(ctx context.Context, path string, query url.Values, dest any) error {
	usedToken, err := c.tokenForRequest(ctx)
	if err != nil {
		return err
	}
	err = c.getJSONWithToken(ctx, path, query, usedToken, dest)
	if idmcp.StatusOf(err) != http.StatusUnauthorized {
		return err
	}
	// A request gets one and only one retry. Only invalidate the token that was
	// actually selected for this request; another goroutine may have refreshed
	// it while this request was in flight.
	c.invalidateToken(usedToken)
	retryToken, err := c.tokenForRequest(ctx)
	if err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	err = c.getJSONWithToken(ctx, path, query, retryToken, dest)
	return err
}

func (c *Client) getJSONWithToken(ctx context.Context, path string, query url.Values, token string, dest any) error {
	graph := *c.graph
	graph.Header = c.graph.Header.Clone()
	graph.Auth = nil
	if token != "" {
		graph.Header.Set("Authorization", "Bearer "+token)
	}
	_, err := graph.GetJSON(ctx, path, query, dest)
	return err
}

// getJSON400 retries successive query variants while Graph returns 400.
func (c *Client) getJSON400(ctx context.Context, path string, dest any, queries ...url.Values) (int, error) {
	var last error
	for i, q := range queries {
		last = c.getJSON(ctx, path, q, dest)
		if last == nil {
			return i, nil
		}
		if !isRetryableSelectQuery(last, q) {
			return i, last
		}
	}
	return -1, last
}

func isRetryableSelect(err error) bool {
	if idmcp.StatusOf(err) != http.StatusBadRequest {
		return false
	}
	var he *idmcp.HTTPError
	if !errors.As(err, &he) {
		return false
	}
	body := strings.ToLower(he.Body)
	return strings.Contains(body, "signinactivity") &&
		(strings.Contains(body, "request_unsupportedquery") ||
			strings.Contains(body, "unsupported property") ||
			strings.Contains(body, "unknown property") ||
			strings.Contains(body, "could not find a property"))
}

func isRetryableSelectQuery(err error, q url.Values) bool {
	if strings.TrimSpace(q.Get("$select")) == "" {
		return false
	}
	if idmcp.StatusOf(err) != http.StatusBadRequest {
		return false
	}
	var he *idmcp.HTTPError
	if !errors.As(err, &he) {
		return false
	}
	body := strings.ToLower(he.Body)
	return strings.Contains(body, "request_unsupportedquery") ||
		strings.Contains(body, "unsupported property") ||
		strings.Contains(body, "unknown property") ||
		strings.Contains(body, "could not find a property")
}

func cloneValues(q url.Values) url.Values {
	if q == nil {
		return url.Values{}
	}
	out := make(url.Values, len(q))
	for k, v := range q {
		out[k] = append([]string(nil), v...)
	}
	return out
}

func withSelect(q url.Values, sel string) url.Values {
	out := cloneValues(q)
	if sel != "" {
		out.Set("$select", sel)
	}
	return out
}

func withoutSelect(q url.Values) url.Values {
	out := cloneValues(q)
	out.Del("$select")
	return out
}

func collectionQuery(limit int, skipToken string) (url.Values, error) {
	if strings.Contains(skipToken, "://") {
		u, err := url.Parse(skipToken)
		if err != nil || u.User != nil || u.RawQuery == "" {
			return nil, fmt.Errorf("invalid Graph pagination cursor")
		}
		q := u.Query()
		if len(q) == 0 {
			return nil, fmt.Errorf("invalid Graph pagination cursor")
		}
		return q, nil
	}
	cur, err := idmcp.OpaqueCursor(skipToken, "$skiptoken")
	if err != nil {
		return nil, err
	}
	q := url.Values{}
	q.Set("$top", fmt.Sprintf("%d", idmcp.ClampLimit(limit)))
	if cur != "" {
		q.Set("$skiptoken", cur)
	}
	return q, nil
}

func (c *Client) graphCollectionQuery(endpoint string, limit int, cursor string) (url.Values, error) {
	if cursor == "" {
		return collectionQuery(limit, "")
	}
	if strings.Contains(cursor, "://") || strings.HasPrefix(cursor, "/") {
		u, err := url.Parse(cursor)
		if err != nil || u.User != nil || u.Fragment != "" || u.RawQuery == "" {
			return nil, fmt.Errorf("invalid Graph pagination cursor")
		}
		base, err := url.Parse(c.graph.BaseURL)
		if err != nil {
			return nil, fmt.Errorf("Graph pagination cursor authority does not match configured Graph endpoint")
		}
		if u.IsAbs() && (u.Scheme != base.Scheme || !strings.EqualFold(u.Host, base.Host)) {
			return nil, fmt.Errorf("Graph pagination cursor authority does not match configured Graph endpoint")
		}
		basePath := strings.TrimRight(base.Path, "/")
		if endpoint != "" {
			expectedPath := basePath + "/" + strings.TrimLeft(endpoint, "/")
			if u.Path != expectedPath {
				return nil, fmt.Errorf("Graph pagination cursor path does not match %s", endpoint)
			}
		} else if !strings.HasPrefix(u.Path, basePath+"/") {
			return nil, fmt.Errorf("Graph pagination cursor path is outside the configured Graph API")
		}
		q := u.Query()
		if len(q) == 0 {
			return nil, fmt.Errorf("invalid Graph pagination cursor")
		}
		return q, nil
	}
	return collectionQuery(limit, cursor)
}

func extractSkipToken(nextLink string) string {
	if nextLink == "" {
		return ""
	}
	u, err := url.Parse(nextLink)
	if err != nil {
		return nextLink
	}
	q := u.Query()
	if t := q.Get("$skiptoken"); t != "" {
		return t
	}
	if t := q.Get("$skipToken"); t != "" {
		return t
	}
	return nextLink
}

func pageOf[T any](items []T, nextLink string) idmcp.Page[T] {
	if items == nil {
		items = []T{}
	}
	next := extractSkipToken(nextLink)
	return idmcp.Page[T]{Items: items, Next: next, Truncated: next != ""}
}

func odataStr(s string) string {
	return strings.ReplaceAll(s, `'`, `''`)
}

func sanitizeSearch(s string) string {
	s = strings.ReplaceAll(s, `"`, "")
	s = strings.ReplaceAll(s, "\n", " ")
	return strings.TrimSpace(s)
}

func applySearch(q url.Values, search, filter string) {
	if q == nil {
		return
	}
	if filter != "" {
		q.Set("$filter", filter)
	}
	if search != "" {
		q.Set("$search", fmt.Sprintf(`"displayName:%s"`, sanitizeSearch(search)))
		q.Set("$count", "true")
	}
}

func userStartswith(search string) string {
	s := odataStr(sanitizeSearch(search))
	return fmt.Sprintf("startswith(displayName,'%s') or startswith(userPrincipalName,'%s') or startswith(mail,'%s')", s, s, s)
}

func displayNameStartswith(search string) string {
	return fmt.Sprintf("startswith(displayName,'%s')", odataStr(sanitizeSearch(search)))
}

func queryVariants(base url.Values, search, filter, startswith, sel, selFallback string) []url.Values {
	var out []url.Values
	q := cloneValues(base)
	applySearch(q, search, filter)
	out = append(out, withSelect(q, sel))
	if selFallback != "" && selFallback != sel {
		out = append(out, withSelect(q, selFallback))
	}
	if search != "" {
		q2 := cloneValues(base)
		if filter != "" {
			// Graph may reject combining $search and $filter. The fallback
			// must retain both predicates; dropping search would broaden the
			// result set and silently change the caller's query.
			q2.Set("$filter", "("+filter+") and ("+startswith+")")
		} else if startswith != "" {
			q2.Set("$filter", startswith)
		}
		out = append(out, withSelect(q2, sel))
		if selFallback != "" && selFallback != sel {
			out = append(out, withSelect(q2, selFallback))
		}
	}
	return out
}

func objectType(odataType string) string {
	t := strings.TrimPrefix(odataType, "#")
	t = strings.TrimPrefix(t, "microsoft.graph.")
	if t == "" {
		return "unknown"
	}
	return t
}

func isGroupType(odataType string, groupTypes []string) bool {
	if objectType(odataType) == "group" {
		return true
	}
	return odataType == "" && groupTypes != nil
}

func enabledPtr(p *bool) bool {
	if p == nil {
		return false
	}
	return *p
}

func lastSignIn(a *graphSignInActivity) string {
	if a == nil {
		return ""
	}
	if a.LastSuccessfulSignInDateTime != "" {
		return a.LastSuccessfulSignInDateTime
	}
	if a.LastSignInDateTime != "" {
		return a.LastSignInDateTime
	}
	return a.LastNonInteractiveSignInDateTime
}

func clampSignIns(n int) int {
	n = idmcp.ClampLimit(n)
	if n > 50 {
		return 50
	}
	return n
}

func parseGraphTime(s string) (time.Time, bool) {
	if s == "" {
		return time.Time{}, false
	}
	if ts, err := time.Parse(time.RFC3339Nano, s); err == nil {
		return ts, true
	}
	if ts, err := time.Parse(time.RFC3339, s); err == nil {
		return ts, true
	}
	return time.Time{}, false
}
