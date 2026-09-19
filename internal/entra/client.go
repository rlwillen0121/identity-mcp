package entra

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
)

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

	mu     sync.Mutex
	token  string
	expiry time.Time
}

func NewClient(cfg Config) *Client {
	graphBase := cfg.GraphBaseURL
	if graphBase == "" {
		graphBase = defaultGraphBase
	}
	tokenURL := cfg.TokenURL
	if tokenURL == "" && cfg.TenantID != "" {
		tokenURL = fmt.Sprintf("https://login.microsoftonline.com/%s/oauth2/v2.0/token", cfg.TenantID)
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
	defer c.mu.Unlock()
	if c.token != "" && time.Now().Before(c.expiry) {
		return nil
	}

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

func (c *Client) getJSON(ctx context.Context, path string, query url.Values, dest any) error {
	if err := c.ensureToken(ctx); err != nil {
		return err
	}
	_, err := c.graph.GetJSON(ctx, path, query, dest)
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
		if !isRetryableSelect(last) {
			return i, last
		}
	}
	return -1, last
}

func isRetryableSelect(err error) bool {
	sc := idmcp.StatusOf(err)
	return sc == 400 || sc == 403
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
			q2.Set("$filter", filter)
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
