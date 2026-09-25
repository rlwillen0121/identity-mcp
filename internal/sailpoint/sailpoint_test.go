package sailpoint

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/rlwillen0121/identity-mcp/internal/idmcp"
)

func TestNewServerTools(t *testing.T) {
	c := NewClient(Config{ClientID: "c", ClientSecret: "s", BaseURL: "https://example.invalid", TokenURL: "https://example.invalid/oauth/token"})
	session := connect(t, NewServer(c))
	res, err := session.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"list_identities", "get_identity", "get_identity_access", "list_accounts",
		"list_uncorrelated_accounts", "list_sources", "search", "find_stale_identities",
		"list_account_activities", "list_entitlements",
	}
	got := map[string]bool{}
	for _, tool := range res.Tools {
		got[tool.Name] = true
		if tool.Annotations == nil || !tool.Annotations.ReadOnlyHint {
			t.Errorf("%s missing read-only annotation", tool.Name)
		}
	}
	for _, name := range want {
		if !got[name] {
			t.Errorf("missing tool %s", name)
		}
	}
	if len(res.Tools) != len(want) {
		t.Fatalf("tool count %d want %d", len(res.Tools), len(want))
	}
}

func TestListIdentitiesFetchesToken(t *testing.T) {
	var tokenCalls, idCalls atomic.Int32
	c := startFake(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/oauth/token" {
			tokenCalls.Add(1)
			writeToken(t, w, r)
			return
		}
		if r.Header.Get("Authorization") != "Bearer tok" {
			t.Errorf("auth = %q", r.Header.Get("Authorization"))
		}
		if r.URL.Path != "/identities" {
			t.Errorf("path = %s", r.URL.Path)
		}
		if r.URL.Query().Get("defaultFilter") != "CORRELATED_ONLY" {
			t.Errorf("defaultFilter = %q", r.URL.Query().Get("defaultFilter"))
		}
		idCalls.Add(1)
		writeJSON(w, 200, `[{
			"id":"i1",
			"name":"Ada",
			"alias":"ada",
			"email":"ada@x",
			"identityState":"ACTIVE",
			"attributes":{"cloudLifecycleState":"active"}
		}]`)
	})

	out := callTool[idmcp.Page[IdentityItem]](t, c, "list_identities", ListIdentitiesInput{Limit: 10})
	if tokenCalls.Load() != 1 || idCalls.Load() != 1 {
		t.Fatalf("token=%d identities=%d", tokenCalls.Load(), idCalls.Load())
	}
	if len(out.Items) != 1 || out.Items[0].Email != "ada@x" || out.Items[0].CloudLifecycle != "active" {
		t.Fatalf("items = %#v", out.Items)
	}
	_ = callTool[idmcp.Page[IdentityItem]](t, c, "list_identities", ListIdentitiesInput{Limit: 10})
	if tokenCalls.Load() != 1 {
		t.Fatalf("token not cached: %d", tokenCalls.Load())
	}
}

func TestExpiredTokenRefreshes(t *testing.T) {
	var tokenCalls atomic.Int32
	c := startFake(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/oauth/token" {
			tokenCalls.Add(1)
			writeToken(t, w, r)
			return
		}
		writeJSON(w, 200, `[]`)
	})
	_ = callTool[idmcp.Page[IdentityItem]](t, c, "list_identities", ListIdentitiesInput{})
	c.expiry = time.Now().Add(-time.Minute)
	_ = callTool[idmcp.Page[IdentityItem]](t, c, "list_identities", ListIdentitiesInput{})
	if tokenCalls.Load() != 2 {
		t.Fatalf("token calls = %d", tokenCalls.Load())
	}
}

func TestGetIdentityAccessHitsFourPaths(t *testing.T) {
	var paths []string
	c := startFake(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/oauth/token" {
			writeToken(t, w, r)
			return
		}
		if r.Header.Get("Authorization") != "Bearer tok" {
			t.Errorf("auth = %q", r.Header.Get("Authorization"))
		}
		paths = append(paths, r.URL.Path)
		switch r.URL.Path {
		case "/identities/i1":
			writeJSON(w, 200, `{"id":"i1","name":"Ada","alias":"ada","email":"ada@x","identityState":"ACTIVE","attributes":{"cloudLifecycleState":"active"}}`)
		case "/accounts":
			if !strings.Contains(r.URL.Query().Get("filters"), `identityId eq "i1"`) {
				t.Errorf("filters = %q", r.URL.Query().Get("filters"))
			}
			if r.URL.Query().Get("detailLevel") != "SLIM" {
				t.Errorf("detailLevel = %q", r.URL.Query().Get("detailLevel"))
			}
			writeJSON(w, 200, `[{"id":"a1","name":"Ada AD","nativeIdentity":"ada","disabled":false,"uncorrelated":false,"sourceId":"s1","sourceName":"AD","identityId":"i1"}]`)
		case "/entitlements/identities/i1/entitlements":
			writeJSON(w, 200, `[{"id":"e1","name":"Domain Users","source":{"id":"s1","name":"AD"}}]`)
		case "/identities/i1/role-assignments":
			writeJSON(w, 200, `[{"id":"r1","role":{"id":"role1","name":"Admin"},"type":"ROLE"}]`)
		default:
			t.Errorf("unexpected path %s", r.URL.Path)
			writeJSON(w, 404, `{}`)
		}
	})
	out := callTool[IdentityAccess](t, c, "get_identity_access", GetIdentityAccessInput{IdentityID: "i1"})
	if out.ID != "i1" || out.Email != "ada@x" || out.CloudLifecycle != "active" {
		t.Fatalf("identity = %#v", out)
	}
	if len(out.Accounts) != 1 || out.Accounts[0].SourceName != "AD" || out.Accounts[0].NativeIdentity != "ada" {
		t.Fatalf("accounts = %#v", out.Accounts)
	}
	if len(out.Entitlements) != 1 || out.Entitlements[0].Name != "Domain Users" || out.Entitlements[0].Source != "AD" {
		t.Fatalf("entitlements = %#v", out.Entitlements)
	}
	if len(out.Roles) != 1 || out.Roles[0].Name != "Admin" || out.Roles[0].ID != "role1" {
		t.Fatalf("roles = %#v", out.Roles)
	}
	joined := strings.Join(paths, " ")
	for _, want := range []string{"/identities/i1", "/accounts", "/entitlements/identities/i1/entitlements", "/identities/i1/role-assignments"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("missing path %s in %v", want, paths)
		}
	}
}

func TestSearchPostJSONPath(t *testing.T) {
	var method, path, ctype string
	var body []byte
	c := startFake(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/oauth/token" {
			writeToken(t, w, r)
			return
		}
		method = r.Method
		path = r.URL.Path
		ctype = r.Header.Get("Content-Type")
		body, _ = io.ReadAll(r.Body)
		writeJSON(w, 200, `[{"id":"i1","name":"Ada","email":"ada@x","_type":"identity"}]`)
	})
	out := callTool[idmcp.Page[SearchHit]](t, c, "search", SearchInput{Query: "email:ada@x", Limit: 10})
	if method != http.MethodPost || path != "/search" {
		t.Fatalf("method=%s path=%s", method, path)
	}
	if ctype != "application/json" {
		t.Fatalf("content-type = %q", ctype)
	}
	if !strings.Contains(string(body), `"query"`) || !strings.Contains(string(body), "email:ada@x") {
		t.Fatalf("body = %s", body)
	}
	if !strings.Contains(string(body), `"sort":["id"]`) {
		t.Fatalf("body missing sort: %s", body)
	}
	if len(out.Items) != 1 || out.Items[0].Type != "identity" {
		t.Fatalf("items = %#v", out.Items)
	}
}

func TestPostJSONRefusesAbsolute(t *testing.T) {
	hit := false
	c := startFake(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/oauth/token" {
			writeToken(t, w, r)
			return
		}
		hit = true
	})
	if err := c.ensureToken(context.Background()); err != nil {
		t.Fatal(err)
	}
	_, err := c.api.PostJSON(context.Background(), "https://evil.example/steal", map[string]any{"q": "x"}, nil)
	if err == nil {
		t.Fatal("expected error")
	}
	if hit {
		t.Fatal("must not fetch attacker URL")
	}
}

func TestListUncorrelatedAccountsFilter(t *testing.T) {
	var filters string
	c := startFake(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/oauth/token" {
			writeToken(t, w, r)
			return
		}
		filters = r.URL.Query().Get("filters")
		writeJSON(w, 200, `[{"id":"a1","name":"orphan","nativeIdentity":"x","disabled":false,"uncorrelated":true,"sourceId":"s1","sourceName":"AD"}]`)
	})
	out := callTool[idmcp.Page[AccountItem]](t, c, "list_uncorrelated_accounts", ListAccountsInput{})
	if filters != "uncorrelated eq true" {
		t.Fatalf("filters = %q", filters)
	}
	if len(out.Items) != 1 || !out.Items[0].Uncorrelated {
		t.Fatalf("items = %#v", out.Items)
	}
}

func TestRetryAfterSurfaces(t *testing.T) {
	c := startFake(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/oauth/token" {
			writeToken(t, w, r)
			return
		}
		w.Header().Set("Retry-After", "2")
		writeJSON(w, 429, `{"message":"rate limited"}`)
	})
	res := callToolRaw(t, c, "list_identities", ListIdentitiesInput{})
	if !res.IsError {
		t.Fatal("expected error")
	}
	msg := ""
	for _, part := range res.Content {
		b, _ := json.Marshal(part)
		msg += string(b)
	}
	if !strings.Contains(msg, "retry after 2") {
		t.Fatalf("error content = %s", msg)
	}
}

func TestFindStaleIdentitiesUncorrelatedSample(t *testing.T) {
	var accountFilters string
	accountCalls := 0
	c := startFake(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/oauth/token" {
			writeToken(t, w, r)
			return
		}
		if r.Method == http.MethodPost && r.URL.Path == "/search" {
			writeJSON(w, 200, `[{"id":"i1","name":"Ada","email":"ada@x","identityState":"INACTIVE"}]`)
			return
		}
		if r.URL.Path == "/accounts" {
			accountCalls++
			accountFilters = r.URL.Query().Get("filters")
			writeJSON(w, 200, `[{"id":"a-orphan","name":"orphan","uncorrelated":true,"sourceId":"s1","sourceName":"AD"}]`)
			return
		}
		t.Errorf("unexpected path %s", r.URL.Path)
		writeJSON(w, 200, `[]`)
	})
	out := callTool[StalePage](t, c, "find_stale_identities", FindStaleIdentitiesInput{Limit: 50})
	if accountCalls != 1 {
		t.Fatalf("account calls = %d", accountCalls)
	}
	if accountFilters != "uncorrelated eq true" {
		t.Fatalf("filters = %q", accountFilters)
	}
	var gotUncorr bool
	for _, it := range out.Items {
		if it.ID == "a-orphan" && it.Uncorrelated && contains(it.Reasons, "uncorrelated") {
			gotUncorr = true
		}
	}
	if !gotUncorr {
		t.Fatalf("missing uncorrelated sample: %#v", out.Items)
	}
}

func contains(ss []string, want string) bool {
	for _, s := range ss {
		if s == want {
			return true
		}
	}
	return false
}

func TestFindStaleInspectCap(t *testing.T) {
	searchCalls := 0
	c := startFake(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/oauth/token" {
			writeToken(t, w, r)
			return
		}
		if r.URL.Path == "/search" {
			searchCalls++
			writeJSON(w, 200, `[{"id":"s0","name":"S0"},{"id":"s1","name":"S1"},{"id":"s2","name":"S2"}]`)
			return
		}
		t.Errorf("unexpected path %s", r.URL.Path)
		writeJSON(w, 200, `[]`)
	})
	out := callTool[StalePage](t, c, "find_stale_identities", FindStaleIdentitiesInput{Limit: 2})
	if searchCalls != 1 {
		t.Fatalf("search calls = %d", searchCalls)
	}
	if !out.Truncated || out.Next != "" || out.Scanned != 3 || len(out.Items) != 2 {
		t.Fatalf("page = %#v", out)
	}
}

func TestEndpoints(t *testing.T) {
	base, token, err := Endpoints("acme", "", "")
	if err != nil {
		t.Fatal(err)
	}
	if base != "https://acme.api.identitynow.com/v2026" || token != "https://acme.api.identitynow.com/oauth/token" {
		t.Fatalf("derived = %s %s", base, token)
	}
	for _, bad := range []string{"evil.example/", "evil.example#", "evil.example?", ""} {
		if _, _, err := Endpoints(bad, "", ""); err == nil {
			t.Fatalf("accepted tenant %q", bad)
		}
	}
	base, token, err = Endpoints("", "https://override.example/v2026", "https://override.example/oauth/token")
	if err != nil {
		t.Fatal(err)
	}
	if base != "https://override.example/v2026" || token != "https://override.example/oauth/token" {
		t.Fatalf("override = %s %s", base, token)
	}
}

func TestTokenErrorScrubsSecret(t *testing.T) {
	const secret = "super-sailpoint-secret/with+chars"
	const access = "super-sailpoint-access-token"
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/oauth/token" {
			http.NotFound(w, r)
			return
		}
		if calls.Add(1) == 1 {
			writeJSON(w, 200, `{"access_token":"`+access+`","expires_in":3600,"token_type":"Bearer"}`)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = io.WriteString(w, "echo "+secret+" "+url.QueryEscape(secret)+" "+access)
	}))
	t.Cleanup(srv.Close)
	c := NewClient(Config{
		ClientID:     "cid",
		ClientSecret: secret,
		BaseURL:      srv.URL,
		TokenURL:     srv.URL + "/oauth/token",
		HTTP:         srv.Client(),
	})
	if err := c.ensureToken(context.Background()); err != nil {
		t.Fatal(err)
	}
	c.expiry = time.Now().Add(-time.Minute)
	err := c.ensureToken(context.Background())
	if err == nil {
		t.Fatal("expected error")
	}
	msg := err.Error()
	for _, leak := range []string{secret, url.QueryEscape(secret), access} {
		if strings.Contains(msg, leak) {
			t.Fatalf("error contains %q: %s", leak, msg)
		}
	}
}

func TestGetIdentityAccessTruncatesOversizedAccounts(t *testing.T) {
	var accounts strings.Builder
	accounts.WriteByte('[')
	for i := 0; i < 51; i++ {
		if i > 0 {
			accounts.WriteByte(',')
		}
		fmt.Fprintf(&accounts, `{"id":"a%d","name":"n%d","nativeIdentity":"n%d","disabled":false,"uncorrelated":false,"sourceId":"s1","sourceName":"AD","identityId":"i1"}`, i, i, i)
	}
	accounts.WriteByte(']')
	c := startFake(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/oauth/token" {
			writeToken(t, w, r)
			return
		}
		switch r.URL.Path {
		case "/identities/i1":
			writeJSON(w, 200, `{"id":"i1","name":"Ada","alias":"ada","email":"ada@x","identityState":"ACTIVE","attributes":{"cloudLifecycleState":"active"}}`)
		case "/accounts":
			writeJSON(w, 200, accounts.String())
		case "/entitlements/identities/i1/entitlements", "/identities/i1/role-assignments":
			writeJSON(w, 200, `[]`)
		default:
			t.Errorf("unexpected path %s", r.URL.Path)
			writeJSON(w, 404, `{}`)
		}
	})
	out := callTool[IdentityAccess](t, c, "get_identity_access", GetIdentityAccessInput{IdentityID: "i1"})
	if len(out.Accounts) != 50 || !out.TruncatedAccounts {
		t.Fatalf("accounts=%d truncated=%v", len(out.Accounts), out.TruncatedAccounts)
	}
	if out.TruncatedEntitlements || out.TruncatedRoles {
		t.Fatalf("ent truncated=%v roles truncated=%v", out.TruncatedEntitlements, out.TruncatedRoles)
	}
}

func TestFindStaleOversizedPageStopsAtCap(t *testing.T) {
	const limit = 10
	const rows = 600
	var searchCalls atomic.Int32
	c := startFake(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/oauth/token" {
			writeToken(t, w, r)
			return
		}
		if r.URL.Path != "/search" {
			t.Errorf("unexpected path %s", r.URL.Path)
			writeJSON(w, 200, `[]`)
			return
		}
		searchCalls.Add(1)
		body, _ := io.ReadAll(r.Body)
		if !strings.Contains(string(body), `"sort":["id"]`) {
			t.Errorf("search body missing sort: %s", body)
		}
		var b strings.Builder
		b.WriteByte('[')
		for i := 0; i < rows; i++ {
			if i > 0 {
				b.WriteByte(',')
			}
			fmt.Fprintf(&b, `{"id":"i%d","name":"N%d","identityState":"INACTIVE"}`, i, i)
		}
		b.WriteByte(']')
		writeJSON(w, 200, b.String())
	})
	out := callTool[StalePage](t, c, "find_stale_identities", FindStaleIdentitiesInput{Limit: limit})
	if searchCalls.Load() != 1 {
		t.Fatalf("search calls = %d", searchCalls.Load())
	}
	if out.Scanned > 500 || !out.Truncated || len(out.Items) > limit {
		t.Fatalf("page = %#v", out)
	}
	if out.Scanned != 500 || len(out.Items) != limit || out.Next != "0" {
		t.Fatalf("scanned=%d items=%d next=%q truncated=%v", out.Scanned, len(out.Items), out.Next, out.Truncated)
	}
}

func startFake(t *testing.T, h http.HandlerFunc) *Client {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return NewClient(Config{
		ClientID:     "cid",
		ClientSecret: "sec",
		BaseURL:      srv.URL,
		TokenURL:     srv.URL + "/oauth/token",
		HTTP:         srv.Client(),
	})
}

func writeToken(t *testing.T, w http.ResponseWriter, r *http.Request) {
	t.Helper()
	if r.Method != http.MethodPost {
		t.Errorf("token method %s", r.Method)
	}
	body, _ := io.ReadAll(r.Body)
	form := string(body)
	for _, want := range []string{"grant_type=client_credentials", "client_id=cid", "client_secret=sec"} {
		if !strings.Contains(form, want) {
			t.Errorf("token body missing %q in %q", want, form)
		}
	}
	writeJSON(w, 200, `{"access_token":"tok","expires_in":3600,"token_type":"Bearer"}`)
}

func writeJSON(w http.ResponseWriter, status int, body string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = io.WriteString(w, body)
}

func connect(t *testing.T, server *mcp.Server) *mcp.ClientSession {
	t.Helper()
	ctx := context.Background()
	t1, t2 := mcp.NewInMemoryTransports()
	if _, err := server.Connect(ctx, t1, nil); err != nil {
		t.Fatal(err)
	}
	client := mcp.NewClient(&mcp.Implementation{Name: "test", Version: "0"}, nil)
	session, err := client.Connect(ctx, t2, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = session.Close() })
	return session
}

func callTool[Out any](t *testing.T, c *Client, name string, args any) Out {
	t.Helper()
	res := callToolRaw(t, c, name, args)
	if res.IsError {
		t.Fatalf("%s tool error: %v", name, res.Content)
	}
	b, err := json.Marshal(res.StructuredContent)
	if err != nil {
		t.Fatal(err)
	}
	var out Out
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatalf("decode %s: %v\n%s", name, err, b)
	}
	return out
}

func callToolRaw(t *testing.T, c *Client, name string, args any) *mcp.CallToolResult {
	t.Helper()
	session := connect(t, NewServer(c))
	res, err := session.CallTool(context.Background(), &mcp.CallToolParams{Name: name, Arguments: args})
	if err != nil {
		t.Fatal(err)
	}
	return res
}
