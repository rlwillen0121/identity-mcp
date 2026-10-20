package entra

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/rlwillen0121/identity-mcp/internal/authz"
	"github.com/rlwillen0121/identity-mcp/internal/idmcp"
)

func TestExtractSkipToken(t *testing.T) {
	got := extractSkipToken("https://graph.microsoft.com/v1.0/users?$top=1&$skiptoken=abc%3D")
	if got != "abc=" {
		t.Fatalf("skiptoken = %q", got)
	}
	full := "https://graph.microsoft.com/v1.0/users?$top=1"
	if extractSkipToken(full) != full {
		t.Fatalf("expected full nextLink, got %q", extractSkipToken(full))
	}
	if extractSkipToken("") != "" {
		t.Fatal("empty")
	}
}

func TestNewServerTools(t *testing.T) {
	c := NewClient(Config{TenantID: "t", ClientID: "c", ClientSecret: "s"})
	session := connect(t, NewServer(c))
	res, err := session.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"list_users", "get_user", "list_user_groups", "list_groups", "list_group_members",
		"list_directory_roles", "list_role_members", "list_service_principals",
		"find_stale_users", "list_sign_ins",
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

func TestListUsersFetchesToken(t *testing.T) {
	var tokenCalls, userCalls atomic.Int32
	c := startFake(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/oauth2/v2.0/token" {
			tokenCalls.Add(1)
			writeToken(t, w, r)
			return
		}
		if r.Header.Get("Authorization") != "Bearer tok" {
			t.Errorf("auth = %q", r.Header.Get("Authorization"))
		}
		if r.URL.Path != "/users" {
			t.Errorf("path = %s", r.URL.Path)
		}
		userCalls.Add(1)
		writeJSON(w, 200, `{
			"value":[{
				"id":"u1",
				"displayName":"Ada",
				"userPrincipalName":"ada@contoso.com",
				"mail":"ada@contoso.com",
				"accountEnabled":true,
				"createdDateTime":"2020-01-01T00:00:00Z",
				"userType":"Member",
				"jobTitle":"Engineer",
				"department":"IT",
				"signInActivity":{"lastSignInDateTime":"2024-06-01T00:00:00Z"}
			}]
		}`)
	})

	out := callTool[idmcp.Page[User]](t, c, "list_users", ListUsersInput{Limit: 10})
	if tokenCalls.Load() != 1 || userCalls.Load() != 1 {
		t.Fatalf("token=%d users=%d", tokenCalls.Load(), userCalls.Load())
	}
	if len(out.Items) != 1 || out.Items[0].UPN != "ada@contoso.com" {
		t.Fatalf("items = %#v", out.Items)
	}
	if out.Items[0].LastSignIn != "2024-06-01T00:00:00Z" || !out.Items[0].Enabled {
		t.Fatalf("user = %#v", out.Items[0])
	}

	// Cached token: second call should not hit the token endpoint again.
	_ = callTool[idmcp.Page[User]](t, c, "list_users", ListUsersInput{Limit: 10})
	if tokenCalls.Load() != 1 {
		t.Fatalf("token not cached: %d", tokenCalls.Load())
	}
	if userCalls.Load() != 2 {
		t.Fatalf("users=%d", userCalls.Load())
	}
}

func TestListUsersGraph401(t *testing.T) {
	c := startFake(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/oauth2/v2.0/token" {
			writeToken(t, w, r)
			return
		}
		writeJSON(w, 401, `{"error":{"code":"InvalidAuthenticationToken","message":"expired"}}`)
	})
	res := callToolRaw(t, c, "list_users", ListUsersInput{})
	if !res.IsError {
		t.Fatalf("expected tool error, got %#v", res)
	}
}

func TestListUsersNextLink(t *testing.T) {
	c := startFake(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/oauth2/v2.0/token" {
			writeToken(t, w, r)
			return
		}
		if r.URL.Query().Get("$skiptoken") == "page2" {
			writeJSON(w, 200, `{"value":[{"id":"u2","displayName":"Bob","userPrincipalName":"bob@contoso.com","accountEnabled":true}]}`)
			return
		}
		next := "https://graph.microsoft.com/v1.0/users?$top=1&$skiptoken=page2"
		writeJSON(w, 200, `{"value":[{"id":"u1","displayName":"Ada","userPrincipalName":"ada@contoso.com","accountEnabled":true}],"@odata.nextLink":"`+next+`"}`)
	})

	page1 := callTool[idmcp.Page[User]](t, c, "list_users", ListUsersInput{Limit: 1})
	if page1.Next != "page2" || !page1.Truncated || len(page1.Items) != 1 {
		t.Fatalf("page1 = %#v", page1)
	}
	page2 := callTool[idmcp.Page[User]](t, c, "list_users", ListUsersInput{SkipToken: page1.Next})
	if page2.Next != "" || len(page2.Items) != 1 || page2.Items[0].ID != "u2" {
		t.Fatalf("page2 = %#v", page2)
	}
}

func TestListUsersSignInActivityRetry(t *testing.T) {
	var with, without atomic.Int32
	c := startFake(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/oauth2/v2.0/token" {
			writeToken(t, w, r)
			return
		}
		sel := r.URL.Query().Get("$select")
		if strings.Contains(sel, "signInActivity") {
			with.Add(1)
			writeJSON(w, 400, `{"error":{"code":"Request_UnsupportedQuery","message":"Unsupported property signInActivity"}}`)
			return
		}
		without.Add(1)
		writeJSON(w, 200, `{"value":[{"id":"u1","displayName":"Ada","userPrincipalName":"ada@contoso.com","accountEnabled":true}]}`)
	})
	out := callTool[idmcp.Page[User]](t, c, "list_users", ListUsersInput{})
	if with.Load() < 1 || without.Load() < 1 {
		t.Fatalf("with=%d without=%d", with.Load(), without.Load())
	}
	if len(out.Items) != 1 || out.Items[0].ID != "u1" {
		t.Fatalf("items = %#v", out.Items)
	}
}

func TestFindStaleUsers(t *testing.T) {
	c := startFake(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/oauth2/v2.0/token" {
			writeToken(t, w, r)
			return
		}
		if !strings.Contains(r.URL.Query().Get("$select"), "signInActivity") {
			t.Errorf("expected signInActivity select, got %q", r.URL.RawQuery)
		}
		writeJSON(w, 200, `{
			"value":[
				{"id":"disabled","displayName":"Off","userPrincipalName":"off@contoso.com","accountEnabled":false,"signInActivity":{"lastSignInDateTime":"2024-06-01T00:00:00Z"}},
				{"id":"never","displayName":"Never","userPrincipalName":"never@contoso.com","accountEnabled":true},
				{"id":"old","displayName":"Old","userPrincipalName":"old@contoso.com","accountEnabled":true,"signInActivity":{"lastSignInDateTime":"2020-01-01T00:00:00Z"}},
				{"id":"active","displayName":"Active","userPrincipalName":"active@contoso.com","accountEnabled":true,"signInActivity":{"lastSuccessfulSignInDateTime":"2030-01-01T00:00:00Z"}}
			]
		}`)
	})
	out := callTool[FindStaleUsersOutput](t, c, "find_stale_users", FindStaleUsersInput{InactiveDays: 90, Limit: 50})
	byID := map[string]StaleUser{}
	for _, u := range out.Items {
		byID[u.ID] = u
	}
	if _, ok := byID["active"]; ok {
		t.Fatalf("active user should not be stale: %#v", out.Items)
	}
	if !contains(byID["disabled"].Reasons, "disabled") {
		t.Fatalf("disabled reasons = %v", byID["disabled"].Reasons)
	}
	if !contains(byID["never"].Reasons, "no_sign_in") {
		t.Fatalf("never reasons = %v", byID["never"].Reasons)
	}
	if !contains(byID["old"].Reasons, "sign_in_older_than_90_days") {
		t.Fatalf("old reasons = %v", byID["old"].Reasons)
	}
}

func TestFindStaleUsersSignInActivityUnavailable(t *testing.T) {
	c := startFake(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/oauth2/v2.0/token" {
			writeToken(t, w, r)
			return
		}
		if strings.Contains(r.URL.Query().Get("$select"), "signInActivity") {
			writeJSON(w, 400, `{"error":{"code":"Request_UnsupportedQuery"}}`)
			return
		}
		writeJSON(w, 200, `{
			"value":[
				{"id":"disabled","displayName":"Off","userPrincipalName":"off@contoso.com","accountEnabled":false},
				{"id":"enabled","displayName":"On","userPrincipalName":"on@contoso.com","accountEnabled":true}
			]
		}`)
	})
	out := callTool[FindStaleUsersOutput](t, c, "find_stale_users", FindStaleUsersInput{})
	if out.Note == "" || !strings.Contains(out.Note, "unknown") {
		t.Fatalf("note = %q", out.Note)
	}
	if len(out.Items) != 1 || out.Items[0].ID != "disabled" || out.Items[0].LastSignIn != "unknown" {
		t.Fatalf("items = %#v", out.Items)
	}
}

func TestListGroupMembersSendsCount(t *testing.T) {
	var gotCount, gotTop, gotSelect string
	c := startFake(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/oauth2/v2.0/token" {
			writeToken(t, w, r)
			return
		}
		if r.URL.Path != "/groups/g1/members" {
			t.Errorf("path = %s", r.URL.Path)
		}
		gotCount = r.URL.Query().Get("$count")
		gotTop = r.URL.Query().Get("$top")
		gotSelect = r.URL.Query().Get("$select")
		writeJSON(w, 200, `{"value":[{"id":"u1","displayName":"Ada","userPrincipalName":"ada@contoso.com","@odata.type":"#microsoft.graph.user"}]}`)
	})
	page := callTool[idmcp.Page[DirectoryMember]](t, c, "list_group_members", ListGroupMembersInput{GroupID: "g1", Limit: 10})
	if gotCount != "true" {
		t.Fatalf("$count = %q", gotCount)
	}
	if gotTop != "10" || !strings.Contains(gotSelect, "userPrincipalName") {
		t.Fatalf("top=%q select=%q", gotTop, gotSelect)
	}
	if len(page.Items) != 1 || page.Items[0].ID != "u1" {
		t.Fatalf("items = %#v", page.Items)
	}
}

func TestListRoleMembersOmitsTopAndSkipToken(t *testing.T) {
	var gotTop, gotSkip, gotCount string
	c := startFake(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/oauth2/v2.0/token" {
			writeToken(t, w, r)
			return
		}
		if r.URL.Path != "/directoryRoles/r1/members" {
			t.Errorf("path = %s", r.URL.Path)
		}
		gotTop = r.URL.Query().Get("$top")
		gotSkip = r.URL.Query().Get("$skiptoken")
		gotCount = r.URL.Query().Get("$count")
		writeJSON(w, 200, `{"value":[
			{"id":"u1","displayName":"Ada","userPrincipalName":"ada@contoso.com"},
			{"id":"u2","displayName":"Bob","userPrincipalName":"bob@contoso.com"}
		]}`)
	})
	page := callTool[idmcp.Page[DirectoryMember]](t, c, "list_role_members", ListRoleMembersInput{RoleID: "r1", Limit: 1})
	if gotTop != "" || gotSkip != "" || gotCount != "" {
		t.Fatalf("$top=%q $skiptoken=%q $count=%q", gotTop, gotSkip, gotCount)
	}
	if !page.Truncated || page.Next != "" || len(page.Items) != 1 || page.Items[0].ID != "u1" {
		t.Fatalf("page = %#v", page)
	}
}

func TestListRoleMembersRejectsSkipToken(t *testing.T) {
	c := startFake(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/oauth2/v2.0/token" {
			writeToken(t, w, r)
			return
		}
		t.Errorf("must not call Graph path %s", r.URL.Path)
	})
	res := callToolRaw(t, c, "list_role_members", ListRoleMembersInput{RoleID: "r1", SkipToken: "abc"})
	if !res.IsError {
		t.Fatal("expected error")
	}
}

func TestFindStaleUsersLeftoverDoesNotAdvanceCursor(t *testing.T) {
	calls := 0
	c := startFake(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/oauth2/v2.0/token" {
			writeToken(t, w, r)
			return
		}
		calls++
		writeJSON(w, 200, `{
			"value":[
				{"id":"s0","displayName":"S0","userPrincipalName":"s0@contoso.com","accountEnabled":true,"signInActivity":{"lastSignInDateTime":"2010-01-01T00:00:00Z"}},
				{"id":"s1","displayName":"S1","userPrincipalName":"s1@contoso.com","accountEnabled":true,"signInActivity":{"lastSignInDateTime":"2010-01-01T00:00:00Z"}},
				{"id":"s2","displayName":"S2","userPrincipalName":"s2@contoso.com","accountEnabled":true,"signInActivity":{"lastSignInDateTime":"2010-01-01T00:00:00Z"}}
			],
			"@odata.nextLink":"https://graph.microsoft.com/v1.0/users?$skiptoken=p2"
		}`)
	})
	page := callTool[FindStaleUsersOutput](t, c, "find_stale_users", FindStaleUsersInput{InactiveDays: 90, Limit: 2})
	if calls != 1 {
		t.Fatalf("calls = %d", calls)
	}
	if !page.Truncated || page.Next != "" || page.Scanned != 3 || len(page.Items) != 2 {
		t.Fatalf("page = %#v", page)
	}
}

func TestNextLinkWithoutSkipToken(t *testing.T) {
	next := "https://graph.microsoft.com/v1.0/users?$top=1"
	c := startFake(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/oauth2/v2.0/token" {
			writeToken(t, w, r)
			return
		}
		writeJSON(w, 200, `{"value":[{"id":"u1","displayName":"Ada","userPrincipalName":"ada@contoso.com","accountEnabled":true}],"@odata.nextLink":"`+next+`"}`)
	})
	page := callTool[idmcp.Page[User]](t, c, "list_users", ListUsersInput{})
	if page.Next != next {
		t.Fatalf("next = %q", page.Next)
	}
}

func startFake(t *testing.T, h http.HandlerFunc) *Client {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return NewClient(Config{
		TenantID:     "tid",
		ClientID:     "cid",
		ClientSecret: "sec",
		GraphBaseURL: srv.URL,
		TokenURL:     srv.URL + "/oauth2/v2.0/token",
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
	for _, want := range []string{"grant_type=client_credentials", "client_id=cid", "client_secret=sec", "graph.microsoft.com"} {
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

func contains(ss []string, want string) bool {
	for _, s := range ss {
		if s == want {
			return true
		}
	}
	return false
}

func TestValidateTenantIDAndSecretScrubbing(t *testing.T) {
	for _, valid := range []string{"00000000-0000-0000-0000-000000000000", "contoso.onmicrosoft.com", "tenant-123"} {
		if err := ValidateTenantID(valid); err != nil {
			t.Fatalf("ValidateTenantID(%q) unexpected error: %v", valid, err)
		}
	}
	for _, bad := range []string{"", ".", "..", "a..b", "@evil.example/x#", "../evil", "tenant/path", "tenant?x=1"} {
		if err := ValidateTenantID(bad); err == nil {
			t.Fatalf("ValidateTenantID(%q) expected error", bad)
		}
	}

	const secret = "entra-client-secret-xyz987"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "bad secret "+secret, http.StatusUnauthorized)
	}))
	t.Cleanup(srv.Close)

	c := NewClient(Config{
		TenantID:     "contoso.onmicrosoft.com",
		ClientID:     "cid",
		ClientSecret: secret,
		GraphBaseURL: srv.URL,
		TokenURL:     srv.URL + "/token",
		HTTP:         srv.Client(),
	})
	err := c.ensureToken(context.Background())
	if err == nil {
		t.Fatal("expected error")
	}
	if strings.Contains(err.Error(), secret) {
		t.Fatalf("ensureToken leaked client_secret: %v", err)
	}
}

func callWriteTool[Out any](t *testing.T, c *Client, name string, args any) Out {
	t.Helper()
	res := callWriteToolRaw(t, c, name, args)
	if res.IsError {
		t.Fatalf("%s write tool error: %v", name, res.Content)
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

func TestNewServerWithOptions(t *testing.T) {
	c := NewClient(Config{TenantID: "t", ClientID: "c", ClientSecret: "s"})

	// Default read-only server (enableWrites = false)
	sessDefault := connect(t, NewServer(c))
	resDefault, err := sessDefault.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(resDefault.Tools) != 10 {
		t.Fatalf("expected 10 read-only tools by default, got %d", len(resDefault.Tools))
	}
	for _, tool := range resDefault.Tools {
		if tool.Name == "add_group_member" || tool.Name == "revoke_sign_in_sessions" {
			t.Fatalf("unexpected write tool in default server: %s", tool.Name)
		}
	}

	// Explicit false
	sessFalse := connect(t, NewServerWithOptions(c, false))
	resFalse, err := sessFalse.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(resFalse.Tools) != 10 {
		t.Fatalf("expected 10 read-only tools with enableWrites=false, got %d", len(resFalse.Tools))
	}

	// Writes enabled (enableWrites = true)
	sessTrue := connect(t, NewServerWithOptions(c, true))
	resTrue, err := sessTrue.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(resTrue.Tools) != 12 {
		t.Fatalf("expected 12 tools with enableWrites=true, got %d", len(resTrue.Tools))
	}

	toolMap := make(map[string]*mcp.Tool)
	for _, tool := range resTrue.Tools {
		toolMap[tool.Name] = tool
	}

	agm, ok := toolMap["add_group_member"]
	if !ok {
		t.Fatal("missing add_group_member tool")
	}
	if agm.Annotations == nil || agm.Annotations.ReadOnlyHint || agm.Annotations.IdempotentHint || agm.Annotations.DestructiveHint == nil || *agm.Annotations.DestructiveHint {
		t.Fatalf("unexpected add_group_member annotations: %#v", agm.Annotations)
	}

	rev, ok := toolMap["revoke_sign_in_sessions"]
	if !ok {
		t.Fatal("missing revoke_sign_in_sessions tool")
	}
	if rev.Annotations == nil || rev.Annotations.ReadOnlyHint || !rev.Annotations.IdempotentHint || rev.Annotations.DestructiveHint == nil || *rev.Annotations.DestructiveHint {
		t.Fatalf("unexpected revoke_sign_in_sessions annotations: %#v", rev.Annotations)
	}
}

func TestAddGroupMember(t *testing.T) {
	var postedBody map[string]string
	var gotMethod, gotPath, gotAuth string

	c := startFake(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/oauth2/v2.0/token" {
			writeToken(t, w, r)
			return
		}
		if r.URL.Path == "/groups/grp-123/members/$ref" {
			gotMethod = r.Method
			gotPath = r.URL.Path
			gotAuth = r.Header.Get("Authorization")
			bodyBytes, _ := io.ReadAll(r.Body)
			_ = json.Unmarshal(bodyBytes, &postedBody)
			w.WriteHeader(http.StatusNoContent)
			return
		}
		http.Error(w, "not found", http.StatusNotFound)
	})

	out := callWriteTool[AddGroupMemberOutput](t, c, "add_group_member", AddGroupMemberInput{
		GroupID: "grp-123",
		UserID:  "usr-456",
	})

	if gotMethod != http.MethodPost {
		t.Fatalf("expected POST, got %s", gotMethod)
	}
	if gotPath != "/groups/grp-123/members/$ref" {
		t.Fatalf("expected path /groups/grp-123/members/$ref, got %s", gotPath)
	}
	if gotAuth != "Bearer tok" {
		t.Fatalf("expected Authorization 'Bearer tok', got %s", gotAuth)
	}
	expectedOdataID := c.graphBase + "/directoryObjects/usr-456"
	if postedBody["@odata.id"] != expectedOdataID {
		t.Fatalf("expected @odata.id %q, got %q", expectedOdataID, postedBody["@odata.id"])
	}
	if out.GroupID != "grp-123" || out.UserID != "usr-456" || out.Status != "added" {
		t.Fatalf("unexpected output: %#v", out)
	}

	// Validation errors
	resNoGroup := callWriteToolRaw(t, c, "add_group_member", AddGroupMemberInput{UserID: "usr-456"})
	if !resNoGroup.IsError {
		t.Fatal("expected error on missing group_id")
	}

	resNoUser := callWriteToolRaw(t, c, "add_group_member", AddGroupMemberInput{GroupID: "grp-123"})
	if !resNoUser.IsError {
		t.Fatal("expected error on missing user_id")
	}

	// HTTP error from upstream
	resNotFound := callWriteToolRaw(t, c, "add_group_member", AddGroupMemberInput{GroupID: "unknown-group", UserID: "usr-456"})
	if !resNotFound.IsError {
		t.Fatal("expected error on 404 from Graph")
	}
}

func TestRevokeSignInSessions(t *testing.T) {
	var gotMethod, gotPath, gotAuth string

	c := startFake(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/oauth2/v2.0/token" {
			writeToken(t, w, r)
			return
		}
		if r.URL.Path == "/users/usr-789/revokeSignInSessions" {
			gotMethod = r.Method
			gotPath = r.URL.Path
			gotAuth = r.Header.Get("Authorization")
			writeJSON(w, http.StatusOK, `{"@odata.context":"https://graph.microsoft.com/v1.0/$metadata#Edm.Boolean","value":true}`)
			return
		}
		http.Error(w, "not found", http.StatusNotFound)
	})

	out := callWriteTool[RevokeSignInSessionsOutput](t, c, "revoke_sign_in_sessions", RevokeSignInSessionsInput{
		UserID: "usr-789",
	})

	if gotMethod != http.MethodPost {
		t.Fatalf("expected POST, got %s", gotMethod)
	}
	if gotPath != "/users/usr-789/revokeSignInSessions" {
		t.Fatalf("expected path /users/usr-789/revokeSignInSessions, got %s", gotPath)
	}
	if gotAuth != "Bearer tok" {
		t.Fatalf("expected Authorization 'Bearer tok', got %s", gotAuth)
	}
	if out.UserID != "usr-789" || !out.Revoked {
		t.Fatalf("unexpected output: %#v", out)
	}

	// Validation error
	resNoUser := callWriteToolRaw(t, c, "revoke_sign_in_sessions", RevokeSignInSessionsInput{})
	if !resNoUser.IsError {
		t.Fatal("expected error on missing user_id")
	}

	// HTTP error
	resNotFound := callWriteToolRaw(t, c, "revoke_sign_in_sessions", RevokeSignInSessionsInput{UserID: "unknown-user"})
	if !resNotFound.IsError {
		t.Fatal("expected error on 404 from Graph")
	}
}

func TestEntraWritePolicyValidation(t *testing.T) {
	policyPath := filepath.Join("..", "..", "examples", "authz", "entra-write-policy.json")
	raw, err := os.ReadFile(policyPath)
	if err != nil {
		t.Fatalf("read policy file %s: %v", policyPath, err)
	}

	uidReplacer := strings.NewReplacer(
		`"service_uid": 991`, `"service_uid": `+strconv.Itoa(os.Geteuid()),
		`"forbidden_uids": [501, 1000]`, `"forbidden_uids": [99998, 99999]`,
	)
	uidAdjusted := []byte(uidReplacer.Replace(string(raw)))

	// Placeholder policy must fail closed with KNOWN_TEST_KEY_FORBIDDEN
	if _, err := authz.ParseAndValidatePolicyBytes("", uidAdjusted); err == nil || !strings.Contains(err.Error(), string(authz.ErrKnownTestKeyForbidden)) {
		t.Fatalf("expected KNOWN_TEST_KEY_FORBIDDEN on unedited placeholder policy, got %v", err)
	}

	// Generate clean random Ed25519 keys
	pub1, _, _ := ed25519.GenerateKey(rand.Reader)
	pub2, _, _ := ed25519.GenerateKey(rand.Reader)
	pub3, _, _ := ed25519.GenerateKey(rand.Reader)
	pub4, _, _ := ed25519.GenerateKey(rand.Reader)

	replacer := strings.NewReplacer(
		"<64-hex-admin-ed25519-public-key>", hex.EncodeToString(pub1),
		"<64-hex-idp-ed25519-public-key>", hex.EncodeToString(pub2),
		"<64-hex-secops-lead-ed25519-public-key>", hex.EncodeToString(pub3),
		"<64-hex-iam-oncall-ed25519-public-key>", hex.EncodeToString(pub4),
	)
	populated := []byte(replacer.Replace(string(uidAdjusted)))

	pol, err := authz.ParseAndValidatePolicyBytes("", populated)
	if err != nil {
		t.Fatalf("ParseAndValidatePolicyBytes with populated keys failed: %v", err)
	}
	if pol.GatewayID != "prod-entra-write-gw-01" {
		t.Fatalf("unexpected GatewayID: %s", pol.GatewayID)
	}
	if pol.Tools["add_group_member"] == nil || !pol.Tools["add_group_member"].Enabled {
		t.Fatal("expected add_group_member to be enabled in policy")
	}
	if pol.Tools["revoke_sign_in_sessions"] == nil || !pol.Tools["revoke_sign_in_sessions"].Enabled {
		t.Fatal("expected revoke_sign_in_sessions to be enabled in policy")
	}
}
