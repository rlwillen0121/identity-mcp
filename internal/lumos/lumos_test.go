package lumos

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/rlwillen0121/identity-mcp/internal/idmcp"
)

func testService(t *testing.T, h http.HandlerFunc) *Service {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	header := make(http.Header)
	header.Set("Authorization", "Bearer secret-token")
	header.Set("Accept", "application/json")
	return NewService(idmcp.NewClient(srv.URL, header))
}

func TestNewServerRegistersTools(t *testing.T) {
	s := httptest.NewServer(http.NotFoundHandler())
	t.Cleanup(s.Close)
	session := connectLumos(t, NewServer(idmcp.NewClient(s.URL, nil)))
	res, err := session.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"list_users", "get_user", "get_user_access", "list_apps", "list_app_accounts",
		"list_groups", "list_group_members", "find_stale_accounts", "list_access_reviews",
		"list_activity_logs",
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

func connectLumos(t *testing.T, server *mcp.Server) *mcp.ClientSession {
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

func TestListUsersBearerAndNextPage(t *testing.T) {
	svc := testService(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer secret-token" {
			t.Errorf("auth = %q", r.Header.Get("Authorization"))
		}
		if r.URL.Path != "/users" {
			t.Errorf("path = %s", r.URL.Path)
		}
		if r.URL.Query().Get("search_term") != "ada" {
			t.Errorf("search_term = %q", r.URL.Query().Get("search_term"))
		}
		if r.URL.Query().Get("page") != "1" {
			t.Errorf("page = %q", r.URL.Query().Get("page"))
		}
		w.Write([]byte(`{
			"items":[{"id":"u1","email":"ada@example.com","given_name":"Ada","family_name":"Lovelace","status":"ACTIVE"}],
			"total":2,"page":1,"size":1,"pages":2
		}`))
	})
	_, page, err := svc.ListUsers(context.Background(), nil, ListUsersInput{SearchTerm: "ada", Limit: 1})
	if err != nil {
		t.Fatal(err)
	}
	if page.Next != "2" || !page.Truncated {
		t.Fatalf("page = %#v", page)
	}
	if len(page.Items) != 1 || page.Items[0].Email != "ada@example.com" {
		t.Fatalf("items = %#v", page.Items)
	}
}

func TestListUsersRefusesAbsolutePage(t *testing.T) {
	hit := false
	svc := testService(t, func(http.ResponseWriter, *http.Request) {
		hit = true
	})
	_, _, err := svc.ListUsers(context.Background(), nil, ListUsersInput{Page: "https://evil.example/x"})
	if err == nil {
		t.Fatal("expected error")
	}
	if hit {
		t.Fatal("must not fetch attacker URL")
	}
}

func TestGetUserAccessComposesAndSlims(t *testing.T) {
	var paths []string
	svc := testService(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer secret-token" {
			t.Errorf("auth = %q", r.Header.Get("Authorization"))
		}
		paths = append(paths, r.URL.Path)
		switch {
		case r.URL.Path == "/users/u1":
			w.Write([]byte(`{"id":"u1","email":"ada@example.com","given_name":"Ada","family_name":"Lovelace","status":"ACTIVE"}`))
		case r.URL.Path == "/users/u1/accounts":
			if r.URL.Query().Get("expand") != "app" {
				t.Errorf("expand = %q", r.URL.Query().Get("expand"))
			}
			w.Write([]byte(`{
				"items":[{
					"id":"a1",
					"unique_identifier":"jdoe",
					"status":"ACTIVE",
					"last_login":"2020-01-01T00:00:00Z",
					"app":{"id":"app1","name":"Slack"}
				}],
				"page":1,"size":50,"pages":1,"total":1
			}`))
		case r.URL.Path == "/users/u1/roles":
			w.Write([]byte(`[{"name":"Admin"}]`))
		default:
			t.Errorf("unexpected path %s", r.URL.Path)
			http.NotFound(w, r)
		}
	})
	_, out, err := svc.GetUserAccess(context.Background(), nil, GetUserAccessInput{UserID: "u1"})
	if err != nil {
		t.Fatal(err)
	}
	if out.ID != "u1" || out.Email != "ada@example.com" || out.Status != "ACTIVE" {
		t.Fatalf("user = %#v", out)
	}
	if len(out.Roles) != 1 || out.Roles[0] != "Admin" {
		t.Fatalf("roles = %#v", out.Roles)
	}
	if len(out.Accounts) != 1 {
		t.Fatalf("accounts = %#v", out.Accounts)
	}
	a := out.Accounts[0]
	if a.ID != "a1" || a.AppID != "app1" || a.AppName != "Slack" || a.LastLogin != "2020-01-01T00:00:00Z" || a.UniqueIdentifier != "jdoe" {
		t.Fatalf("account = %#v", a)
	}
	joined := strings.Join(paths, " ")
	for _, want := range []string{"/users/u1", "/users/u1/accounts", "/users/u1/roles"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("missing path %s in %v", want, paths)
		}
	}
}

func TestFindStaleAccountsFlagsAndCap(t *testing.T) {
	svc := testService(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/accounts" {
			t.Errorf("path = %s", r.URL.Path)
		}
		if r.URL.Query().Get("expand") != "app" {
			t.Errorf("expand = %q", r.URL.Query().Get("expand"))
		}
		w.Write([]byte(`{
			"items":[
				{"id":"a-susp","unique_identifier":"s","status":"SUSPENDED","app":{"id":"app1","name":"Slack"}},
				{"id":"a-nologin","unique_identifier":"n","status":"ACTIVE","app":{"id":"app1","name":"Slack"}},
				{"id":"a-old","unique_identifier":"o","status":"ACTIVE","last_login":"2020-01-01T00:00:00Z","app":{"id":"app1","name":"Slack"}},
				{"id":"a-ok","unique_identifier":"ok","status":"ACTIVE","last_login":"2099-01-01T00:00:00Z","app":{"id":"app1","name":"Slack"}}
			],
			"page":1,"size":50,"pages":1,"total":4
		}`))
	})
	_, page, err := svc.FindStaleAccounts(context.Background(), nil, FindStaleAccountsInput{InactiveDays: 90, Limit: 50})
	if err != nil {
		t.Fatal(err)
	}
	byID := map[string]StaleAccount{}
	for _, it := range page.Items {
		byID[it.ID] = it
	}
	if _, ok := byID["a-ok"]; ok {
		t.Fatalf("active recent should not be stale: %#v", page.Items)
	}
	if !contains(byID["a-susp"].Reasons, "SUSPENDED") {
		t.Fatalf("susp reasons = %v", byID["a-susp"].Reasons)
	}
	if !contains(byID["a-nologin"].Reasons, "no_login") {
		t.Fatalf("nologin reasons = %v", byID["a-nologin"].Reasons)
	}
	if !contains(byID["a-old"].Reasons, "login_older_than_90_days") {
		t.Fatalf("old reasons = %v", byID["a-old"].Reasons)
	}
}

func TestFindStaleAccountsInspectCap(t *testing.T) {
	calls := 0
	svc := testService(t, func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.Write([]byte(`{
			"items":[
				{"id":"s0","status":"SUSPENDED","app":{"id":"app1","name":"Slack"}},
				{"id":"s1","status":"SUSPENDED","app":{"id":"app1","name":"Slack"}},
				{"id":"s2","status":"SUSPENDED","app":{"id":"app1","name":"Slack"}}
			],
			"page":1,"size":50,"pages":2,"total":6
		}`))
	})
	_, page, err := svc.FindStaleAccounts(context.Background(), nil, FindStaleAccountsInput{Limit: 2})
	if err != nil {
		t.Fatal(err)
	}
	if calls != 1 {
		t.Fatalf("calls = %d", calls)
	}
	if !page.Truncated || page.Next != "" || page.Scanned != 3 || len(page.Items) != 2 {
		t.Fatalf("page = %#v", page)
	}
}

func TestFindStaleAccountsOversizedPageStopsAtCap(t *testing.T) {
	const limit = 10
	const rows = 600
	calls := 0
	svc := testService(t, func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.URL.Path != "/accounts" {
			t.Errorf("path = %s", r.URL.Path)
		}
		var b strings.Builder
		b.WriteString(`{"items":[`)
		for i := 0; i < rows; i++ {
			if i > 0 {
				b.WriteByte(',')
			}
			fmt.Fprintf(&b, `{"id":"a%d","status":"SUSPENDED","app":{"id":"app1","name":"Slack"}}`, i)
		}
		b.WriteString(`],"page":1,"size":50,"pages":1,"total":600}`)
		_, _ = w.Write([]byte(b.String()))
	})
	_, page, err := svc.FindStaleAccounts(context.Background(), nil, FindStaleAccountsInput{Limit: limit})
	if err != nil {
		t.Fatal(err)
	}
	if calls != 1 {
		t.Fatalf("calls = %d", calls)
	}
	if page.Scanned > 500 || !page.Truncated || len(page.Items) > limit {
		t.Fatalf("page = %#v", page)
	}
	if page.Scanned != 500 || len(page.Items) != limit || page.Next != "1" {
		t.Fatalf("scanned=%d items=%d next=%q truncated=%v", page.Scanned, len(page.Items), page.Next, page.Truncated)
	}
}

func TestActivityLogsDoesNotFollowLinksNext(t *testing.T) {
	var paths []string
	svc := testService(t, func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.URL.Path)
		if r.URL.Path != "/activity_logs" {
			t.Errorf("path = %s", r.URL.Path)
		}
		if r.URL.Query().Get("limit") != "50" {
			t.Errorf("limit = %q", r.URL.Query().Get("limit"))
		}
		w.Write([]byte(`{
			"items":[{
				"event_hash":"h1",
				"event_type":"access.request.created",
				"event_type_user_friendly":"Access requested",
				"outcome":"SUCCESS",
				"event_began_at":"2024-01-01T00:00:00Z",
				"actor":{"id":"u1","email":"ada@example.com"}
			}],
			"total":1,"limit":50,"offset":0,
			"links":{"next":"https://evil.example/steal"}
		}`))
	})
	_, page, err := svc.ListActivityLogs(context.Background(), nil, ListActivityLogsInput{})
	if err != nil {
		t.Fatal(err)
	}
	if page.Next != "" {
		t.Fatalf("must not use links.next URL as cursor, next=%q", page.Next)
	}
	if len(page.Items) != 1 || page.Items[0].ActorEmail != "ada@example.com" || page.Items[0].ActorID != "u1" {
		t.Fatalf("items = %#v", page.Items)
	}
	for _, p := range paths {
		if strings.Contains(p, "evil") {
			t.Fatalf("followed links.next: %v", paths)
		}
	}
}

func TestListGroupsPageShape(t *testing.T) {
	svc := testService(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/groups" {
			t.Errorf("path = %s", r.URL.Path)
		}
		w.Write([]byte(`{"items":[{"id":"g1","name":"Eng"}],"page":1,"size":50,"pages":1,"total":1}`))
	})
	_, page, err := svc.ListGroups(context.Background(), nil, ListGroupsInput{})
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Items) != 1 || page.Items[0].Name != "Eng" {
		t.Fatalf("items = %#v", page.Items)
	}
}

func TestParseRolesShapes(t *testing.T) {
	if got := parseRoles([]byte(`[{"name":"Admin"}]`)); len(got) != 1 || got[0] != "Admin" {
		t.Fatalf("name objects = %#v", got)
	}
	if got := parseRoles([]byte(`["Admin","IT"]`)); len(got) != 2 {
		t.Fatalf("strings = %#v", got)
	}
	if got := parseRoles([]byte(`{"items":[{"name":"Admin"}]}`)); len(got) != 1 || got[0] != "Admin" {
		t.Fatalf("wrapped = %#v", got)
	}
}

func TestAccountItemLastLoginFallbacks(t *testing.T) {
	var a rawAccount
	if err := json.Unmarshal([]byte(`{"id":"a1","unique_identifier":"jdoe","status":"ACTIVE","last_login":"2020-01-01T00:00:00Z","app":{"id":"app1","name":"Slack"}}`), &a); err != nil {
		t.Fatal(err)
	}
	got := accountItem(a)
	if got.LastLogin != "2020-01-01T00:00:00Z" || got.AppName != "Slack" {
		t.Fatalf("got = %#v", got)
	}
	var b rawAccount
	if err := json.Unmarshal([]byte(`{"id":"a2","status":"SUSPENDED"}`), &b); err != nil {
		t.Fatal(err)
	}
	got = accountItem(b)
	if got.LastLogin != "" || got.Status != "SUSPENDED" {
		t.Fatalf("status-only = %#v", got)
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

func TestNewServerWithOptions(t *testing.T) {
	s := httptest.NewServer(http.NotFoundHandler())
	t.Cleanup(s.Close)

	t.Run("writes disabled returns 10 read-only tools", func(t *testing.T) {
		session := connectLumos(t, NewServerWithOptions(idmcp.NewClient(s.URL, nil), false))
		res, err := session.ListTools(context.Background(), nil)
		if err != nil {
			t.Fatal(err)
		}
		if len(res.Tools) != 10 {
			t.Fatalf("expected 10 tools, got %d", len(res.Tools))
		}
		for _, tool := range res.Tools {
			if tool.Name == "create_access_request" || tool.Name == "remove_group_member" {
				t.Fatalf("unexpected write tool %s when writes disabled", tool.Name)
			}
		}
	})

	t.Run("writes enabled returns 12 tools with proper annotations", func(t *testing.T) {
		session := connectLumos(t, NewServerWithOptions(idmcp.NewClient(s.URL, nil), true))
		res, err := session.ListTools(context.Background(), nil)
		if err != nil {
			t.Fatal(err)
		}
		if len(res.Tools) != 12 {
			t.Fatalf("expected 12 tools, got %d", len(res.Tools))
		}
		toolsByName := map[string]*mcp.Tool{}
		for _, tool := range res.Tools {
			toolsByName[tool.Name] = tool
		}

		// Verify create_access_request
		reqTool, ok := toolsByName["create_access_request"]
		if !ok {
			t.Fatal("missing create_access_request tool")
		}
		if reqTool.Title != "Create access request" {
			t.Errorf("create_access_request title = %q, want 'Create access request'", reqTool.Title)
		}
		if reqTool.Annotations == nil {
			t.Fatal("create_access_request annotations is nil")
		}
		if reqTool.Annotations.ReadOnlyHint {
			t.Error("create_access_request ReadOnlyHint should be false")
		}
		if reqTool.Annotations.IdempotentHint {
			t.Error("create_access_request IdempotentHint should be false")
		}
		if reqTool.Annotations.DestructiveHint == nil || *reqTool.Annotations.DestructiveHint {
			t.Error("create_access_request DestructiveHint should be false")
		}
		if reqTool.Annotations.OpenWorldHint == nil || !*reqTool.Annotations.OpenWorldHint {
			t.Error("create_access_request OpenWorldHint should be true")
		}

		// Verify remove_group_member
		remTool, ok := toolsByName["remove_group_member"]
		if !ok {
			t.Fatal("missing remove_group_member tool")
		}
		if remTool.Title != "Remove group member" {
			t.Errorf("remove_group_member title = %q, want 'Remove group member'", remTool.Title)
		}
		if remTool.Annotations == nil {
			t.Fatal("remove_group_member annotations is nil")
		}
		if remTool.Annotations.ReadOnlyHint {
			t.Error("remove_group_member ReadOnlyHint should be false")
		}
		if !remTool.Annotations.IdempotentHint {
			t.Error("remove_group_member IdempotentHint should be true")
		}
		if remTool.Annotations.DestructiveHint == nil || !*remTool.Annotations.DestructiveHint {
			t.Error("remove_group_member DestructiveHint should be true")
		}
		if remTool.Annotations.OpenWorldHint == nil || !*remTool.Annotations.OpenWorldHint {
			t.Error("remove_group_member OpenWorldHint should be true")
		}
	})
}

func TestCreateAccessRequest(t *testing.T) {
	t.Run("happy path with id and status response", func(t *testing.T) {
		var receivedMethod, receivedPath, receivedAuth, receivedCT string
		var receivedBody map[string]string
		svc := testService(t, func(w http.ResponseWriter, r *http.Request) {
			receivedMethod = r.Method
			receivedPath = r.URL.Path
			receivedAuth = r.Header.Get("Authorization")
			receivedCT = r.Header.Get("Content-Type")
			_ = json.NewDecoder(r.Body).Decode(&receivedBody)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			w.Write([]byte(`{"id":"req-001","status":"PENDING"}`))
		})
		_, res, err := svc.CreateAccessRequest(context.Background(), nil, CreateAccessRequestInput{
			UserID: "u100",
			AppID:  "app-slack",
			Reason: "Needs Slack for eng on-call",
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if receivedMethod != http.MethodPost {
			t.Errorf("method = %s, want POST", receivedMethod)
		}
		if receivedPath != "/access_requests" {
			t.Errorf("path = %s, want /access_requests", receivedPath)
		}
		if receivedAuth != "Bearer secret-token" {
			t.Errorf("auth = %s, want Bearer secret-token", receivedAuth)
		}
		if receivedCT != "application/json" {
			t.Errorf("content-type = %s, want application/json", receivedCT)
		}
		if receivedBody["user_id"] != "u100" || receivedBody["app_id"] != "app-slack" || receivedBody["reason"] != "Needs Slack for eng on-call" {
			t.Errorf("receivedBody = %#v", receivedBody)
		}
		if res.RequestID != "req-001" {
			t.Errorf("request_id = %s, want req-001", res.RequestID)
		}
		if res.UserID != "u100" {
			t.Errorf("user_id = %s, want u100", res.UserID)
		}
		if res.AppID != "app-slack" {
			t.Errorf("app_id = %s, want app-slack", res.AppID)
		}
		if res.Status != "PENDING" {
			t.Errorf("status = %s, want PENDING", res.Status)
		}
	})

	t.Run("happy path with request_id and explicit fields", func(t *testing.T) {
		svc := testService(t, func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"request_id":"req-002","user_id":"u200","app_id":"app-aws","status":"APPROVED"}`))
		})
		_, res, err := svc.CreateAccessRequest(context.Background(), nil, CreateAccessRequestInput{
			UserID: "u200",
			AppID:  "app-aws",
			Reason: "Cloud admin",
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if res.RequestID != "req-002" || res.UserID != "u200" || res.AppID != "app-aws" || res.Status != "APPROVED" {
			t.Errorf("result = %#v", res)
		}
	})

	t.Run("empty response defaults status", func(t *testing.T) {
		svc := testService(t, func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNoContent)
		})
		_, res, err := svc.CreateAccessRequest(context.Background(), nil, CreateAccessRequestInput{
			UserID: "u300",
			AppID:  "app-zoom",
			Reason: "Meetings",
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if res.Status != "SUBMITTED" || res.UserID != "u300" || res.AppID != "app-zoom" {
			t.Errorf("result = %#v", res)
		}
	})

	t.Run("validation errors", func(t *testing.T) {
		svc := testService(t, func(w http.ResponseWriter, r *http.Request) {
			t.Fatal("server should not be called on validation error")
		})
		// missing user_id
		if _, _, err := svc.CreateAccessRequest(context.Background(), nil, CreateAccessRequestInput{
			AppID:  "app1",
			Reason: "justification",
		}); err == nil || !strings.Contains(err.Error(), "user_id is required") {
			t.Errorf("expected user_id required, got %v", err)
		}

		// missing app_id
		if _, _, err := svc.CreateAccessRequest(context.Background(), nil, CreateAccessRequestInput{
			UserID: "u1",
			Reason: "justification",
		}); err == nil || !strings.Contains(err.Error(), "app_id is required") {
			t.Errorf("expected app_id required, got %v", err)
		}

		// missing reason
		if _, _, err := svc.CreateAccessRequest(context.Background(), nil, CreateAccessRequestInput{
			UserID: "u1",
			AppID:  "app1",
		}); err == nil || !strings.Contains(err.Error(), "reason is required") {
			t.Errorf("expected reason required, got %v", err)
		}

		// invalid dot-segment user_id
		if _, _, err := svc.CreateAccessRequest(context.Background(), nil, CreateAccessRequestInput{
			UserID: "..",
			AppID:  "app1",
			Reason: "justification",
		}); err == nil || !strings.Contains(err.Error(), "invalid user_id") {
			t.Errorf("expected invalid user_id error, got %v", err)
		}

		// oversized reason
		if _, _, err := svc.CreateAccessRequest(context.Background(), nil, CreateAccessRequestInput{
			UserID: "u1",
			AppID:  "app1",
			Reason: strings.Repeat("a", 1025),
		}); err == nil {
			t.Errorf("expected error on oversized reason")
		}
	})

	t.Run("http error response", func(t *testing.T) {
		svc := testService(t, func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, `{"error":"forbidden"}`, http.StatusForbidden)
		})
		_, _, err := svc.CreateAccessRequest(context.Background(), nil, CreateAccessRequestInput{
			UserID: "u1",
			AppID:  "app1",
			Reason: "justification",
		})
		if err == nil {
			t.Fatal("expected http error, got nil")
		}
		if idmcp.StatusOf(err) != http.StatusForbidden {
			t.Errorf("status = %d, want 403", idmcp.StatusOf(err))
		}
	})
}

func TestRemoveGroupMember(t *testing.T) {
	t.Run("happy path 204 no content", func(t *testing.T) {
		var receivedMethod, receivedPath, receivedAuth string
		svc := testService(t, func(w http.ResponseWriter, r *http.Request) {
			receivedMethod = r.Method
			receivedPath = r.URL.Path
			receivedAuth = r.Header.Get("Authorization")
			w.WriteHeader(http.StatusNoContent)
		})
		_, res, err := svc.RemoveGroupMember(context.Background(), nil, RemoveGroupMemberInput{
			GroupID: "grp-123",
			UserID:  "usr-456",
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if receivedMethod != http.MethodDelete {
			t.Errorf("method = %s, want DELETE", receivedMethod)
		}
		if receivedPath != "/groups/grp-123/members/usr-456" {
			t.Errorf("path = %s, want /groups/grp-123/members/usr-456", receivedPath)
		}
		if receivedAuth != "Bearer secret-token" {
			t.Errorf("auth = %s, want Bearer secret-token", receivedAuth)
		}
		if res.GroupID != "grp-123" || res.UserID != "usr-456" || res.Status != "REMOVED" {
			t.Errorf("result = %#v", res)
		}
	})

	t.Run("happy path with status response", func(t *testing.T) {
		svc := testService(t, func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"status":"SUCCESS"}`))
		})
		_, res, err := svc.RemoveGroupMember(context.Background(), nil, RemoveGroupMemberInput{
			GroupID: "grp-1",
			UserID:  "usr-1",
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if res.Status != "SUCCESS" {
			t.Errorf("status = %s, want SUCCESS", res.Status)
		}
	})

	t.Run("escapes path parameters", func(t *testing.T) {
		var receivedPath string
		svc := testService(t, func(w http.ResponseWriter, r *http.Request) {
			receivedPath = r.URL.RawPath
			if receivedPath == "" {
				receivedPath = r.URL.Path
			}
			w.WriteHeader(http.StatusNoContent)
		})
		_, _, err := svc.RemoveGroupMember(context.Background(), nil, RemoveGroupMemberInput{
			GroupID: "grp/special",
			UserID:  "usr/special",
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !strings.Contains(receivedPath, "grp%2Fspecial") || !strings.Contains(receivedPath, "usr%2Fspecial") {
			t.Errorf("path was not escaped: %s", receivedPath)
		}
	})

	t.Run("validation errors", func(t *testing.T) {
		svc := testService(t, func(w http.ResponseWriter, r *http.Request) {
			t.Fatal("server should not be called on validation error")
		})
		// missing group_id
		if _, _, err := svc.RemoveGroupMember(context.Background(), nil, RemoveGroupMemberInput{
			UserID: "u1",
		}); err == nil || !strings.Contains(err.Error(), "group_id is required") {
			t.Errorf("expected group_id required, got %v", err)
		}

		// missing user_id
		if _, _, err := svc.RemoveGroupMember(context.Background(), nil, RemoveGroupMemberInput{
			GroupID: "g1",
		}); err == nil || !strings.Contains(err.Error(), "user_id is required") {
			t.Errorf("expected user_id required, got %v", err)
		}

		// invalid dot-segment
		if _, _, err := svc.RemoveGroupMember(context.Background(), nil, RemoveGroupMemberInput{
			GroupID: ".",
			UserID:  "u1",
		}); err == nil || !strings.Contains(err.Error(), "invalid group_id") {
			t.Errorf("expected invalid group_id, got %v", err)
		}
	})

	t.Run("http error response", func(t *testing.T) {
		svc := testService(t, func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, `{"error":"not found"}`, http.StatusNotFound)
		})
		_, _, err := svc.RemoveGroupMember(context.Background(), nil, RemoveGroupMemberInput{
			GroupID: "g1",
			UserID:  "u1",
		})
		if err == nil {
			t.Fatal("expected http error, got nil")
		}
		if idmcp.StatusOf(err) != http.StatusNotFound {
			t.Errorf("status = %d, want 404", idmcp.StatusOf(err))
		}
	})
}

func TestMCPToolCall_WriteTools(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/access_requests":
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			w.Write([]byte(`{"id":"req-999","status":"PENDING"}`))
		case r.Method == http.MethodDelete && strings.HasPrefix(r.URL.Path, "/groups/"):
			w.WriteHeader(http.StatusNoContent)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)

	session := connectLumos(t, NewServerWithOptions(idmcp.NewClient(srv.URL, nil), true))
	ctx := context.Background()

	// Call create_access_request via MCP
	callRes1, err := session.CallTool(ctx, &mcp.CallToolParams{
		Name: "create_access_request",
		Arguments: map[string]any{
			"user_id": "u1",
			"app_id":  "app1",
			"reason":  "testing access",
		},
	})
	if err != nil {
		t.Fatalf("CallTool create_access_request failed: %v", err)
	}
	if callRes1.IsError {
		t.Fatalf("callRes1 returned tool error: %#v", callRes1)
	}
	if len(callRes1.Content) == 0 {
		t.Fatal("callRes1 returned empty content")
	}

	// Call remove_group_member via MCP
	callRes2, err := session.CallTool(ctx, &mcp.CallToolParams{
		Name: "remove_group_member",
		Arguments: map[string]any{
			"group_id": "grp1",
			"user_id":  "u1",
		},
	})
	if err != nil {
		t.Fatalf("CallTool remove_group_member failed: %v", err)
	}
	if callRes2.IsError {
		t.Fatalf("callRes2 returned tool error: %#v", callRes2)
	}
	if len(callRes2.Content) == 0 {
		t.Fatal("callRes2 returned empty content")
	}
}

func TestLumosWritePolicyExample(t *testing.T) {
	data, err := os.ReadFile("../../examples/authz/lumos-write-policy.json")
	if err != nil {
		t.Fatalf("failed to read lumos-write-policy.json: %v", err)
	}
	var pol map[string]any
	if err := json.Unmarshal(data, &pol); err != nil {
		t.Fatalf("failed to unmarshal lumos-write-policy.json: %v", err)
	}
	if pol["schema_version"] != "mcp-authz-policy/v1" {
		t.Errorf("schema_version = %v, want mcp-authz-policy/v1", pol["schema_version"])
	}
	if pol["server_name"] != "lumos-write-mcp" {
		t.Errorf("server_name = %v, want lumos-write-mcp", pol["server_name"])
	}
	tools, ok := pol["tools"].(map[string]any)
	if !ok {
		t.Fatal("missing or invalid tools section")
	}
	if _, ok := tools["create_access_request"]; !ok {
		t.Error("missing create_access_request in policy tools")
	}
	if _, ok := tools["remove_group_member"]; !ok {
		t.Error("missing remove_group_member in policy tools")
	}
	content := string(data)
	for _, ph := range []string{
		"<64-hex-admin-ed25519-public-key>",
		"<64-hex-idp-ed25519-public-key>",
		"<64-hex-secops-lead-ed25519-public-key>",
		"<64-hex-iam-oncall-ed25519-public-key>",
	} {
		if !strings.Contains(content, ph) {
			t.Errorf("missing expected placeholder %s in policy", ph)
		}
	}
}

