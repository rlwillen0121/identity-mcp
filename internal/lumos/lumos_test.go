package lumos

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
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
