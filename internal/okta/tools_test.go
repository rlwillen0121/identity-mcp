package okta

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/rlwillen0121/identity-mcp/internal/idmcp"
)

func testService(t *testing.T, h http.HandlerFunc) *Service {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	header := make(http.Header)
	header.Set("Authorization", "SSWS secret-token")
	return NewService(idmcp.NewClient(srv.URL, header))
}

func TestNewServerRegistersTools(t *testing.T) {
	s := httptest.NewServer(http.NotFoundHandler())
	t.Cleanup(s.Close)
	if NewServer(idmcp.NewClient(s.URL, nil)) == nil {
		t.Fatal("nil server")
	}
}

func TestListUsersParsesItemsAndNextCursor(t *testing.T) {
	svc := testService(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/users" {
			t.Errorf("path = %s", r.URL.Path)
		}
		if r.Header.Get("Authorization") != "SSWS secret-token" {
			t.Errorf("auth = %q", r.Header.Get("Authorization"))
		}
		if r.URL.Query().Get("search") != `profile.email eq "ada@example.com"` {
			t.Errorf("search = %q", r.URL.Query().Get("search"))
		}
		w.Header().Set("Link", `<https://example.okta.com/api/v1/users?after=00uNEXT&limit=1>; rel="next"`)
		w.Write([]byte(`[
			{
				"id": "00u1",
				"status": "ACTIVE",
				"created": "2020-01-01T00:00:00.000Z",
				"lastLogin": "2021-06-01T12:00:00.000Z",
				"lastUpdated": "2021-07-01T00:00:00.000Z",
				"profile": {"login": "ada@example.com", "email": "ada@example.com"}
			}
		]`))
	})

	_, page, err := svc.ListUsers(context.Background(), nil, ListUsersInput{
		Search: `profile.email eq "ada@example.com"`,
		Limit:  1,
	})
	if err != nil {
		t.Fatal(err)
	}
	if page.Next != "00uNEXT" {
		t.Fatalf("next = %q", page.Next)
	}
	if !page.Truncated {
		t.Fatal("expected truncated")
	}
	if len(page.Items) != 1 {
		t.Fatalf("items = %#v", page.Items)
	}
	got := page.Items[0]
	if got.ID != "00u1" || got.Login != "ada@example.com" || got.Email != "ada@example.com" {
		t.Fatalf("item = %#v", got)
	}
	if got.Status != "ACTIVE" || got.LastLogin != "2021-06-01T12:00:00.000Z" {
		t.Fatalf("item = %#v", got)
	}
}

func TestGetUser404IsError(t *testing.T) {
	svc := testService(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/users/missing" {
			t.Errorf("path = %s", r.URL.Path)
		}
		http.Error(w, `{"errorCode":"E0000007","errorSummary":"Not found: Resource not found: missing (User)"}`, http.StatusNotFound)
	})

	_, _, err := svc.GetUser(context.Background(), nil, GetUserInput{IDOrLogin: "missing"})
	if err == nil {
		t.Fatal("expected error")
	}
	msg := err.Error()
	if !strings.Contains(msg, "404") {
		t.Fatalf("error = %q", msg)
	}
	if strings.Contains(msg, "secret-token") || strings.Contains(msg, "SSWS") {
		t.Fatalf("token leaked: %s", msg)
	}
}

func TestFindStaleUsersClassifiesMissingLastLogin(t *testing.T) {
	svc := testService(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/users" {
			t.Errorf("path = %s", r.URL.Path)
		}
		w.Write([]byte(`[
			{
				"id": "00u-nologin",
				"status": "ACTIVE",
				"lastLogin": null,
				"profile": {"login": "none@example.com", "email": "none@example.com"}
			},
			{
				"id": "00u-recent",
				"status": "ACTIVE",
				"lastLogin": "2099-01-01T00:00:00.000Z",
				"profile": {"login": "recent@example.com"}
			},
			{
				"id": "00u-staged",
				"status": "STAGED",
				"profile": {"login": "staged@example.com"}
			}
		]`))
	})

	_, page, err := svc.FindStaleUsers(context.Background(), nil, FindStaleUsersInput{InactiveDays: 90, Limit: 50})
	if err != nil {
		t.Fatal(err)
	}
	byID := map[string]StaleUser{}
	for _, it := range page.Items {
		byID[it.ID] = it
	}
	if byID["00u-nologin"].Reason != "no_login" {
		t.Fatalf("missing lastLogin: %#v", byID["00u-nologin"])
	}
	if _, ok := byID["00u-recent"]; ok {
		t.Fatalf("recent user should not be stale: %#v", byID["00u-recent"])
	}
	if byID["00u-staged"].Reason != "non_active_status" {
		t.Fatalf("staged: %#v", byID["00u-staged"])
	}
}

func TestListLogsMapsFields(t *testing.T) {
	svc := testService(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/logs" {
			t.Errorf("path = %s", r.URL.Path)
		}
		w.Write([]byte(`[
			{
				"uuid": "log-1",
				"published": "2024-02-01T15:04:05.000Z",
				"eventType": "user.session.start",
				"displayMessage": "User login to Okta",
				"actor": {
					"id": "00u1",
					"type": "User",
					"alternateId": "ada@example.com",
					"displayName": "Ada Lovelace"
				},
				"outcome": {"result": "SUCCESS", "reason": "ALLOWED"},
				"target": [
					{
						"id": "0oa1",
						"type": "AppInstance",
						"alternateId": "okta_dashboard",
						"displayName": "Okta Dashboard"
					}
				]
			}
		]`))
	})

	_, page, err := svc.ListLogs(context.Background(), nil, ListLogsInput{Limit: 200})
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Items) != 1 {
		t.Fatalf("items = %#v", page.Items)
	}
	got := page.Items[0]
	if got.UUID != "log-1" || got.EventType != "user.session.start" {
		t.Fatalf("item = %#v", got)
	}
	if got.DisplayMessage != "User login to Okta" || got.Published != "2024-02-01T15:04:05.000Z" {
		t.Fatalf("item = %#v", got)
	}
	if got.Actor != "Ada Lovelace (ada@example.com)" {
		t.Fatalf("actor = %q", got.Actor)
	}
	if got.Outcome != "SUCCESS: ALLOWED" {
		t.Fatalf("outcome = %q", got.Outcome)
	}
	if got.Target != "Okta Dashboard (AppInstance)" {
		t.Fatalf("target = %q", got.Target)
	}
}

func TestParseAdminsValueShape(t *testing.T) {
	body := []byte(`{
		"value": [
			{"id": "00uadmin", "orn": "orn:okta:directory:00o:users:00uadmin", "roles": [{"label": "Super Administrator", "type": "SUPER_ADMIN"}]},
			{"user": {"id": "00unested", "profile": {"login": "boss@example.com", "email": "boss@example.com"}}}
		]
	}`)
	items, err := parseAdmins(body)
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 2 {
		t.Fatalf("items = %#v", items)
	}
	if items[0].ID != "00uadmin" || strings.Join(items[0].RoleLabels, ",") != "Super Administrator" {
		t.Fatalf("first = %#v", items[0])
	}
	if items[1].ID != "00unested" || items[1].Login != "boss@example.com" || items[1].Email != "boss@example.com" {
		t.Fatalf("second = %#v", items[1])
	}
}

func TestListLogsLimitCappedInQuery(t *testing.T) {
	var gotLimit string
	svc := testService(t, func(w http.ResponseWriter, r *http.Request) {
		gotLimit = r.URL.Query().Get("limit")
		w.Write([]byte(`[]`))
	})
	if _, _, err := svc.ListLogs(context.Background(), nil, ListLogsInput{Limit: 500}); err != nil {
		t.Fatal(err)
	}
	if gotLimit != "100" {
		t.Fatalf("limit = %q", gotLimit)
	}
}

func TestUserJSONRoundTripNullLastLogin(t *testing.T) {
	var u oktaUser
	if err := json.Unmarshal([]byte(`{"id":"00u","status":"ACTIVE","lastLogin":null,"profile":{"login":"a"}}`), &u); err != nil {
		t.Fatal(err)
	}
	if deref(u.LastLogin) != "" {
		t.Fatalf("lastLogin = %v", u.LastLogin)
	}
}

func TestGetJSONRejectsAbsoluteAfter(t *testing.T) {
	hit := false
	svc := testService(t, func(http.ResponseWriter, *http.Request) { hit = true })
	_, _, err := svc.ListUsers(context.Background(), nil, ListUsersInput{After: "http://127.0.0.1/steal"})
	if err == nil {
		t.Fatal("expected error")
	}
	if hit {
		t.Fatal("must not call Okta with attacker URL")
	}
}

func TestParseAdminsUnknownShape(t *testing.T) {
	if _, err := parseAdmins([]byte(`{"foo":1}`)); err == nil {
		t.Fatal("expected error")
	}
}

func TestParseAdminsEmptyValue(t *testing.T) {
	items, err := parseAdmins([]byte(`{"value":[]}`))
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 0 {
		t.Fatalf("items = %#v", items)
	}
}

func TestListUsersTwoLinkHeaderLines(t *testing.T) {
	svc := testService(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("Link", `<https://example.okta.com/api/v1/users?after=SELF&limit=1>; rel="self"`)
		w.Header().Add("Link", `<https://example.okta.com/api/v1/users?after=00uNEXT&limit=1>; rel="next"`)
		w.Write([]byte(`[{"id":"00u1","status":"ACTIVE","profile":{"login":"ada@example.com"}}]`))
	})
	_, page, err := svc.ListUsers(context.Background(), nil, ListUsersInput{Limit: 1})
	if err != nil {
		t.Fatal(err)
	}
	if page.Next != "00uNEXT" || !page.Truncated {
		t.Fatalf("page = %#v", page)
	}
}

func TestFindStaleUsersTwoLinkPages(t *testing.T) {
	calls := 0
	svc := testService(t, func(w http.ResponseWriter, r *http.Request) {
		calls++
		after := r.URL.Query().Get("after")
		if after == "" {
			w.Header().Add("Link", `<https://example.okta.com/api/v1/users?after=p1&limit=50>; rel="self"`)
			w.Header().Add("Link", `<https://example.okta.com/api/v1/users?after=p2&limit=50>; rel="next"`)
			w.Write([]byte(`[{"id":"fresh","status":"ACTIVE","lastLogin":"2099-01-01T00:00:00.000Z","profile":{"login":"fresh@example.com"}}]`))
			return
		}
		w.Write([]byte(`[{"id":"stale","status":"ACTIVE","lastLogin":null,"profile":{"login":"stale@example.com"}}]`))
	})
	_, page, err := svc.FindStaleUsers(context.Background(), nil, FindStaleUsersInput{InactiveDays: 90, Limit: 50})
	if err != nil {
		t.Fatal(err)
	}
	if calls != 2 {
		t.Fatalf("calls = %d", calls)
	}
	if page.Scanned != 2 || len(page.Items) != 1 || page.Items[0].ID != "stale" {
		t.Fatalf("page = %#v", page)
	}
}

func TestFindStaleUsersLeftoverDoesNotAdvanceCursor(t *testing.T) {
	calls := 0
	svc := testService(t, func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.Header().Add("Link", `<https://example.okta.com/api/v1/users?after=self&limit=50>; rel="self"`)
		w.Header().Add("Link", `<https://example.okta.com/api/v1/users?after=p2&limit=50>; rel="next"`)
		w.Write([]byte(`[
			{"id":"s0","status":"STAGED","profile":{"login":"s0"}},
			{"id":"s1","status":"STAGED","profile":{"login":"s1"}},
			{"id":"s2","status":"STAGED","profile":{"login":"s2"}}
		]`))
	})
	_, page, err := svc.FindStaleUsers(context.Background(), nil, FindStaleUsersInput{Limit: 2})
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

func TestListLogsDropsSinceWhenAfterSet(t *testing.T) {
	var since, until, after string
	svc := testService(t, func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		since, until, after = q.Get("since"), q.Get("until"), q.Get("after")
		w.Write([]byte(`[]`))
	})
	_, _, err := svc.ListLogs(context.Background(), nil, ListLogsInput{
		Since: "2024-01-01T00:00:00.000Z",
		Until: "2024-02-01T00:00:00.000Z",
		After: "1627500044869_1",
	})
	if err != nil {
		t.Fatal(err)
	}
	if after != "1627500044869_1" {
		t.Fatalf("after = %q", after)
	}
	if since != "" || until != "" {
		t.Fatalf("since=%q until=%q (must omit when after is set)", since, until)
	}
}

func TestListAdminsDocumentedPayload(t *testing.T) {
	svc := testService(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/api/v1/iam/assignees/users":
			w.Write([]byte(`{
				"value":[{"id":"00u118oQYT4TBGuay0g4","orn":"orn:okta:directory:00o:users:00u118oQYT4TBGuay0g4"}],
				"_links":{"next":{"href":"https://example.okta.com/api/v1/iam/assignees/users?after=00uNEXT"}}
			}`))
		case r.URL.Path == "/api/v1/users/00u118oQYT4TBGuay0g4":
			w.Write([]byte(`{"id":"00u118oQYT4TBGuay0g4","profile":{"login":"ada@example.com","email":"ada@example.com"}}`))
		case r.URL.Path == "/api/v1/users/00u118oQYT4TBGuay0g4/roles":
			w.Write([]byte(`[{"id":"role1","label":"Super Administrator","type":"SUPER_ADMIN"}]`))
		default:
			t.Errorf("unexpected path %s", r.URL.Path)
			http.NotFound(w, r)
		}
	})
	_, page, err := svc.ListAdmins(context.Background(), nil, ListAdminsInput{Limit: 50})
	if err != nil {
		t.Fatal(err)
	}
	if page.Next != "00uNEXT" || !page.Truncated {
		t.Fatalf("page next = %#v", page)
	}
	if len(page.Items) != 1 {
		t.Fatalf("items = %#v", page.Items)
	}
	got := page.Items[0]
	if got.ID != "00u118oQYT4TBGuay0g4" || got.Login != "ada@example.com" || got.Email != "ada@example.com" {
		t.Fatalf("item = %#v", got)
	}
	if strings.Join(got.RoleLabels, ",") != "Super Administrator" {
		t.Fatalf("roles = %#v", got.RoleLabels)
	}
}
