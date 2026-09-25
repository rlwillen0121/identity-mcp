package c1

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/rlwillen0121/identity-mcp/internal/idmcp"
)

func TestTokenFormCacheAndRefresh(t *testing.T) {
	var tokenCalls atomic.Int32
	var sawBasic bool
	var contentType, form string
	c := startFake(t, "cid", "sec", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/oauth/token" {
			tokenCalls.Add(1)
			if r.Method != http.MethodPost {
				t.Errorf("token method %s", r.Method)
			}
			if auth := r.Header.Get("Authorization"); auth != "" {
				sawBasic = true
				t.Errorf("token authorization = %q", auth)
			}
			contentType = r.Header.Get("Content-Type")
			b, _ := io.ReadAll(r.Body)
			form = string(b)
			writeToken(w, "tok", 3600)
			return
		}
		if r.Header.Get("Authorization") != "Bearer tok" {
			t.Errorf("auth = %q", r.Header.Get("Authorization"))
		}
		writeJSON(w, 200, `{"list":[],"nextPageToken":""}`)
	})
	_ = callTool[idmcp.Page[UserItem]](t, c, "list_users", ListUsersInput{Limit: 25})
	if tokenCalls.Load() != 1 {
		t.Fatalf("token calls = %d", tokenCalls.Load())
	}
	if sawBasic {
		t.Fatal("token request used authorization")
	}
	if !strings.HasPrefix(contentType, "application/x-www-form-urlencoded") {
		t.Fatalf("content-type = %q", contentType)
	}
	for _, want := range []string{"grant_type=client_credentials", "client_id=cid", "client_secret=sec"} {
		if !strings.Contains(form, want) {
			t.Errorf("token body missing %q in %q", want, form)
		}
	}
	if strings.Contains(form, `"grant_type"`) {
		t.Fatalf("token body is JSON: %s", form)
	}
	_ = callTool[idmcp.Page[UserItem]](t, c, "list_users", ListUsersInput{Limit: 25})
	if tokenCalls.Load() != 1 {
		t.Fatalf("token refetched within expiry: %d", tokenCalls.Load())
	}
	c.expiry = time.Now().Add(-time.Minute)
	_ = callTool[idmcp.Page[UserItem]](t, c, "list_users", ListUsersInput{Limit: 25})
	if tokenCalls.Load() != 2 {
		t.Fatalf("token calls after expiry = %d", tokenCalls.Load())
	}
}

func TestToolErrorOmitsSecrets(t *testing.T) {
	const secret = "super-c1-secret"
	const access = "super-c1-access-token"
	c := startFake(t, "cid", secret, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/oauth/token" {
			writeToken(w, access, 3600)
			return
		}
		writeJSON(w, 500, `{"err":"super-c1-secret super-c1-access-token"}`)
	})
	res := callToolRaw(t, c, "list_users", ListUsersInput{})
	if !res.IsError {
		t.Fatal("expected error")
	}
	msg := resultText(res)
	if strings.Contains(msg, secret) || strings.Contains(msg, access) {
		t.Fatalf("error leaked secret material: %s", msg)
	}
	if !strings.Contains(msg, "500") {
		t.Fatalf("error = %s", msg)
	}
}

func TestResolveEndpoints(t *testing.T) {
	_, _, err := ResolveEndpoints("abc@tenant.example/read", "http://tenant.example/api/v1", "")
	if err == nil {
		t.Fatal("http base accepted")
	}
	_, _, err = ResolveEndpoints("abc@tenant.example/read", "https://tenant.example/api/v1", "http://tenant.example/auth/v1/token")
	if err == nil {
		t.Fatal("http token url accepted")
	}
	_, _, err = ResolveEndpoints("not-a-client-id", "", "")
	if err == nil {
		t.Fatal("bad client id accepted when deriving")
	}
	_, _, err = ResolveEndpoints("not-a-client-id", "https://override.example/api/v1", "")
	if err == nil {
		t.Fatal("bad client id accepted when token url still needs deriving")
	}
	base, token, err := ResolveEndpoints("not-a-client-id", "https://override.example/api/v1", "https://override.example/auth/v1/token")
	if err != nil {
		t.Fatal(err)
	}
	if base != "https://override.example/api/v1" || token != "https://override.example/auth/v1/token" {
		t.Fatalf("override = %s %s", base, token)
	}
	base, token, err = ResolveEndpoints("rand@acme.c1eu.ai/svc", "", "")
	if err != nil {
		t.Fatal(err)
	}
	if base != "https://acme.c1eu.ai/api/v1" || token != "https://acme.c1eu.ai/auth/v1/token" {
		t.Fatalf("derived = %s %s", base, token)
	}
	base, token, err = ResolveEndpoints("rand@acme.c1eu.ai/svc", "https://override.example/api/v1", "")
	if err != nil {
		t.Fatal(err)
	}
	if base != "https://override.example/api/v1" || token != "https://acme.c1eu.ai/auth/v1/token" {
		t.Fatalf("mixed = %s %s", base, token)
	}
}

func TestHostFromClientIDRejectsSmuggle(t *testing.T) {
	host, err := hostFromClientID("rand@acme.c1eu.ai/svc")
	if err != nil || host != "acme.c1eu.ai" {
		t.Fatalf("normal host=%q err=%v", host, err)
	}
	smuggle := "rand@legit.example%2f@evil.com/svc"
	if _, err := hostFromClientID(smuggle); err == nil {
		t.Fatal("smuggled host accepted")
	}
	if _, _, err := ResolveEndpoints(smuggle, "", ""); err == nil {
		t.Fatal("smuggled client id derived endpoints")
	}
}

func TestPageSizeAndAbsoluteCursor(t *testing.T) {
	var apiHits atomic.Int32
	var lastPath string
	var lastBody map[string]any
	c := startFake(t, "cid", "sec", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/oauth/token" {
			writeToken(w, "tok", 3600)
			return
		}
		apiHits.Add(1)
		lastPath = r.URL.Path
		b, _ := io.ReadAll(r.Body)
		lastBody = nil
		_ = json.Unmarshal(b, &lastBody)
		if r.URL.Path == "/api/v1/search/tasks" {
			writeJSON(w, 200, `{"list":[{"task":{"id":"t1","numericId":42,"displayName":"Review Ada","state":"TASK_STATE_OPEN","createdAt":"2024-01-02T03:04:05Z","userId":"u1","type":{"grant":{"outcome":"APPROVED","appId":"app1"}}}}],"nextPageToken":"tn"}`)
			return
		}
		writeJSON(w, 200, `{"list":[],"nextPageToken":""}`)
	})

	before := apiHits.Load()
	res := callToolRaw(t, c, "list_users", ListUsersInput{PageToken: "https://evil.example/next"})
	if !res.IsError {
		t.Fatal("absolute page_token accepted")
	}
	if apiHits.Load() != before {
		t.Fatal("absolute page_token was fetched")
	}
	msg := resultText(res)
	if !strings.Contains(msg, "opaque") && !strings.Contains(msg, "URL") {
		t.Fatalf("cursor error = %s", msg)
	}

	_ = callTool[idmcp.Page[UserItem]](t, c, "list_users", ListUsersInput{Limit: 500})
	if lastPath != "/api/v1/search/users" {
		t.Fatalf("path = %s", lastPath)
	}
	if got := numberField(lastBody, "pageSize"); got != 100 {
		t.Fatalf("pageSize = %v", lastBody["pageSize"])
	}
	_ = callTool[idmcp.Page[UserItem]](t, c, "list_users", ListUsersInput{Limit: 5})
	if got := numberField(lastBody, "pageSize"); got != 10 {
		t.Fatalf("small pageSize = %v", lastBody["pageSize"])
	}
	out := callTool[idmcp.Page[TaskItem]](t, c, "list_tasks", ListTasksInput{Limit: 100, UserID: "u1", State: "TASK_STATE_OPEN"})
	if lastPath != "/api/v1/search/tasks" {
		t.Fatalf("task path = %s", lastPath)
	}
	if got := numberField(lastBody, "pageSize"); got != 10 {
		t.Fatalf("task pageSize = %v", lastBody["pageSize"])
	}
	if _, ok := lastBody["expandMask"]; ok {
		t.Fatalf("list_tasks sent expandMask: %#v", lastBody["expandMask"])
	}
	if len(out.Items) != 1 || out.Items[0].Type != "grant" || out.Items[0].Outcome != "APPROVED" || out.Items[0].AppID != "app1" || out.Items[0].NumericID != "42" || out.Next != "tn" {
		t.Fatalf("task = %#v", out)
	}
}

func TestListUsersMapsUser(t *testing.T) {
	var body map[string]any
	c := startFake(t, "cid", "sec", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/oauth/token" {
			writeToken(w, "tok", 3600)
			return
		}
		if r.URL.Path != "/api/v1/search/users" || r.Method != http.MethodPost {
			t.Errorf("request %s %s", r.Method, r.URL.Path)
		}
		b, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(b, &body)
		writeJSON(w, 200, `{"list":[{"user":{"id":"u1","displayName":"Ada","email":"ada@x","username":"ada","status":"ENABLED","type":"HUMAN","department":"Eng","jobTitle":"Dev"}}],"nextPageToken":"npt-1"}`)
	})
	out := callTool[idmcp.Page[UserItem]](t, c, "list_users", ListUsersInput{
		Query: "ada", Email: "ada@x", UserStatus: "ENABLED", RoleID: "r1", Limit: 25,
	})
	if body["query"] != "ada" || body["email"] != "ada@x" {
		t.Fatalf("body = %#v", body)
	}
	if statuses, _ := body["userStatuses"].([]any); len(statuses) != 1 || statuses[0] != "ENABLED" {
		t.Fatalf("userStatuses = %#v", body["userStatuses"])
	}
	if roles, _ := body["roleIds"].([]any); len(roles) != 1 || roles[0] != "r1" {
		t.Fatalf("roleIds = %#v", body["roleIds"])
	}
	if len(out.Items) != 1 || out.Next != "npt-1" || !out.Truncated {
		t.Fatalf("page = %#v", out)
	}
	u := out.Items[0]
	if u.ID != "u1" || u.DisplayName != "Ada" || u.Email != "ada@x" || u.Username != "ada" || u.Status != "ENABLED" || u.Type != "HUMAN" || u.Department != "Eng" || u.JobTitle != "Dev" {
		t.Fatalf("user = %#v", u)
	}
}

func TestGetUserRoleNamesBestEffort(t *testing.T) {
	c := startFake(t, "cid", "sec", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/oauth/token" {
			writeToken(w, "tok", 3600)
			return
		}
		if r.Method == http.MethodGet && r.URL.Path == "/api/v1/users/u1" {
			writeJSON(w, 200, `{"userView":{"user":{"id":"u1","displayName":"Ada","email":"ada@x","roleIds":["r1","r2"]}}}`)
			return
		}
		if r.Method == http.MethodPost && r.URL.Path == "/api/v1/search/users" {
			b, _ := io.ReadAll(r.Body)
			var body map[string]any
			_ = json.Unmarshal(b, &body)
			mask, _ := body["expandMask"].(map[string]any)
			paths, _ := mask["paths"].([]any)
			if len(paths) != 1 || paths[0] != "role_ids" {
				t.Errorf("expand = %#v", body["expandMask"])
			}
			writeJSON(w, 200, `{"list":[{"user":{"id":"u1"}}],"expanded":[{"id":"r2","displayName":"Beta"},{"id":"r1","displayName":"Alpha"}]}`)
			return
		}
		t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
		writeJSON(w, 404, `{}`)
	})
	out := callTool[UserDetail](t, c, "get_user", GetUserInput{UserID: "u1"})
	if out.ID != "u1" || out.DisplayName != "Ada" || len(out.RoleIDs) != 2 || out.RoleIDs[0] != "r1" {
		t.Fatalf("user = %#v", out)
	}
	if len(out.RoleNames) != 2 || out.RoleNames[0] != "Alpha" || out.RoleNames[1] != "Beta" {
		t.Fatalf("role names = %#v", out.RoleNames)
	}

	c2 := startFake(t, "cid", "super-c1-secret", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/oauth/token" {
			writeToken(w, "super-c1-access-token", 3600)
			return
		}
		if r.Method == http.MethodGet {
			writeJSON(w, 200, `{"userView":{"user":{"id":"u1","displayName":"Ada","roleIds":["r1"]}}}`)
			return
		}
		writeJSON(w, 500, `{"err":"super-c1-secret super-c1-access-token"}`)
	})
	still := callTool[UserDetail](t, c2, "get_user", GetUserInput{UserID: "u1"})
	if still.ID != "u1" || len(still.RoleIDs) != 1 || len(still.RoleNames) != 0 {
		t.Fatalf("best effort = %#v", still)
	}
	raw, _ := json.Marshal(still)
	if strings.Contains(string(raw), "super-c1-secret") || strings.Contains(string(raw), "super-c1-access-token") {
		t.Fatalf("user leaked secret: %s", raw)
	}
}

func TestListUncorrelatedAccounts(t *testing.T) {
	var body map[string]any
	c := startFake(t, "cid", "sec", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/oauth/token" {
			writeToken(w, "tok", 3600)
			return
		}
		b, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(b, &body)
		writeJSON(w, 200, `{"list":[{"appUser":{"appId":"app1","id":"au1","displayName":"Orphan","email":"o@x","appUserType":"APP_USER_TYPE_USER","status":{"status":"STATUS_ENABLED"},"identityUserId":""}}],"nextPageToken":""}`)
	})
	out := callTool[idmcp.Page[AccountItem]](t, c, "list_uncorrelated_accounts", ListUncorrelatedAccountsInput{AppID: "app1", Query: "orphan"})
	if body["withoutResponsibleParty"] != true {
		t.Fatalf("withoutResponsibleParty = %#v", body["withoutResponsibleParty"])
	}
	if body["appId"] != "app1" || body["query"] != "orphan" {
		t.Fatalf("body = %#v", body)
	}
	if len(out.Items) != 1 || out.Items[0].ID != "au1" || out.Items[0].Status != "STATUS_ENABLED" || out.Items[0].AppID != "app1" {
		t.Fatalf("items = %#v", out.Items)
	}
}

func TestListAppUsersTypeAlias(t *testing.T) {
	var body map[string]any
	c := startFake(t, "cid", "sec", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/oauth/token" {
			writeToken(w, "tok", 3600)
			return
		}
		b, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(b, &body)
		writeJSON(w, 200, `{"list":[],"nextPageToken":""}`)
	})
	_ = callTool[idmcp.Page[AccountItem]](t, c, "list_app_users", ListAppUsersInput{AppID: "app1", Type: "SERVICE_ACCOUNT"})
	types, _ := body["appUserTypes"].([]any)
	if len(types) != 1 || types[0] != "APP_USER_TYPE_SERVICE_ACCOUNT" {
		t.Fatalf("appUserTypes = %#v", body["appUserTypes"])
	}
}

func TestFindStaleAccounts(t *testing.T) {
	recent := time.Now().UTC().Format(time.RFC3339)
	old := "2000-01-01T00:00:00Z"
	page := `{"list":[` +
		appUserJSON("d1", "STATUS_DISABLED", recent) + `,` +
		appUserJSON("x1", "STATUS_DELETED", recent) + `,` +
		appUserJSON("n1", "STATUS_ENABLED", "") + `,` +
		appUserJSON("o1", "STATUS_ENABLED", old) + `,` +
		appUserJSON("f1", "STATUS_ENABLED", recent) +
		`],"nextPageToken":""}`
	var pageSize float64
	var paths []any
	c := startFake(t, "cid", "sec", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/oauth/token" {
			writeToken(w, "tok", 3600)
			return
		}
		b, _ := io.ReadAll(r.Body)
		var body map[string]any
		_ = json.Unmarshal(b, &body)
		pageSize, _ = body["pageSize"].(float64)
		mask, _ := body["expandMask"].(map[string]any)
		paths, _ = mask["paths"].([]any)
		writeJSON(w, 200, page)
	})
	out := callTool[StalePage](t, c, "find_stale_accounts", FindStaleAccountsInput{})
	if pageSize != 50 || len(paths) != 1 || paths[0] != "last_usage" {
		t.Fatalf("pageSize=%v paths=%v", pageSize, paths)
	}
	got := map[string]StaleAccount{}
	for _, item := range out.Items {
		got[item.ID] = item
	}
	if !hasReason(got["d1"].Reasons, "STATUS_DISABLED") || hasReason(got["d1"].Reasons, "no_usage") {
		t.Fatalf("disabled = %#v", got["d1"])
	}
	if !hasReason(got["x1"].Reasons, "STATUS_DELETED") {
		t.Fatalf("deleted = %#v", got["x1"])
	}
	if !hasReason(got["n1"].Reasons, "no_usage") || got["n1"].LastUsage != "" {
		t.Fatalf("missing = %#v", got["n1"])
	}
	if !hasReason(got["o1"].Reasons, "usage_older_than_90_days") || got["o1"].LastUsage != old {
		t.Fatalf("old = %#v", got["o1"])
	}
	if _, ok := got["f1"]; ok {
		t.Fatalf("fresh account flagged: %#v", got["f1"])
	}
	if out.Truncated || out.Next != "" {
		t.Fatalf("page = %#v", out)
	}

	var calls atomic.Int32
	c2 := startFake(t, "cid", "sec", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/oauth/token" {
			writeToken(w, "tok", 3600)
			return
		}
		n := calls.Add(1)
		writeJSON(w, 200, stalePage(50, fmt.Sprintf("p%d", n)))
	})
	capped := callTool[StalePage](t, c2, "find_stale_accounts", FindStaleAccountsInput{Limit: 500})
	if calls.Load() != 10 || capped.Scanned != 500 || len(capped.Items) != 500 {
		t.Fatalf("calls=%d scanned=%d items=%d", calls.Load(), capped.Scanned, len(capped.Items))
	}

	c3 := startFake(t, "cid", "sec", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/oauth/token" {
			writeToken(w, "tok", 3600)
			return
		}
		writeJSON(w, 200, `{"list":[`+appUserJSON("a", "STATUS_DISABLED", "")+`,`+appUserJSON("b", "STATUS_DELETED", "")+`,`+appUserJSON("c", "STATUS_ENABLED", "")+`],"nextPageToken":""}`)
	})
	left := callTool[StalePage](t, c3, "find_stale_accounts", FindStaleAccountsInput{Limit: 2})
	if !left.Truncated || left.Next != "" || len(left.Items) != 2 || left.Scanned != 3 {
		t.Fatalf("leftover = %#v", left)
	}
}

func TestFindStaleAccountsScanResume(t *testing.T) {
	var emptyCalls atomic.Int32
	c := startFake(t, "cid", "sec", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/oauth/token" {
			writeToken(w, "tok", 3600)
			return
		}
		if emptyCalls.Add(1) > 1 {
			t.Errorf("fetched past empty page")
			writeJSON(w, 200, `{"list":[],"nextPageToken":""}`)
			return
		}
		writeJSON(w, 200, `{"list":[],"nextPageToken":"more"}`)
	})
	empty := callTool[StalePage](t, c, "find_stale_accounts", FindStaleAccountsInput{})
	if empty.Next != "more" || !empty.Truncated || empty.Scanned != 0 || len(empty.Items) != 0 {
		t.Fatalf("empty page = %#v", empty)
	}
	if emptyCalls.Load() != 1 {
		t.Fatalf("empty page calls = %d", emptyCalls.Load())
	}

	recent := time.Now().UTC().Format(time.RFC3339)
	var calls atomic.Int32
	c2 := startFake(t, "cid", "sec", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/oauth/token" {
			writeToken(w, "tok", 3600)
			return
		}
		n := calls.Add(1)
		if n > 10 {
			t.Errorf("requested page %d", n)
			writeJSON(w, 200, `{"list":[],"nextPageToken":""}`)
			return
		}
		next := fmt.Sprintf("p%d", n)
		if n == 10 {
			next = "further"
		}
		writeJSON(w, 200, freshPage(50, recent, next))
	})
	capped := callTool[StalePage](t, c2, "find_stale_accounts", FindStaleAccountsInput{Limit: 500})
	if calls.Load() != 10 || capped.Scanned != 500 || len(capped.Items) != 0 || !capped.Truncated || capped.Next != "further" {
		t.Fatalf("calls=%d page=%#v", calls.Load(), capped)
	}
}

func TestGetUserAccessCap(t *testing.T) {
	var calls []string
	var bodies []map[string]any
	c := startFake(t, "cid", "sec", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/oauth/token" {
			writeToken(w, "tok", 3600)
			return
		}
		calls = append(calls, r.Method+" "+r.URL.Path)
		if r.Method == http.MethodPost {
			b, _ := io.ReadAll(r.Body)
			var body map[string]any
			_ = json.Unmarshal(b, &body)
			bodies = append(bodies, body)
		}
		switch {
		case r.URL.Path == "/api/v1/users/u1":
			writeJSON(w, 200, `{"userView":{"user":{"id":"u1","displayName":"Ada","email":"ada@x","username":"ada","status":"ENABLED","type":"HUMAN","department":"Eng","jobTitle":"Dev","roleIds":["r1"]}}}`)
		case r.URL.Path == "/api/v1/search/app_users":
			writeJSON(w, 200, accountPage(51))
		case r.URL.Path == "/api/v1/search/grants":
			writeJSON(w, 200, grantPage(51))
		default:
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
			writeJSON(w, 404, `{}`)
		}
	})
	out := callTool[UserAccess](t, c, "get_user_access", GetUserAccessInput{UserID: "u1"})
	wantCalls := []string{
		"GET /api/v1/users/u1",
		"POST /api/v1/search/app_users",
		"POST /api/v1/search/grants",
	}
	if strings.Join(calls, ",") != strings.Join(wantCalls, ",") {
		t.Fatalf("calls = %#v", calls)
	}
	if len(bodies) != 2 {
		t.Fatalf("bodies = %d", len(bodies))
	}
	if numberField(bodies[0], "pageSize") != 50 || numberField(bodies[1], "pageSize") != 50 {
		t.Fatalf("page sizes = %#v %#v", bodies[0]["pageSize"], bodies[1]["pageSize"])
	}
	ids, _ := bodies[0]["userIds"].([]any)
	if len(ids) != 1 || ids[0] != "u1" {
		t.Fatalf("userIds = %#v", bodies[0]["userIds"])
	}
	mask, _ := bodies[0]["expandMask"].(map[string]any)
	paths, _ := mask["paths"].([]any)
	if len(paths) != 1 || paths[0] != "last_usage" {
		t.Fatalf("expand = %#v", bodies[0]["expandMask"])
	}
	if bodies[1]["userId"] != "u1" {
		t.Fatalf("userId = %#v", bodies[1]["userId"])
	}
	if _, ok := bodies[1]["expandMask"]; ok {
		t.Fatal("grants search expanded")
	}
	if out.ID != "u1" || out.Email != "ada@x" || len(out.RoleIDs) != 1 {
		t.Fatalf("user = %#v", out)
	}
	if len(out.Accounts) != 50 || !out.TruncatedAccounts || len(out.Grants) != 50 || !out.TruncatedGrants {
		t.Fatalf("caps accounts=%d grants=%d truncA=%v truncG=%v", len(out.Accounts), len(out.Grants), out.TruncatedAccounts, out.TruncatedGrants)
	}
	if out.Accounts[0].AppID != "app1" || out.Accounts[0].ID != "au0" || out.Accounts[0].Status != "STATUS_ENABLED" || out.Accounts[0].Type != "APP_USER_TYPE_USER" || out.Accounts[0].IdentityUserID != "u1" || out.Accounts[0].LastUsage != "2024-01-02T03:04:05Z" {
		t.Fatalf("account = %#v", out.Accounts[0])
	}
	if out.Grants[0].AppID != "app1" || out.Grants[0].EntitlementID != "ent0" || out.Grants[0].DisplayName != "From Entitlement" {
		t.Fatalf("grant = %#v", out.Grants[0])
	}
	if out.Grants[1].DisplayName != "From Entitlement Object" {
		t.Fatalf("grant fallback = %#v", out.Grants[1])
	}
}

func TestListShapes(t *testing.T) {
	c := startFake(t, "cid", "sec", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/oauth/token" {
			writeToken(w, "tok", 3600)
			return
		}
		switch r.URL.Path {
		case "/api/v1/search/apps":
			writeJSON(w, 200, `{"list":[{"app":{"id":"a1","displayName":"Okta","description":"dir","isDirectory":true}},{"id":"a2","displayName":"Flat","description":"","isDirectory":false}],"nextPageToken":"an"}`)
		case "/api/v1/search/entitlements":
			writeJSON(w, 200, `{"list":[{"appEntitlement":{"id":"e1","appId":"a1","displayName":"Admin","alias":"admin"}}],"nextPageToken":""}`)
		case "/api/v1/access_reviews":
			if r.URL.Query().Get("page_size") == "" {
				t.Errorf("missing page_size")
			}
			writeJSON(w, 200, `{"list":[{"accessReview":{"id":"c1","displayName":"Q1","state":"OPEN","createdAt":"2024-01-02T03:04:05Z"}},{"id":"c2","displayName":"Flat","state":"CLOSED","createdAt":"2024-02-02T03:04:05Z"}],"nextPageToken":"rn"}`)
		default:
			t.Errorf("unexpected %s", r.URL.Path)
			writeJSON(w, 404, `{}`)
		}
	})
	apps := callTool[idmcp.Page[AppItem]](t, c, "list_apps", ListAppsInput{Query: "ok"})
	if len(apps.Items) != 2 || !apps.Items[0].IsDirectory || apps.Items[0].DisplayName != "Okta" || apps.Items[1].IsDirectory || apps.Next != "an" {
		t.Fatalf("apps = %#v", apps)
	}
	ents := callTool[idmcp.Page[EntitlementItem]](t, c, "list_entitlements", ListEntitlementsInput{AppID: "a1"})
	if len(ents.Items) != 1 || ents.Items[0].ID != "e1" || ents.Items[0].Alias != "admin" || ents.Items[0].AppID != "a1" {
		t.Fatalf("ents = %#v", ents)
	}
	reviews := callTool[idmcp.Page[AccessReviewItem]](t, c, "list_access_reviews", ListAccessReviewsInput{Limit: 25})
	if len(reviews.Items) != 2 || reviews.Items[0].State != "OPEN" || reviews.Items[1].DisplayName != "Flat" || reviews.Next != "rn" {
		t.Fatalf("reviews = %#v", reviews)
	}
}

func TestNewServerTools(t *testing.T) {
	c := NewClient(Config{ClientID: "c", ClientSecret: "s", BaseURL: "https://example.invalid/api/v1", TokenURL: "https://example.invalid/auth/v1/token"})
	session := connect(t, NewServer(c))
	res, err := session.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"list_users", "get_user", "get_user_access", "list_apps", "list_app_users",
		"list_entitlements", "list_uncorrelated_accounts", "find_stale_accounts",
		"list_access_reviews", "list_tasks",
	}
	got := map[string]bool{}
	for _, tool := range res.Tools {
		got[tool.Name] = true
		ann := tool.Annotations
		if ann == nil || !ann.ReadOnlyHint || !ann.IdempotentHint || ann.OpenWorldHint == nil || !*ann.OpenWorldHint {
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

func startFake(t *testing.T, clientID, secret string, h http.HandlerFunc) *Client {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return NewClient(Config{
		ClientID:     clientID,
		ClientSecret: secret,
		BaseURL:      srv.URL,
		TokenURL:     srv.URL + "/oauth/token",
		HTTP:         srv.Client(),
	})
}

func writeToken(w http.ResponseWriter, access string, expires int) {
	writeJSON(w, 200, fmt.Sprintf(`{"access_token":%q,"expires_in":%d,"token_type":"Bearer"}`, access, expires))
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
		t.Fatalf("%s tool error: %s", name, resultText(res))
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

func resultText(res *mcp.CallToolResult) string {
	b, _ := json.Marshal(res)
	return string(b)
}

func numberField(m map[string]any, k string) int {
	switch n := m[k].(type) {
	case float64:
		return int(n)
	case json.Number:
		i, _ := n.Int64()
		return int(i)
	default:
		return -1
	}
}

func hasReason(reasons []string, want string) bool {
	for _, r := range reasons {
		if r == want {
			return true
		}
	}
	return false
}

func appUserJSON(id, status, lastUsed string) string {
	expanded := ""
	if lastUsed != "" {
		expanded = fmt.Sprintf(`,"expanded":{"lastUsedAt":%q}`, lastUsed)
	}
	return fmt.Sprintf(`{"appUser":{"id":%q,"appId":"app","displayName":%q,"status":{"status":%q}}%s}`, id, id, status, expanded)
}

func freshPage(n int, lastUsed, next string) string {
	var b strings.Builder
	b.WriteString(`{"list":[`)
	for i := 0; i < n; i++ {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(appUserJSON(fmt.Sprintf("f%d", i), "STATUS_ENABLED", lastUsed))
	}
	b.WriteString(`],"nextPageToken":`)
	nb, _ := json.Marshal(next)
	b.Write(nb)
	b.WriteString(`}`)
	return b.String()
}

func stalePage(n int, next string) string {
	var b strings.Builder
	b.WriteString(`{"list":[`)
	for i := 0; i < n; i++ {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(appUserJSON(fmt.Sprintf("s%d", i), "STATUS_ENABLED", ""))
	}
	b.WriteString(`],"nextPageToken":`)
	nb, _ := json.Marshal(next)
	b.Write(nb)
	b.WriteString(`}`)
	return b.String()
}

func accountPage(n int) string {
	var b strings.Builder
	b.WriteString(`{"list":[`)
	for i := 0; i < n; i++ {
		if i > 0 {
			b.WriteByte(',')
		}
		fmt.Fprintf(&b, `{"appUser":{"appId":"app1","id":"au%d","displayName":"Ada","email":"ada@x","appUserType":"APP_USER_TYPE_USER","status":{"status":"STATUS_ENABLED"},"identityUserId":"u1"},"expanded":{"lastUsedAt":"2024-01-02T03:04:05Z"}}`, i)
	}
	b.WriteString(`],"nextPageToken":"more-accounts"}`)
	return b.String()
}

func grantPage(n int) string {
	var b strings.Builder
	b.WriteString(`{"list":[`)
	for i := 0; i < n; i++ {
		if i > 0 {
			b.WriteByte(',')
		}
		name := ""
		switch i {
		case 0:
			name = `,"appEntitlement":{"displayName":"From Entitlement"},"entitlement":{"displayName":"ignored"}`
		case 1:
			name = `,"entitlement":{"displayName":"From Entitlement Object"}`
		}
		fmt.Fprintf(&b, `{"appEntitlementUserBinding":{"appId":"app1","appEntitlementId":"ent%d"}%s}`, i, name)
	}
	b.WriteString(`],"nextPageToken":"more-grants"}`)
	return b.String()
}
