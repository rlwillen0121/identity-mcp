package idmcp

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestGetJSON(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "SSWS test" {
			t.Errorf("auth = %q", r.Header.Get("Authorization"))
		}
		w.Header().Set("Link", `<https://example/next>; rel="next"`)
		w.Write([]byte(`{"ok":true}`))
	}))
	t.Cleanup(s.Close)

	h := make(http.Header)
	h.Set("Authorization", "SSWS test")
	c := NewClient(s.URL, h)
	var dest map[string]any
	hdr, err := c.GetJSON(context.Background(), "/x", nil, &dest)
	if err != nil {
		t.Fatal(err)
	}
	if dest["ok"] != true {
		t.Fatalf("dest = %#v", dest)
	}
	if LinkHeader(hdr, "next") != "https://example/next" {
		t.Fatalf("link = %q", LinkHeader(hdr, "next"))
	}
}

func TestClampLimit(t *testing.T) {
	if ClampLimit(0) != DefaultLimit {
		t.Fatal(ClampLimit(0))
	}
	if ClampLimit(9999) != MaxLimit {
		t.Fatal(ClampLimit(9999))
	}
}

func TestGetRejectsAbsoluteURL(t *testing.T) {
	hit := false
	s := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		hit = true
	}))
	t.Cleanup(s.Close)
	h := make(http.Header)
	h.Set("Authorization", "SSWS secret")
	c := NewClient(s.URL, h)
	_, _, err := c.Get(context.Background(), "http://127.0.0.1/steal", nil)
	if err == nil {
		t.Fatal("expected error")
	}
	if hit {
		t.Fatal("must not fetch attacker URL")
	}
}

func TestOpaqueCursorExtractsQuery(t *testing.T) {
	got, err := OpaqueCursor("https://evil.example/x?after=00uNEXT", "after")
	if err != nil || got != "00uNEXT" {
		t.Fatalf("got %q err %v", got, err)
	}
	if _, err := OpaqueCursor("https://evil.example/x", "after"); err == nil {
		t.Fatal("expected error")
	}
}

func TestLinkHeaderSeparateLines(t *testing.T) {
	hdr := make(http.Header)
	hdr.Add("Link", `<https://example.okta.com/api/v1/users?after=self&limit=1>; rel="self"`)
	hdr.Add("Link", `<https://example.okta.com/api/v1/users?after=00uNEXT&limit=1>; rel="next"`)
	if got := LinkHeader(hdr, "next"); got != "https://example.okta.com/api/v1/users?after=00uNEXT&limit=1" {
		t.Fatalf("next = %q", got)
	}
	if got := LinkHeader(hdr, "self"); !strings.Contains(got, "after=self") {
		t.Fatalf("self = %q", got)
	}
}

func TestHTTPErrorStatus(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, `{"error":": 400 "}`, 403)
	}))
	t.Cleanup(s.Close)
	c := NewClient(s.URL, nil)
	_, _, err := c.Get(context.Background(), "/x", nil)
	if StatusOf(err) != 403 {
		t.Fatalf("status = %d err=%v", StatusOf(err), err)
	}
}

func TestPostJSONSuccessAuth(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method = %s", r.Method)
		}
		if r.URL.Path != "/search" {
			t.Errorf("path = %s", r.URL.Path)
		}
		if r.Header.Get("Authorization") != "Bearer tok" {
			t.Errorf("auth = %q", r.Header.Get("Authorization"))
		}
		if r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("content-type = %q", r.Header.Get("Content-Type"))
		}
		w.Write([]byte(`{"ok":true}`))
	}))
	t.Cleanup(s.Close)

	h := make(http.Header)
	h.Set("Authorization", "Bearer tok")
	c := NewClient(s.URL, h)
	var dest map[string]any
	_, err := c.PostJSON(context.Background(), "/search", map[string]any{"q": "ada"}, &dest)
	if err != nil {
		t.Fatal(err)
	}
	if dest["ok"] != true {
		t.Fatalf("dest = %#v", dest)
	}
}

func TestPostJSONRejectsAbsoluteURL(t *testing.T) {
	hit := false
	s := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		hit = true
	}))
	t.Cleanup(s.Close)
	c := NewClient(s.URL, nil)
	_, err := c.PostJSON(context.Background(), "https://127.0.0.1/steal", map[string]any{"q": "x"}, nil)
	if err == nil {
		t.Fatal("expected error")
	}
	if hit {
		t.Fatal("must not fetch attacker URL")
	}
}

func TestHTTPErrorRetryAfter(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Retry-After", "2")
		http.Error(w, `rate limited`, http.StatusTooManyRequests)
	}))
	t.Cleanup(s.Close)
	c := NewClient(s.URL, nil)
	_, _, err := c.Get(context.Background(), "/x", nil)
	if err == nil {
		t.Fatal("expected error")
	}
	var he *HTTPError
	if !errors.As(err, &he) {
		t.Fatalf("err = %v", err)
	}
	if he.Status != 429 || he.RetryAfter != "2" {
		t.Fatalf("status=%d retry=%q err=%v", he.Status, he.RetryAfter, err)
	}
	if !strings.Contains(err.Error(), "retry after 2") {
		t.Fatalf("error = %q", err)
	}
}

func TestParseIntCursor(t *testing.T) {
	tests := []struct {
		in      string
		want    int
		wantErr bool
	}{
		{"", 0, false},
		{"  ", 0, false},
		{"3", 3, false},
		{"0", 0, false},
		{"-1", 0, true},
		{"abc", 0, true},
		{"https://evil.example/x", 0, true},
	}
	for _, tt := range tests {
		got, err := ParseIntCursor(tt.in)
		if tt.wantErr {
			if err == nil {
				t.Errorf("ParseIntCursor(%q) err=nil", tt.in)
			}
			continue
		}
		if err != nil || got != tt.want {
			t.Errorf("ParseIntCursor(%q) = %d, %v want %d", tt.in, got, err, tt.want)
		}
	}
}

func TestNextPage(t *testing.T) {
	tests := []struct {
		page, pages int
		want        string
	}{
		{1, 3, "2"},
		{3, 3, ""},
		{1, 0, ""},
		{2, 2, ""},
		{0, 2, "1"},
	}
	for _, tt := range tests {
		if got := NextPage(tt.page, tt.pages); got != tt.want {
			t.Errorf("NextPage(%d,%d)=%q want %q", tt.page, tt.pages, got, tt.want)
		}
	}
}

func TestNextOffset(t *testing.T) {
	tests := []struct {
		offset, n, limit int
		want             string
	}{
		{0, 50, 50, "50"},
		{50, 50, 50, "100"},
		{0, 49, 50, ""},
		{0, 50, 0, ""},
		{0, 0, 50, ""},
	}
	for _, tt := range tests {
		if got := NextOffset(tt.offset, tt.n, tt.limit); got != tt.want {
			t.Errorf("NextOffset(%d,%d,%d)=%q want %q", tt.offset, tt.n, tt.limit, got, tt.want)
		}
	}
}

func TestPostFormDoesNotFollowRedirect(t *testing.T) {
	const secret = "super-secret-value"
	hits := 0
	b := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits++
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(b.Close)
	a := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		w.Header().Set("Location", b.URL+"/token")
		w.WriteHeader(http.StatusTemporaryRedirect)
		_, _ = io.WriteString(w, "echo "+secret)
	}))
	t.Cleanup(a.Close)

	c := NewClient("", nil)
	form := url.Values{}
	form.Set("client_secret", secret)
	_, err := c.PostForm(context.Background(), a.URL+"/oauth/token", form)
	if err == nil {
		t.Fatal("expected error")
	}
	if hits != 0 {
		t.Fatalf("redirect target hits = %d", hits)
	}
	if strings.Contains(err.Error(), secret) {
		t.Fatalf("error contains secret: %v", err)
	}
}

func TestRequireHTTPSRejectsUserinfo(t *testing.T) {
	if err := RequireHTTPS("X", "https://user:secret@host.example/v1"); err == nil {
		t.Fatal("userinfo accepted")
	}
	if err := RequireHTTPS("X", "https://host.example/v1"); err != nil {
		t.Fatal(err)
	}
}

func TestPostJSONSearchOnly(t *testing.T) {
	hits := 0
	var gotPath, gotQuery string
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		gotPath = r.URL.Path
		gotQuery = r.URL.RawQuery
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	t.Cleanup(s.Close)
	c := NewClient(s.URL, nil)
	if _, err := c.PostJSON(context.Background(), "/identities", map[string]any{"id": "x"}, nil); err == nil {
		t.Fatal("expected POST /identities to be refused")
	}
	if hits != 0 {
		t.Fatal("POST /identities must not reach the server")
	}
	var dest map[string]any
	if _, err := c.PostJSON(context.Background(), "/search?limit=1", map[string]any{"q": "ada"}, &dest); err != nil {
		t.Fatal(err)
	}
	if hits != 1 || gotPath != "/search" || gotQuery != "limit=1" {
		t.Fatalf("hits=%d path=%s query=%s", hits, gotPath, gotQuery)
	}
	if dest["ok"] != true {
		t.Fatalf("dest = %#v", dest)
	}
}

func TestHTTPErrorRedactsBearerToken(t *testing.T) {
	const token = "sek/ret+tok"
	authz := "Bearer " + token
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "echo "+authz+" "+token+" "+url.QueryEscape(token)+" "+url.QueryEscape(authz), http.StatusInternalServerError)
	}))
	t.Cleanup(s.Close)
	c := NewClient(s.URL, nil)
	c.Auth = func() string { return authz }
	_, _, err := c.Get(context.Background(), "/x", nil)
	if err == nil {
		t.Fatal("expected error")
	}
	msg := err.Error()
	if !strings.Contains(msg, "500") {
		t.Fatalf("error = %s", msg)
	}
	for _, leak := range []string{authz, token, url.QueryEscape(token), url.QueryEscape(authz)} {
		if strings.Contains(msg, leak) {
			t.Fatalf("error contains %q: %s", leak, msg)
		}
	}
}

func TestClampSize(t *testing.T) {
	tests := []struct {
		n, max, want int
	}{
		{0, 100, DefaultLimit},
		{-1, 100, DefaultLimit},
		{999, 100, 100},
		{5, 100, 5},
		{0, 10, 10},
		{300, 300, MaxLimit},
		{0, 300, DefaultLimit},
	}
	for _, tt := range tests {
		if got := ClampSize(tt.n, tt.max); got != tt.want {
			t.Errorf("ClampSize(%d,%d)=%d want %d", tt.n, tt.max, got, tt.want)
		}
	}
}

func TestGetAndPostJSONDoNotFollowRedirects(t *testing.T) {
	hits := 0
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(target.Close)

	redir := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+"/leaked", http.StatusFound)
	}))
	t.Cleanup(redir.Close)

	h := make(http.Header)
	h.Set("Authorization", "Bearer super-secret-token")
	c := NewClient(redir.URL, h)

	if _, _, err := c.Get(context.Background(), "/users", nil); err == nil {
		t.Fatal("expected error on 302 redirect in Get")
	}
	if _, err := c.PostJSON(context.Background(), "/search", map[string]any{"q": "x"}, nil); err == nil {
		t.Fatal("expected error on 302 redirect in PostJSON")
	}
	if hits != 0 {
		t.Fatalf("redirect target received %d requests; expected 0", hits)
	}
}

func TestGetRejectsDotSegmentsAndRequireRejectsTraversal(t *testing.T) {
	hit := false
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hit = true
	}))
	t.Cleanup(s.Close)

	c := NewClient(s.URL, nil)
	for _, badPath := range []string{
		"/api/v1/users/../groups",
		"/api/v1/users/./groups",
		"/api/v1/users/%2e%2e/groups",
		"//evil.example/users",
	} {
		if _, _, err := c.Get(context.Background(), badPath, nil); err == nil {
			t.Fatalf("expected Get(%q) to fail", badPath)
		}
	}
	if hit {
		t.Fatal("dot-segment path must not reach server")
	}

	for _, badID := range []string{"", "   ", ".", "..", "user\x00id", "user\nid"} {
		if err := Require("user_id", badID); err == nil {
			t.Fatalf("expected Require(%q) to fail", badID)
		}
	}
}

func TestPostForm400RedactsClientSecret(t *testing.T) {
	const secret = "my-ultra-secret-client-credential"
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "invalid client_secret: "+secret+" or "+url.QueryEscape(secret), http.StatusBadRequest)
	}))
	t.Cleanup(s.Close)

	c := NewClient("", nil)
	form := url.Values{}
	form.Set("client_secret", secret)
	_, err := c.PostForm(context.Background(), s.URL+"/oauth/token", form)
	if err == nil {
		t.Fatal("expected error")
	}
	if strings.Contains(err.Error(), secret) || strings.Contains(err.Error(), url.QueryEscape(secret)) {
		t.Fatalf("PostForm error leaked client_secret: %v", err)
	}
}

func TestDoWriteJSONAndWritesEnabled(t *testing.T) {
	if WritesEnabled([]string{"--other"}) {
		t.Fatal("expected WritesEnabled false by default")
	}
	if !WritesEnabled([]string{"--enable-writes"}) {
		t.Fatal("expected WritesEnabled true with --enable-writes")
	}
	ann := Write("Test write", true, false)
	if ann.ReadOnlyHint || !ann.IdempotentHint || ann.DestructiveHint == nil || *ann.DestructiveHint {
		t.Fatalf("unexpected Write annotations: %+v", ann)
	}

	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPut && r.URL.Path == "/api/v1/groups/g1/users/u1" {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		http.Error(w, "bad request", http.StatusBadRequest)
	}))
	t.Cleanup(s.Close)

	c := NewClient(s.URL, nil)
	if _, err := c.DoWriteJSON(context.Background(), http.MethodPut, "/api/v1/groups/g1/users/u1", nil, nil, nil); err != nil {
		t.Fatalf("DoWriteJSON PUT 204 failed: %v", err)
	}
	if _, err := c.DoWriteJSON(context.Background(), http.MethodPut, "https://evil.example/x", nil, nil, nil); err == nil {
		t.Fatal("expected DoWriteJSON to reject absolute URL")
	}
	if _, err := c.DoWriteJSON(context.Background(), http.MethodPut, "/api/v1/../evil", nil, nil, nil); err == nil {
		t.Fatal("expected DoWriteJSON to reject dot-segment")
	}
}
