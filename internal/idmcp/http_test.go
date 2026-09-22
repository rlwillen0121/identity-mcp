package idmcp

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
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

func TestRequireHTTPSRejectsCredentialRedirectShapes(t *testing.T) {
	for _, raw := range []string{
		"https://user:secret@example.com",
		"https://example.com/path?redirect=https://evil.example",
		"https://example.com/path#fragment",
		"http://example.com",
	} {
		if err := RequireHTTPS("endpoint", raw); err == nil {
			t.Errorf("RequireHTTPS(%q) unexpectedly succeeded", raw)
		}
	}
}

func TestValidateOktaBaseURLAuthorities(t *testing.T) {
	for _, raw := range []string{
		"https://acme.okta.com",
		"https://acme.oktapreview.com/",
		"https://acme.okta-emea.com",
		"https://acme.okta-gov.com",
	} {
		if err := ValidateOktaBaseURL(raw, false); err != nil {
			t.Errorf("ValidateOktaBaseURL(%q): %v", raw, err)
		}
	}
	for _, raw := range []string{
		"https://acme.example.com",
		"https://acme.okta.com:8443",
		"https://acme.okta.com/api/v1",
		"https://acme.okta.com?x=1",
		"https://user:secret@acme.okta.com",
	} {
		if err := ValidateOktaBaseURL(raw, false); err == nil {
			t.Errorf("ValidateOktaBaseURL(%q) unexpectedly succeeded", raw)
		}
	}
	if err := ValidateOktaBaseURL("https://private.example.test", true); err != nil {
		t.Fatalf("explicit custom Okta endpoint: %v", err)
	}
}

func TestValidateGraphBaseURLAuthorities(t *testing.T) {
	for _, raw := range []string{
		"https://graph.microsoft.com/v1.0",
		"https://graph.microsoft.com/beta",
	} {
		if err := ValidateGraphBaseURL(raw, false); err != nil {
			t.Errorf("ValidateGraphBaseURL(%q): %v", raw, err)
		}
	}
	for _, raw := range []string{
		"https://graph.example.com/v1.0",
		"https://graph.microsoft.us/v1.0/",
		"https://dod-graph.microsoft.us/beta",
		"https://graph.microsoft.de/v1.0",
		"https://microsoftgraph.chinacloudapi.cn/v1.0",
		"https://graph.microsoft.com/v1.0?x=1",
		"https://graph.microsoft.com/v1.0#fragment",
		"https://user:secret@graph.microsoft.com/v1.0",
		"https://graph.microsoft.com/",
		"https://graph.microsoft.com:8443/v1.0",
	} {
		if err := ValidateGraphBaseURL(raw, false); err == nil {
			t.Errorf("ValidateGraphBaseURL(%q) unexpectedly succeeded", raw)
		}
	}
	if err := ValidateGraphBaseURL("https://private.example.test/v1.0", true); err != nil {
		t.Fatalf("explicit custom Graph endpoint: %v", err)
	}
}

func TestPostFormDoesNotFollowCredentialRedirect(t *testing.T) {
	var redirected atomic.Bool
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		redirected.Store(true)
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(target.Close)
	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+"/capture", http.StatusTemporaryRedirect)
	}))
	t.Cleanup(source.Close)
	c := NewClient("", nil)
	if _, err := c.PostForm(context.Background(), source.URL+"/token", url.Values{"client_secret": {"redacted-test-value"}}); err == nil || StatusOf(err) != http.StatusTemporaryRedirect {
		t.Fatalf("redirect error = %v, status = %d", err, StatusOf(err))
	}
	if redirected.Load() {
		t.Fatal("credential redirect was followed")
	}
}

func TestGetJSONWithAuthDoesNotMutateClientHeaders(t *testing.T) {
	var got string
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Get("Authorization")
		w.Write([]byte(`{"ok":true}`))
	}))
	t.Cleanup(s.Close)
	h := make(http.Header)
	h.Set("Authorization", "Bearer old")
	c := NewClient(s.URL, h)
	var dst map[string]bool
	if _, err := c.GetJSONWithAuth(context.Background(), "/x", nil, "Bearer selected", &dst); err != nil {
		t.Fatal(err)
	}
	if got != "Bearer selected" {
		t.Fatalf("authorization = %q", got)
	}
	if c.Header.Get("Authorization") != "Bearer old" {
		t.Fatalf("client header mutated: %q", c.Header.Get("Authorization"))
	}
}

func TestGetWithAuthDoesNotFollowRedirect(t *testing.T) {
	var redirected atomic.Bool
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		redirected.Store(true)
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(target.Close)
	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer selected" {
			t.Errorf("source authorization = %q", got)
		}
		http.Redirect(w, r, target.URL+"/capture", http.StatusTemporaryRedirect)
	}))
	t.Cleanup(source.Close)

	c := NewClient(source.URL, nil)
	if _, err := c.GetJSONWithAuth(context.Background(), "/users", nil, "Bearer selected", nil); err == nil || StatusOf(err) != http.StatusTemporaryRedirect {
		t.Fatalf("redirect error = %v, status = %d", err, StatusOf(err))
	}
	if redirected.Load() {
		t.Fatal("authenticated redirect was followed")
	}
}
