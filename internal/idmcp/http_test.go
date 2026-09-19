package idmcp

import (
	"context"
	"net/http"
	"net/http/httptest"
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
