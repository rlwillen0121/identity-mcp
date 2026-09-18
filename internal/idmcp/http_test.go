package idmcp

import (
	"context"
	"net/http"
	"net/http/httptest"
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
