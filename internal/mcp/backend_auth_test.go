package mcp

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestBackendAdminAuthIsScopedAndDoesNotFollowRedirects(t *testing.T) {
	forwarded := false
	foreign := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { forwarded = true }))
	defer foreign.Close()
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/redirect" {
			http.Redirect(w, r, foreign.URL, 302)
			return
		}
		want := ""
		if r.URL.Path == "/api/owned" {
			want = "Bearer synthetic-admin"
		}
		if r.Header.Get("Authorization") != want {
			t.Errorf("%s: unexpected auth header", r.URL.Path)
		}
		w.Write([]byte(`{}`))
	}))
	defer backend.Close()
	s := &Server{baseURL: backend.URL, adminToken: "synthetic-admin"}
	c := s.newClient()
	if _, err := c.Get("/api/owned", nil); err != nil {
		t.Fatal(err)
	}
	if _, _, err := c.GetRaw("/api/owned", nil); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Get("/unrelated", nil); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Get("/api/redirect", nil); err == nil {
		t.Fatal("redirect became successful API data")
	}
	if forwarded {
		t.Fatal("backend credentials followed redirect")
	}
}
