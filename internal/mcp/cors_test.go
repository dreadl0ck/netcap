package mcp

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestAuthenticatedMCPDoesNotGrantWildcardCORS(t *testing.T) {
	s, err := New(Options{BaseURL: "http://127.0.0.1:1", AdminToken: "synthetic"})
	if err != nil {
		t.Fatal(err)
	}
	for _, origin := range []string{"", "https://evil.invalid", "https://approved.invalid"} {
		for _, approved := range []bool{false, true} {
			w := httptest.NewRecorder()
			if approved {
				w.Header().Set("Access-Control-Allow-Origin", origin)
			}
			r := httptest.NewRequest("POST", "/mcp", nil)
			r.Header.Set("Origin", origin)
			r.Header.Set("Authorization", "bearer synthetic")
			called := false
			s.adminAuth(s.corsForMCP(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { called = true }))).ServeHTTP(w, r)
			got := w.Header().Get("Access-Control-Allow-Origin")
			if !called || got == "*" || (!approved && got != "") || (approved && got != origin) {
				t.Fatalf("origin=%s approved=%t header=%s status=%d", origin, approved, got, w.Code)
			}
		}
	}
}
