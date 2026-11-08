package firewallui

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestOriginBoundary(t *testing.T) {
	for _, tc := range []struct {
		name, origin, path, kind, auth string
		want                           int
	}{
		{"same policy", "http://admin.test", "/api/v1/policy/stage", "policy", "Bearer test", 204},
		{"same fleet", "http://admin.test", "/api/v1/fleet/drain", "fleet", "Bearer test", 204},
		{"same lease", "http://admin.test", "/v1/leases/example", "leases", "Bearer test", 204},
		{"CLI", "", "/mcp", "policy", "Bearer test", 204},
		{"cross origin", "http://evil.test", "/api/v1/policy/stage", "policy", "Bearer test", 403},
		{"null origin", "null", "/api/v1/policy/stage", "policy", "Bearer test", 403},
		{"scheme", "https://admin.test", "/api/v1/policy/stage", "policy", "Bearer test", 403},
		{"port", "http://admin.test:80", "/api/v1/policy/stage", "policy", "Bearer test", 403},
		{"missing bearer", "http://admin.test", "/api/v1/policy/stage", "policy", "", 403},
		{"MCP stays private", "http://admin.test", "/mcp", "policy", "Bearer test", 403},
		{"agent stays private", "http://admin.test", "/api/v1/fleet/desired", "fleet", "Bearer test", 403},
		{"unknown operation", "http://admin.test", "/api/v1/policy/unknown", "policy", "Bearer test", 403},
		{"wrong listener", "http://admin.test", "/api/v1/fleet/status", "policy", "Bearer test", 403},
	} {
		t.Run(tc.name, func(t *testing.T) {
			next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("Origin") != "" || r.Header.Get("Authorization") != tc.auth {
					t.Error("incorrect forwarded headers")
				}
				w.WriteHeader(204)
			})
			r := httptest.NewRequest("POST", "http://admin.test"+tc.path, nil)
			r.Header.Set("Origin", tc.origin)
			r.Header.Set("Authorization", tc.auth)
			r.Header.Set("X-Forwarded-Proto", "https")
			w := httptest.NewRecorder()
			Wrap(next, tc.kind).ServeHTTP(w, r)
			if w.Code != tc.want {
				t.Fatalf("status %d, want %d", w.Code, tc.want)
			}
			if r.Header.Get("Origin") != tc.origin {
				t.Error("mutated original request")
			}
			if w.Header().Get("Access-Control-Allow-Origin") != "" {
				t.Error("unexpected CORS surface")
			}
		})
	}
}

func TestEmbeddedAssets(t *testing.T) {
	h := Wrap(http.NotFoundHandler(), "policy")
	for _, path := range []string{"/console/", "/console/app.js", "/console/app.css", "/console/service"} {
		t.Run(path, func(t *testing.T) {
			w := httptest.NewRecorder()
			h.ServeHTTP(w, httptest.NewRequest("GET", path, nil))
			if w.Code != 200 {
				t.Fatal(w.Code)
			}
			csp := w.Header().Get("Content-Security-Policy")
			if !strings.Contains(csp, "script-src 'self'") || strings.Contains(csp, "unsafe-inline") {
				t.Fatal(csp)
			}
			if w.Header().Get("Cache-Control") != "no-store" {
				t.Fatal("cacheable admin content")
			}
		})
	}
	for _, path := range []string{"/console/missing", "/console/index.html", "/console/subdir/"} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest("GET", path, nil))
		if w.Code != 404 {
			t.Fatal(path, w.Code)
		}
	}
}
