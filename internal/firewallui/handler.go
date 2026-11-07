// Package firewallui serves the standalone, embedded administrative console.
package firewallui

import (
	"embed"
	"io"
	"io/fs"
	"net/http"
	"strings"
)

//go:embed static/*
var assets embed.FS

// Wrap adds /console to one administrative listener. Authentication and scope
// authorization remain in next. Forwarded headers deliberately do not set origin.
func Wrap(next http.Handler, kind string) http.Handler {
	files, _ := fs.Sub(assets, "static")
	static := http.FileServer(http.FS(files))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Cache-Control", "no-store")
		if r.URL.Path == "/console" {
			http.Redirect(w, r, "/console/", http.StatusTemporaryRedirect)
			return
		}
		if strings.HasPrefix(r.URL.Path, "/console/") {
			if r.Method != http.MethodGet && r.Method != http.MethodHead {
				w.WriteHeader(http.StatusMethodNotAllowed)
				return
			}
			if r.URL.Path == "/console/service" {
				w.Header().Set("Content-Type", "text/plain")
				_, _ = w.Write([]byte(kind))
				return
			}
			p := strings.TrimPrefix(r.URL.Path, "/console/")
			if p != "" && p != "app.js" && p != "app.css" {
				http.NotFound(w, r)
				return
			}
			http.StripPrefix("/console/", static).ServeHTTP(w, r)
			return
		}
		if origin := r.Header.Get("Origin"); origin != "" {
			scheme := "http"
			if r.TLS != nil {
				scheme = "https"
			}
			if origin != scheme+"://"+r.Host || !consoleAPI(r.URL.Path, kind) || !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") {
				http.Error(w, `{"error":"console requires exact same origin and bearer authentication"}`, http.StatusForbidden)
				return
			}
			// Only the private console REST allowlist reaches legacy handlers that
			// refuse every Origin. The original request is never mutated.
			r = r.Clone(r.Context())
			r.Header.Del("Origin")
		}
		if kind == "leases" && r.URL.Path == "/api/v1/console/enforcer-capabilities" {
			if r.Method != http.MethodGet {
				w.WriteHeader(http.StatusMethodNotAllowed)
				return
			}
			r = r.Clone(r.Context())
			r.URL.Path = "/mcp"
			r.Method = http.MethodPost
			body := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"get_enforcer_capabilities","arguments":{}}}`
			r.Body = io.NopCloser(strings.NewReader(body))
			r.ContentLength = int64(len(body))
			r.Header.Set("Content-Type", "application/json")
			r.Header.Set("Accept", "application/json, text/event-stream")
		}
		next.ServeHTTP(w, r)
	})
}

func consoleAPI(path, kind string) bool {
	var prefix, operations string
	switch kind {
	case "policy":
		prefix, operations = "/api/v1/policy/", " capabilities revision revisions check evaluate stage diff activate rollback audit "
	case "fleet":
		prefix, operations = "/api/v1/fleet/", " capabilities status audit stage rollout activate promote rollback drain revoke resume "
	case "leases":
		return path == "/api/v1/console/enforcer-capabilities" || path == "/v1/leases" || (strings.HasPrefix(path, "/v1/leases/") && !strings.Contains(strings.TrimPrefix(path, "/v1/leases/"), "/"))
	}
	if prefix != "" && strings.HasPrefix(path, prefix) {
		for _, op := range strings.Fields(operations) {
			if strings.TrimPrefix(path, prefix) == op {
				return true
			}
		}
	}
	return false
}
