package webui

import (
	"crypto/subtle"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
)

const localSessionCookie = "netcap-local-session"

// LocalAccessToken authenticates local API clients. Never include it in URLs.
func (s *Server) LocalAccessToken() string { return s.localAccessToken }

func (s *Server) localHostAllowed(host string) bool {
	bindHost, port, err := net.SplitHostPort(s.addr)
	if err != nil {
		return false
	}
	if strings.EqualFold(host, s.addr) {
		return true
	}
	ip := net.ParseIP(bindHost)
	if bindHost != "localhost" && (ip == nil || !ip.IsLoopback()) {
		return false
	}
	for _, name := range []string{"localhost", "127.0.0.1", "::1"} {
		if strings.EqualFold(host, net.JoinHostPort(name, port)) {
			return true
		}
	}
	return false
}

func (s *Server) localSecurityMiddleware(next http.Handler) http.Handler {
	if s.isServiceMode {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Referrer-Policy", "no-referrer")
		if !s.localHostAllowed(r.Host) {
			http.Error(w, "untrusted Host", http.StatusForbidden)
			return
		}
		if origin := r.Header.Get("Origin"); origin != "" {
			u, err := url.Parse(origin)
			scheme := "http"
			if r.TLS != nil {
				scheme = "https"
			}
			if err != nil || u.User != nil || u.Host == "" || u.RawQuery != "" || u.Fragment != "" || u.Path != "" ||
				(u.Scheme != "http" && u.Scheme != "https") ||
				!(u.Scheme == scheme && strings.EqualFold(u.Host, r.Host) || corsAllowedOrigins()[origin]) {
				http.Error(w, "untrusted Origin", http.StatusForbidden)
				return
			}
		}
		valid := func(token string) bool {
			return s.localAccessToken != "" && subtle.ConstantTimeCompare([]byte(token), []byte(s.localAccessToken)) == 1
		}
		if r.URL.Path == "/auth" {
			if r.Method == http.MethodGet {
				w.Header().Set("Content-Type", "text/html; charset=utf-8")
				w.Header().Set("Content-Security-Policy", "default-src 'none'; form-action 'self'; frame-ancestors 'none'")
				fmt.Fprint(w, `<!doctype html><title>Netcap local access</title><h1>Netcap local access</h1><form method="post" action="/auth"><label>Access token from the terminal <input name="token" type="password" required autocomplete="off"></label><button>Sign in</button></form>`)
				return
			}
			if r.Method != http.MethodPost {
				w.Header().Set("Allow", "GET, POST")
				http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
				return
			}
			r.Body = http.MaxBytesReader(w, r.Body, 4096)
			if err := r.ParseForm(); err != nil || !valid(r.PostForm.Get("token")) {
				http.Error(w, "invalid access token", http.StatusUnauthorized)
				return
			}
			http.SetCookie(w, &http.Cookie{Name: localSessionCookie, Value: s.localAccessToken, Path: "/", HttpOnly: true, Secure: r.TLS != nil, SameSite: http.SameSiteStrictMode})
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}
		token := bearerCredential(r)
		if !valid(token) {
			if (r.URL.Path == "/mcp" || r.URL.Path == "/mcp/" || r.URL.Path == "/mcp/metrics") && captureAdminAuthorized(r) {
				next.ServeHTTP(w, r)
				return
			}
			cookie, err := r.Cookie(localSessionCookie)
			if err != nil || !valid(cookie.Value) {
				if r.Method == http.MethodGet && !strings.HasPrefix(r.URL.Path, "/api/") {
					http.Redirect(w, r, "/auth", http.StatusSeeOther)
				} else {
					http.Error(w, "local access token required", http.StatusUnauthorized)
				}
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}
