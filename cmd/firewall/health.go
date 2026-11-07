package firewall

import (
	"context"
	"net/http"
	"time"

	"github.com/dreadl0ck/netcap/internal/firewallfleet"
	"github.com/dreadl0ck/netcap/internal/firewallstate"
)

func fleetHealthHandler(s *firewallfleet.Service, cfg firewallfleet.Config) http.Handler {
	next := s.Handler()
	slots := make(chan struct{}, 16)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/health" {
			next.ServeHTTP(w, r)
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		token := firewallstate.Bearer(r)
		operator := firewallstate.MatchToken(token, cfg.Token)
		authorized := operator
		for _, p := range cfg.Identities {
			authorized = firewallstate.MatchToken(token, p.Token) || authorized
		}
		if !authorized {
			http.Error(w, "administrative bearer required", http.StatusUnauthorized)
			return
		}
		if r.Header.Get("Origin") != "" {
			http.Error(w, "browser origins refused", http.StatusForbidden)
			return
		}
		if r.Method != "GET" {
			w.Header().Set("Allow", "GET")
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		if r.URL.RawQuery != "" {
			http.Error(w, "health takes no parameters", http.StatusBadRequest)
			return
		}
		select {
		case slots <- struct{}{}:
			defer func() { <-slots }()
		default:
			http.Error(w, "health capacity exhausted", http.StatusServiceUnavailable)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		defer cancel()
		req := firewallfleet.Request{}
		if operator {
			req.Scope = firewallfleet.Scope{Tenant: "health", App: "health"}
		}
		// Capabilities runs a read-only authoritative transaction, including the
		// PostgreSQL bootstrap fingerprint check, without driving maintenance.
		if _, err := s.Execute(ctx, token, "capabilities", req); err != nil {
			http.Error(w, "controller unavailable", http.StatusServiceUnavailable)
			return
		}
		firewallstate.WriteJSON(w, http.StatusOK, map[string]bool{"ready": true})
	})
}
