package enforcer

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/dreadl0ck/netcap/internal/firewallauth"
)

// Handler serves /mcp (stateless Streamable HTTP), GET/POST /v1/leases and
// DELETE /v1/leases/{id}. REST POST accepts
// {"id":"incident-1","source":"192.0.2.1","ttl_seconds":60}.
// expires_at optionally specifies an authoritative RFC3339Nano deadline; it can
// replace ttl_seconds. When both are present, TTL is an additional upper bound.
// All routes require Authorization: Bearer <Token>. Mount behind TLS or on a
// trusted local socket; the embedding server owns transport timeouts. Bodies are
// bounded and duplicate/unknown JSON fields are rejected before action dispatch.
func (c *Controller) Handler() http.Handler {
	mcpHandler := c.mcpHandler()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		if c.config.Auth != nil && strings.HasPrefix(r.URL.Path, "/api/v1/auth/") {
			c.config.Auth.LifecycleHandler(c.config.Origin).ServeHTTP(w, r)
			return
		}
		got := sha256.Sum256([]byte(r.Header.Get("Authorization")))
		want := sha256.Sum256([]byte("Bearer " + c.config.Token))
		valid := subtle.ConstantTimeCompare(got[:], want[:]) == 1
		if c.config.Auth != nil {
			var err error
			r, err = c.config.Auth.Request(r)
			valid = err == nil
		}
		if !valid {
			w.Header().Set("WWW-Authenticate", `Bearer realm="enforcer"`)
			http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
			return
		}
		if !firewallauth.AllowOrigin(r, c.config.Origin) {
			http.Error(w, `{"error":"origin refused"}`, 403)
			return
		}
		r = r.WithContext(firewallauth.WithReceipt(r.Context(), r.Header.Get("X-Firewall-Approval")))
		if r.URL.Path == "/v1/approval" {
			if c.config.Approvals == nil || r.Method != "POST" {
				http.NotFound(w, r)
				return
			}
			raw, err := readJSONBody(w, r, 4096)
			var req firewallauth.ApprovalRequest
			if err != nil || decodeObject(raw, &req, "actor", "action", "scope", "digest") != nil || req.Scope != c.config.AuthScope {
				http.Error(w, "invalid approval request", 400)
				return
			}
			receipt, err := c.config.Approvals.Issue(r.Context(), req)
			if err != nil {
				http.Error(w, "approval refused", 403)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]string{"receipt": receipt})
			return
		}
		if c.config.Auth != nil && r.URL.Path != "/mcp" {
			action := firewallauth.Lease
			if r.Method == http.MethodGet {
				action = firewallauth.Read
			}
			if err := firewallauth.Require(r.Context(), action, c.config.AuthScope); err != nil {
				http.Error(w, `{"error":"lease grant required"}`, 403)
				return
			}
		}
		if r.URL.Path == "/mcp" {
			mcpHandler.ServeHTTP(w, r)
			return
		}
		if r.URL.Path == "/v1/capabilities" && r.Method == http.MethodGet {
			_ = json.NewEncoder(w).Encode(c.capabilities())
			return
		}
		if r.URL.Path == "/v1/leases" {
			switch r.Method {
			case http.MethodGet:
				ls, err := c.List(r.Context())
				if err != nil {
					apiError(w, err)
					return
				}
				_ = json.NewEncoder(w).Encode(ls)
			case http.MethodPost:
				raw, err := readJSONBody(w, r, 4096)
				var req leaseRequest
				if err != nil {
					http.Error(w, `{"error":"invalid request"}`, 400)
					return
				}
				if err := decodeObject(raw, &req, "id", "source", "ttl_seconds", "expires_at", "action", "receipt"); err != nil {
					http.Error(w, `{"error":"invalid request fields"}`, 400)
					return
				}
				l, err := c.createRequest(r.Context(), req)
				if err != nil {
					apiError(w, err)
					return
				}
				w.WriteHeader(http.StatusCreated)
				_ = json.NewEncoder(w).Encode(l)
			default:
				w.Header().Set("Allow", "GET, POST")
				http.Error(w, `{"error":"method not allowed"}`, 405)
			}
			return
		}
		if strings.HasPrefix(r.URL.Path, "/v1/leases/") {
			id := strings.TrimPrefix(r.URL.Path, "/v1/leases/")
			if !identifier.MatchString(id) {
				http.Error(w, `{"error":"invalid ID"}`, 400)
				return
			}
			if r.Method != http.MethodDelete {
				w.Header().Set("Allow", "DELETE")
				http.Error(w, `{"error":"method not allowed"}`, 405)
				return
			}
			if err := c.Delete(r.Context(), id); err != nil {
				apiError(w, err)
				return
			}
			w.WriteHeader(http.StatusNoContent)
			return
		}
		http.Error(w, `{"error":"not found"}`, 404)
	})
}

func apiError(w http.ResponseWriter, err error) {
	status := http.StatusBadRequest
	if errors.Is(err, firewallauth.ErrForbidden) || errors.Is(err, firewallauth.ErrUnauthenticated) {
		status = http.StatusForbidden
	} else if errors.Is(err, ErrConflict) {
		status = http.StatusConflict
	} else if errors.Is(err, ErrLimit) {
		status = http.StatusTooManyRequests
	} else {
		var e *ExecutionError
		if errors.As(err, &e) {
			status = http.StatusServiceUnavailable
		}
	}
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
}

// ExecutionError identifies backend/persistence failures without exposing command output.
type ExecutionError struct{ Err error }

func (e *ExecutionError) Error() string { return "enforcer executor unavailable: " + e.Err.Error() }
func (e *ExecutionError) Unwrap() error { return e.Err }
