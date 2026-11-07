package firewallauth

import (
	"context"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

type Revocations interface {
	Revoked(context.Context, string) (bool, error)
	Revoke(context.Context, string) error
}

// SQLRevocations stores only credential fingerprints in operator-owned SQLite.
// Revocations are permanent; rotation/re-admission uses trusted configuration.
type SQLRevocations struct{ DB *sql.DB }

func NewSQLRevocations(ctx context.Context, db *sql.DB) (*SQLRevocations, error) {
	_, err := db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS firewall_credential_revocations(digest TEXT PRIMARY KEY)`)
	return &SQLRevocations{DB: db}, err
}
func (s *SQLRevocations) Revoked(ctx context.Context, digest string) (bool, error) {
	var n int
	err := s.DB.QueryRowContext(ctx, `SELECT count(*) FROM firewall_credential_revocations WHERE digest=?`, digest).Scan(&n)
	return n != 0, err
}
func (s *SQLRevocations) Revoke(ctx context.Context, digest string) error {
	if len(digest) != 64 {
		return errors.New("invalid credential fingerprint")
	}
	if _, err := hex.DecodeString(digest); err != nil {
		return err
	}
	digest = strings.ToLower(digest)
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var n int
	if err = tx.QueryRowContext(ctx, `SELECT count(*) FROM firewall_credential_revocations`).Scan(&n); err != nil {
		return err
	}
	if n >= 4096 {
		return errors.New("credential revocation capacity exhausted")
	}
	if _, err = tx.ExecContext(ctx, `INSERT OR IGNORE INTO firewall_credential_revocations VALUES(?)`, digest); err != nil {
		return err
	}
	return tx.Commit()
}
func (a *Authority) Revoke(ctx context.Context, fingerprint string) error {
	if err := Require(ctx, ManageCredentials, Scope{}); err != nil {
		return err
	}
	a.mu.RLock()
	defer a.mu.RUnlock()
	if a.revocations == nil {
		return errors.New("durable revocations not configured")
	}
	return a.revocations.Revoke(ctx, fingerprint)
}
func (a *Authority) AddLifecycleTool(s *server.MCPServer) {
	s.AddTool(mcp.NewTool("revoke_firewall_credential", mcp.WithDescription("Permanently revoke a SHA-256 credential fingerprint; requires manage-credentials grant."), mcp.WithString("fingerprint", mcp.Required())), func(ctx context.Context, r mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		fingerprint, err := r.RequireString("fingerprint")
		if err != nil {
			return mcp.NewToolResultError("fingerprint required"), nil
		}
		if err = a.Revoke(ctx, fingerprint); err != nil {
			return mcp.NewToolResultError("credential revocation denied or unavailable"), nil
		}
		return mcp.NewToolResultText("revoked"), nil
	})
}

// LifecycleHandler never issues JWTs, changes issuer trust, or accepts tokens in a URL.
func (a *Authority) LifecycleHandler(origin string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		if !AllowOrigin(r, origin) {
			http.Error(w, "origin refused", 403)
			return
		}
		r, err := a.Request(r)
		if err != nil {
			http.Error(w, "credential rejected", 401)
			return
		}
		if Require(r.Context(), ManageCredentials, Scope{}) != nil {
			http.Error(w, "credential administration grant required", 403)
			return
		}
		if r.URL.Path != "/api/v1/auth/revoke" {
			http.NotFound(w, r)
			return
		}
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", "POST")
			w.WriteHeader(405)
			return
		}
		var in struct {
			Fingerprint string `json:"fingerprint"`
		}
		d := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1024))
		d.DisallowUnknownFields()
		if d.Decode(&in) != nil || d.Decode(&struct{}{}) != io.EOF {
			http.Error(w, "invalid revocation request", 400)
			return
		}
		if err := a.Revoke(r.Context(), in.Fingerprint); err != nil {
			http.Error(w, "revocation failed or durable store unavailable", 400)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
}
