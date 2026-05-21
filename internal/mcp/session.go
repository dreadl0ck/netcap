/*
 * NETCAP - Traffic Analysis Framework
 * Copyright (c) Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
 * License: GNU General Public License v3.0
 */

package mcp

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"sync"
)

// SessionRef is the abstraction the MCP server uses to address an analysis
// across both webui deployment modes:
//
//   - In service mode, webui sessions have a 16-byte hex id and are
//     selected via POST /api/try/session/<id>.
//   - In local mode, "sessions" are really input-file paths selected via
//     POST /api/set-directory with body {"inputFile": "..."}.
//
// We expose a single string field `session_id` to MCP clients and figure
// out which mode applies at call time, by probing /api/status.
type SessionRef struct {
	// ID is whatever the client supplied as session_id. It may be a
	// 16-byte hex (service) or a filesystem path (local).
	ID string

	// isPath is set to true when ID looks like a filesystem path; the
	// resolver uses /api/set-directory rather than /api/try/session.
	isPath bool
}

func newSessionRef(id string) SessionRef {
	id = strings.TrimSpace(id)
	return SessionRef{
		ID:     id,
		isPath: looksLikePath(id),
	}
}

// looksLikePath is a heuristic: a 32-hex-character string is a service
// session id; anything containing a path separator or a known PCAP
// extension is treated as a local-mode input file path.
func looksLikePath(s string) bool {
	if strings.ContainsAny(s, "/\\") {
		return true
	}
	low := strings.ToLower(s)
	for _, ext := range []string{".pcap", ".pcapng", ".cap", ".dmp"} {
		if strings.HasSuffix(low, ext) {
			return true
		}
	}
	// 16-byte hex (32 chars) — service session id shape.
	if len(s) == 32 && isHex(s) {
		return false
	}
	// Empty / unknown shapes fall through as "not a path"; the server-mode
	// fallback returns an error if the id isn't recognised.
	return false
}

func isHex(s string) bool {
	for _, r := range s {
		switch {
		case r >= '0' && r <= '9', r >= 'a' && r <= 'f', r >= 'A' && r <= 'F':
		default:
			return false
		}
	}
	return true
}

// sessionGate serialises (selectSession + call) pairs so two concurrent
// MCP tool invocations against different sessions don't stomp on the
// webui's global currentSession / currentOutDir. Until the analytical
// handlers accept a per-request session id, this is the only safe option.
type sessionGate struct {
	mu sync.Mutex
}

// run holds the gate for the duration of fn. fn typically does
//
//	client.SelectSession(ref); client.Get("/api/foo")
//
// and so must complete before another session can be selected.
func (g *sessionGate) run(fn func() error) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	return fn()
}

// selectSession switches the webui to ref via the right endpoint for the
// current mode. Errors are wrapped with the ref so logs are useful.
func (c *NetcapClient) selectSession(ref SessionRef) error {
	if ref.ID == "" {
		return fmt.Errorf("session_id is empty")
	}
	if ref.isPath {
		body, err := c.PostJSON("/api/set-directory", map[string]string{"inputFile": ref.ID})
		if err != nil {
			return fmt.Errorf("set-directory %s: %w", ref.ID, err)
		}
		var resp struct {
			Success bool   `json:"success"`
			Error   string `json:"error,omitempty"`
		}
		_ = json.Unmarshal(body, &resp)
		if resp.Error != "" {
			return fmt.Errorf("set-directory %s: %s", ref.ID, resp.Error)
		}
		return nil
	}
	// Service-mode session.
	_, err := c.Get("/api/try/session/"+url.PathEscape(ref.ID), nil)
	if err != nil {
		return fmt.Errorf("select session %s: %w", ref.ID, err)
	}
	return nil
}
