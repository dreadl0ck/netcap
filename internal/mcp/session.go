/*
 * NETCAP - Traffic Analysis Framework
 * Copyright (c) Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
 * License: GNU General Public License v3.0
 */

package mcp

import (
	"net/url"
	"strings"
)

// SessionRef is the abstraction the MCP server uses to address an
// analysis across both webui deployment modes:
//
//   - Service mode: 16-byte hex id (e.g. "abcdef0123456789...").
//   - Local mode: absolute filesystem path to a PCAP/PCAPNG.
//
// The webui's session_resolver.resolveOutDirFromRequest accepts either
// shape via the ?sessionId= and ?inputFile= query parameters, so the
// MCP layer only needs to know which kind it has.
type SessionRef struct {
	ID     string
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
	// 32-char hex → service session id.
	if len(s) == 32 && isHex(s) {
		return false
	}
	// Empty / unknown shapes fall through as "not a path".
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

// sessionQueryParams returns the URL query params that tell the webui
// analytical handlers which session to use. Service-mode refs become
// ?sessionId=<hex>; local-mode refs become ?inputFile=<abs path>. An
// empty SessionRef returns empty values.
func (ref SessionRef) sessionQueryParams() url.Values {
	v := url.Values{}
	if ref.ID == "" {
		return v
	}
	if ref.isPath {
		v.Set("inputFile", ref.ID)
	} else {
		v.Set("sessionId", ref.ID)
	}
	return v
}
