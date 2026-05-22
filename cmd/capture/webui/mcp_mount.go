/*
 * NETCAP - Traffic Analysis Framework
 * Copyright (c) Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
 * License: GNU General Public License v3.0
 */

package webui

import (
	"log"
	"net"
	"net/http"
	"os"
	"strings"

	netcapmcp "github.com/dreadl0ck/netcap/internal/mcp"
)

// EnvMCPAdminToken is the env-var name that gates the /mcp endpoint in
// service mode. When unset (or empty), /mcp is not mounted at all and
// HTTP requests to it return 404. Operators of try.netcap.io set this
// to enable admin-only MCP access.
const EnvMCPAdminToken = "NETCAP_MCP_ADMIN_TOKEN"

// mountMCP attaches the MCP streamable-HTTP handler at /mcp on the given
// mux, behind admin-token authentication. The token is read from the
// EnvMCPAdminToken environment variable. If empty, this is a no-op and
// /mcp remains unmapped (so an unprotected endpoint can never accidentally
// be served).
//
// The MCP server tools are thin shims that talk to this same webui over
// loopback. We pass loopbackBase so a single physical webui instance can
// service both browser users (over its public bind) and MCP tool calls
// (over loopback, no auth, no rate limit).
func (s *Server) mountMCP(mux *http.ServeMux, loopbackBase string) {
	token := os.Getenv(EnvMCPAdminToken)
	if token == "" {
		return
	}

	resolved := loopbackize(loopbackBase)
	mcpLog := log.New(log.Writer(), "[MCP] ", log.LstdFlags|log.Lmicroseconds)
	allowFetch := os.Getenv("NETCAP_MCP_ALLOW_FETCH") == "1"
	srv, err := netcapmcp.New(netcapmcp.Options{
		BaseURL:      resolved,
		AdminToken:   token,
		Logger:       mcpLog,
		AllowNetwork: allowFetch,
	})
	if err != nil {
		log.Printf("[MCP] Failed to construct server: %v (endpoint not mounted)", err)
		return
	}

	// Streamable HTTP exposes both POST and GET on /mcp (SSE for server
	// notifications). Mount both the bare path and the trailing-slash
	// variant so the transport's internal routing works.
	handler := srv.HTTPHandler()
	mux.Handle("/mcp", handler)
	mux.Handle("/mcp/", handler)

	log.Printf("[MCP] Admin endpoint registered at /mcp (loopback=%s, token fingerprint=%s)",
		resolved, srv.TokenFingerprint())
}

// loopbackize rewrites a public bind URL into one safe for self-loopback
// HTTP calls (the MCP tools connect back to this same server). If the
// URL's host is 0.0.0.0, :: or empty, swap it for 127.0.0.1. Anything
// else (a specific IP, "localhost", a hostname) is left intact.
func loopbackize(base string) string {
	const httpPrefix = "http://"
	if !strings.HasPrefix(base, httpPrefix) {
		return base
	}
	hostport := strings.TrimPrefix(base, httpPrefix)

	// "":8080 — no host part at all (very common: addr=":8080").
	if strings.HasPrefix(hostport, ":") {
		return httpPrefix + "127.0.0.1" + hostport
	}

	host, port, err := net.SplitHostPort(hostport)
	if err != nil {
		// Malformed; best-effort return unchanged.
		return base
	}
	switch host {
	case "", "0.0.0.0", "::", "[::]":
		host = "127.0.0.1"
	}
	return httpPrefix + net.JoinHostPort(host, port)
}
