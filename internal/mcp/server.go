/*
 * NETCAP - Traffic Analysis Framework
 * Copyright (c) Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
 * License: GNU General Public License v3.0
 */

package mcp

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	mcplib "github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"

	netcapver "github.com/dreadl0ck/netcap"
)

const (
	serverName    = "netcap-mcp"
	defaultPath   = "/mcp"
	tokenAuthHdr  = "Authorization"
	tokenAuthKind = "Bearer "
)

// serverInstructions is the long markdown preamble shipped to LLM clients
// at initialize time. Keep it concise: every connect pays the token cost.
const serverInstructions = `# Netcap MCP

Netcap converts PCAP files into structured audit records and exposes them
as analytical queries. To use this server:

1. Call ` + "`ingest_pcap`" + ` with an absolute file path; capture the
   ` + "`session_id`" + ` from the response.
2. Poll ` + "`get_session_info`" + ` with the session_id until
   ` + "`status: completed`" + ` (typically a few seconds for a small PCAP).
3. Run analytical tools (` + "`list_hosts`" + `, ` + "`list_connections`" + `,
   ` + "`list_http_records`" + `, etc.) passing the same session_id. Use
   ` + "`limit`" + `/` + "`offset`" + `/` + "`search`" + ` arguments to keep
   responses below the 256 KiB per-call cap.
4. ` + "`carve_subpcap_for_*`" + ` returns a download URL for a focused
   sub-PCAP; hand it to another tool for offline review.

Notes:
 - A session id in this server may be a 32-char hex (service mode) or an
   absolute path to a PCAP file (CLI mode). Pass back exactly what
   ` + "`ingest_pcap`" + ` returned.
 - Per-tool calls serialise through the underlying webui's single
   currentSession; parallel calls against different sessions may queue.
 - YARA scans and rule executions are synchronous — they may take seconds
   to minutes; results are returned inline. Use ` + "`list_alerts`" + ` to
   review historical alerts.
`

// Server is the top-level MCP server. A single Server instance can be
// exposed via either an HTTP handler (service mode) or stdio (CLI).
type Server struct {
	// baseURL points at the netcap webui that backs all tool handlers.
	// In service mode this is a loopback URL into the same process; in
	// CLI stdio mode it is the embedded webui spawned by `net mcp`.
	baseURL string

	// adminToken, if non-empty, is required as a Bearer token on every
	// HTTP request to /mcp. Stdio mode does not consult this field.
	adminToken string

	// activeSession is set when the server has a single "blessed" session
	// (used by `net mcp --pcap <path>`). Exposed to the LLM as a resource.
	activeSession string

	// allowedTools / disallowedTools are optional allow/deny lists keyed
	// by tool name. Empty allowedTools means all-allowed (modulo deny).
	allowedTools    map[string]struct{}
	disallowedTools map[string]struct{}

	// logger is the destination for human-readable diagnostic logs. In
	// stdio mode this MUST NOT be os.Stdout (that's reserved for JSON-RPC
	// frames). Defaults to log.New(os.Stderr, ...).
	logger *log.Logger

	// gate serialises session-switching tool calls. See sessionGate.
	gate sessionGate

	// cve fetches CVE details from NVD with caching. Disabled when the
	// AllowNetwork option is false (or NETCAP_MCP_DISABLE_NETWORK is set).
	cve *CVELookup

	// carve holds previously-extracted sub-PCAPs for delivery via the
	// netcap://carve/{id} resource URI. Capped at 32 entries / 1h TTL by
	// default (CarveStore.gc).
	carve *CarveStore

	mcpSrv     *server.MCPServer
	httpServer *server.StreamableHTTPServer
}

// Options configures a Server.
type Options struct {
	// BaseURL of the netcap webui API. Required.
	BaseURL string
	// AdminToken, if non-empty, is required as a Bearer token on the HTTP
	// transport. Ignored by the stdio transport.
	AdminToken string
	// ActiveSession marks a single pre-loaded session as the default for
	// the CLI stdio server (so LLMs can discover it without arguments).
	// May be a 32-char hex (service id) or an absolute PCAP path (local).
	ActiveSession string
	// AllowedTools / DisallowedTools optionally restrict which tools are
	// registered (post-name validation). Empty lists mean no restriction.
	AllowedTools    []string
	DisallowedTools []string
	// Logger receives diagnostic messages. Defaults to stderr.
	Logger *log.Logger

	// AllowNetwork enables outbound HTTP for tools that talk to the
	// public internet (e.g. lookup_cve hits NVD). Default false in
	// air-gapped service-mode operators' environments. Set
	// NETCAP_MCP_DISABLE_NETWORK=1 to force-disable regardless of this
	// field.
	AllowNetwork bool

	// CarveDir overrides the on-disk location for carved sub-PCAPs.
	// Default: os.TempDir()/netcap-mcp-carve.
	CarveDir string
}

// New constructs a Server, registers tools/resources/prompts, and returns
// it. The returned Server has not yet been bound to a transport; call
// HTTPHandler or ServeStdio.
func New(opts Options) (*Server, error) {
	if opts.BaseURL == "" {
		return nil, fmt.Errorf("mcp: BaseURL is required")
	}
	if opts.Logger == nil {
		// Always log to stderr; never stdout (would corrupt stdio JSON-RPC).
		opts.Logger = log.New(io.Discard, "[MCP] ", log.LstdFlags|log.Lmicroseconds)
	}

	networkEnabled := opts.AllowNetwork && os.Getenv("NETCAP_MCP_DISABLE_NETWORK") != "1"
	s := &Server{
		baseURL:         strings.TrimRight(opts.BaseURL, "/"),
		adminToken:      opts.AdminToken,
		activeSession:   strings.TrimSpace(opts.ActiveSession),
		allowedTools:    toSet(opts.AllowedTools),
		disallowedTools: toSet(opts.DisallowedTools),
		logger:          opts.Logger,
		cve:             NewCVELookup(networkEnabled),
		carve:           NewCarveStore(opts.CarveDir, 32, time.Hour),
	}

	s.mcpSrv = server.NewMCPServer(
		serverName,
		netcapver.Version,
		server.WithToolCapabilities(false),
		server.WithResourceCapabilities(false, false),
		server.WithPromptCapabilities(false),
		server.WithRecovery(),
		server.WithInstructions(serverInstructions),
		server.WithToolHandlerMiddleware(s.toolLogMiddleware),
	)

	if err := s.registerAll(); err != nil {
		return nil, err
	}

	return s, nil
}

// HTTPHandler returns an http.Handler that serves the MCP endpoint over
// streamable HTTP at /mcp. The returned handler wraps the mcp-go transport
// in admin-token authentication.
func (s *Server) HTTPHandler() http.Handler {
	if s.httpServer == nil {
		s.httpServer = server.NewStreamableHTTPServer(
			s.mcpSrv,
			server.WithEndpointPath(defaultPath),
			server.WithStateLess(true),
			server.WithHeartbeatInterval(30*time.Second),
		)
	}
	return s.adminAuth(s.corsForMCP(s.httpServer))
}

// ServeStdio runs the server over stdio until the context is cancelled or
// stdin is closed. Intended for `net mcp` CLI usage with desktop clients.
func (s *Server) ServeStdio(ctx context.Context) error {
	stdio := server.NewStdioServer(s.mcpSrv)
	stdio.SetErrorLogger(s.logger)
	return stdio.Listen(ctx, stdinReader(), stdoutWriter())
}

// adminAuth enforces a constant-time bearer-token check on every request
// to /mcp. When s.adminToken is empty the middleware short-circuits to
// 503 — we never serve unauthenticated MCP traffic.
func (s *Server) adminAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Always answer CORS preflight without auth so browser-based MCP
		// clients can discover the endpoint.
		if r.Method == http.MethodOptions {
			next.ServeHTTP(w, r)
			return
		}
		if s.adminToken == "" {
			s.logger.Printf("rejecting %s %s: MCP disabled (no admin token)", r.Method, r.URL.Path)
			http.Error(w, "mcp endpoint disabled", http.StatusServiceUnavailable)
			return
		}
		h := r.Header.Get(tokenAuthHdr)
		if len(h) <= len(tokenAuthKind) || !strings.EqualFold(h[:len(tokenAuthKind)], tokenAuthKind) {
			s.logger.Printf("rejecting %s %s: missing/invalid Authorization", r.Method, r.URL.Path)
			w.Header().Set("WWW-Authenticate", `Bearer realm="netcap-mcp"`)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		token := h[len(tokenAuthKind):]
		if subtle.ConstantTimeCompare([]byte(token), []byte(s.adminToken)) != 1 {
			s.logger.Printf("rejecting %s %s: bad token (len=%d)", r.Method, r.URL.Path, len(token))
			w.Header().Set("WWW-Authenticate", `Bearer realm="netcap-mcp"`)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// corsForMCP installs a permissive CORS policy on the MCP endpoint that
// includes Authorization in Allow-Headers so browser-based MCP clients
// can present a Bearer token. The outer webui's corsMiddleware does not
// include Authorization.
func (s *Server) corsForMCP(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, Accept, Mcp-Session-Id, Last-Event-ID")
		w.Header().Set("Access-Control-Expose-Headers", "Mcp-Session-Id")
		w.Header().Set("Access-Control-Max-Age", "86400")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusOK)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// toolLogMiddleware is a server.ToolHandlerMiddleware that logs every
// tool invocation with its duration, response size, and error status.
// This is invaluable when debugging an LLM session.
func (s *Server) toolLogMiddleware(next server.ToolHandlerFunc) server.ToolHandlerFunc {
	return func(ctx context.Context, req mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
		name := req.Params.Name
		start := time.Now()
		result, err := next(ctx, req)
		dur := time.Since(start)
		switch {
		case err != nil:
			s.logger.Printf("tool=%s duration=%s error=%v", name, dur, err)
		case result != nil && result.IsError:
			s.logger.Printf("tool=%s duration=%s status=error_result content=%d bytes",
				name, dur, contentSize(result))
		default:
			s.logger.Printf("tool=%s duration=%s status=ok content=%d bytes",
				name, dur, contentSize(result))
		}
		return result, err
	}
}

func contentSize(r *mcplib.CallToolResult) int {
	if r == nil {
		return 0
	}
	n := 0
	for _, c := range r.Content {
		if tc, ok := c.(mcplib.TextContent); ok {
			n += len(tc.Text)
		}
	}
	return n
}

// addTool registers a ServerTool unless it is blocked by the allow/deny
// configuration. Tool names are validated against Anthropic's regex
// (`^[a-zA-Z0-9_-]{1,64}$`) at registration time to fail fast on typos.
func (s *Server) addTool(t server.ServerTool) error {
	name := t.Tool.Name
	if !validToolName(name) {
		return fmt.Errorf("mcp: invalid tool name %q (must match ^[a-zA-Z0-9_-]{1,64}$)", name)
	}
	if _, denied := s.disallowedTools[name]; denied {
		return nil
	}
	if len(s.allowedTools) > 0 {
		if _, ok := s.allowedTools[name]; !ok {
			return nil
		}
	}
	s.mcpSrv.AddTools(t)
	return nil
}

// newClient builds a fresh NetcapClient for the current request.
func (s *Server) newClient() *NetcapClient {
	return NewNetcapClient(s.baseURL)
}

// TokenFingerprint returns the first 8 hex chars of the SHA-256 of the
// admin token, suitable for logging at startup. Empty string when no
// token is configured.
func (s *Server) TokenFingerprint() string {
	if s.adminToken == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(s.adminToken))
	return hex.EncodeToString(sum[:])[:8]
}

// Logger returns the diagnostic logger (mainly for tests).
func (s *Server) Logger() *log.Logger { return s.logger }

func (s *Server) registerAll() error {
	for _, fn := range []func() error{
		s.registerPipelineTools,
		s.registerRecordTools,
		s.registerInventoryTools,
		s.registerFlowTools,
		s.registerProtocolTools,
		s.registerFileTools,
		s.registerThreatTools,
		s.registerActionTools,
		s.registerCarveTools,
	} {
		if err := fn(); err != nil {
			return err
		}
	}
	s.registerResources()
	s.registerPrompts()
	return nil
}

// validToolName mirrors Anthropic's tool-name regex
// `^[a-zA-Z0-9_-]{1,64}$`.
func validToolName(name string) bool {
	if len(name) == 0 || len(name) > 64 {
		return false
	}
	for _, c := range name {
		switch {
		case c >= 'a' && c <= 'z',
			c >= 'A' && c <= 'Z',
			c >= '0' && c <= '9',
			c == '_' || c == '-':
		default:
			return false
		}
	}
	return true
}

func toSet(items []string) map[string]struct{} {
	if len(items) == 0 {
		return nil
	}
	out := make(map[string]struct{}, len(items))
	for _, item := range items {
		item = strings.TrimSpace(item)
		if item != "" {
			out[item] = struct{}{}
		}
	}
	return out
}

// requireSessionID returns the session_id argument or the active session
// fallback when the caller didn't pass one. Returns a SessionRef ready
// for selectSession.
func (s *Server) requireSessionID(req mcplib.CallToolRequest) (SessionRef, error) {
	if id := req.GetString("session_id", ""); id != "" {
		return newSessionRef(id), nil
	}
	if s.activeSession != "" {
		return newSessionRef(s.activeSession), nil
	}
	return SessionRef{}, fmt.Errorf("session_id is required (call ingest_pcap or list_sessions first)")
}

// withSession switches the webui to ref under the session gate and runs
// fn. Use this for every analytical tool handler that reads per-session
// audit records. Errors from selectSession are wrapped with context.
func (s *Server) withSession(client *NetcapClient, ref SessionRef, fn func() error) error {
	return s.gate.run(func() error {
		if err := client.selectSession(ref); err != nil {
			s.logger.Printf("session select failed: %v", err)
			return err
		}
		return fn()
	})
}
