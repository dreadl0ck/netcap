/*
 * NETCAP - Traffic Analysis Framework
 * Copyright (c) Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
 * License: GNU General Public License v3.0
 */

package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	mcplib "github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

// registerPipelineTools registers tools that drive the ingest/session
// lifecycle: ingest_pcap, list_sessions, get_session_info, list_decoders,
// list_audit_records, reanalyze_session.
func (s *Server) registerPipelineTools() error {
	tools := []server.ServerTool{
		{
			Tool: mcplib.NewTool("ingest_pcap",
				mcplib.WithDescription(
					"Ingest a local PCAP/PCAPNG file into a new netcap analysis session. "+
						"Returns immediately with a session_id; ingest runs asynchronously. "+
						"Poll get_session_info until the session reports completed=true "+
						"before running analytical tools. dpi/bpf/include_decoders/"+
						"exclude_decoders are recorded and may be applied on the next "+
						"reanalyze_session — they are not honoured on initial ingest in v1."),
				mcplib.WithString("path",
					mcplib.Description("Absolute filesystem path of the .pcap or .pcapng file to ingest."),
					mcplib.Required()),
				mcplib.WithBoolean("dpi",
					mcplib.Description("Request DPI on the next reanalyze. Default false.")),
				mcplib.WithString("bpf",
					mcplib.Description("Optional BPF filter to remember for reanalyze (e.g. \"tcp port 443\").")),
				mcplib.WithString("include_decoders",
					mcplib.Description("CSV of decoder names to include exclusively on reanalyze.")),
				mcplib.WithString("exclude_decoders",
					mcplib.Description("CSV of decoder names to exclude on reanalyze.")),
				mcplib.WithReadOnlyHintAnnotation(false),
				mcplib.WithDestructiveHintAnnotation(false),
				mcplib.WithIdempotentHintAnnotation(false),
				mcplib.WithOpenWorldHintAnnotation(false),
			),
			Handler: s.handleIngestPCAP,
		},
		{
			Tool: mcplib.NewTool("list_sessions",
				mcplib.WithDescription(
					"List analysis sessions visible to this server. In service mode this "+
						"returns the operator's session inventory; in CLI mode it returns "+
						"the pre-loaded session (if any) plus everything uploaded via "+
						"ingest_pcap in this process. Response shape is identical across "+
						"modes: every entry has session_id, mode, input_file, input_name, "+
						"size_bytes, completed, status, plus mode-specific fields. "+
						"Use limit/offset to paginate; completed_only filters to ready sessions."),
				mcplib.WithNumber("limit",
					mcplib.Description("Max sessions to return (default 100, max 500)."),
					mcplib.Max(500)),
				mcplib.WithNumber("offset",
					mcplib.Description("Pagination offset.")),
				mcplib.WithString("search",
					mcplib.Description("Case-insensitive substring match against input_name and input_file.")),
				mcplib.WithBoolean("completed_only",
					mcplib.Description("If true, return only sessions whose analysis has completed.")),
				mcplib.WithBoolean("failed_only",
					mcplib.Description("If true, return only sessions in a failed state.")),
				mcplib.WithReadOnlyHintAnnotation(true),
				mcplib.WithDestructiveHintAnnotation(false),
				mcplib.WithIdempotentHintAnnotation(true),
				mcplib.WithOpenWorldHintAnnotation(false),
			),
			Handler: s.handleListSessions,
		},
		{
			Tool: mcplib.NewTool("get_session_info",
				mcplib.WithDescription(
					"Return metadata for one analysis session: completion status, error "+
						"message if any, input filename and size, per-record-type audit "+
						"counts. Use this to poll an in-flight ingest."),
				mcplib.WithString("session_id",
					mcplib.Description("Session identifier returned by ingest_pcap or list_sessions."),
					mcplib.Required()),
				mcplib.WithReadOnlyHintAnnotation(true),
				mcplib.WithDestructiveHintAnnotation(false),
				mcplib.WithIdempotentHintAnnotation(true),
				mcplib.WithOpenWorldHintAnnotation(false),
			),
			Handler: s.handleGetSessionInfo,
		},
		{
			Tool: mcplib.NewTool("list_decoders",
				mcplib.WithDescription(
					"List all available packet and stream decoders, with descriptions. "+
						"Use the names returned here as values for include_decoders / "+
						"exclude_decoders on ingest_pcap and reanalyze_session."),
				mcplib.WithReadOnlyHintAnnotation(true),
				mcplib.WithDestructiveHintAnnotation(false),
				mcplib.WithIdempotentHintAnnotation(true),
				mcplib.WithOpenWorldHintAnnotation(false),
			),
			Handler: s.handleListDecoders,
		},
		{
			Tool: mcplib.NewTool("list_audit_records",
				mcplib.WithDescription(
					"List the audit-record files produced for one session (DNS.ncap.gz, "+
						"HTTP.ncap.gz, Connection.ncap.gz, ...) with their record counts "+
						"and on-disk sizes."),
				mcplib.WithString("session_id",
					mcplib.Description("Session identifier."),
					mcplib.Required()),
				mcplib.WithReadOnlyHintAnnotation(true),
				mcplib.WithDestructiveHintAnnotation(false),
				mcplib.WithIdempotentHintAnnotation(true),
				mcplib.WithOpenWorldHintAnnotation(false),
			),
			Handler: s.handleListAuditRecords,
		},
		{
			Tool: mcplib.NewTool("reanalyze_session",
				mcplib.WithDescription(
					"Re-decode an existing session's PCAP. Server-wide BPF/DPI/decoder "+
						"settings apply (configure them out-of-band before calling). "+
						"Returns immediately; poll get_session_info for completion."),
				mcplib.WithString("session_id",
					mcplib.Description("Session identifier."),
					mcplib.Required()),
				mcplib.WithReadOnlyHintAnnotation(false),
				mcplib.WithDestructiveHintAnnotation(true),
				mcplib.WithIdempotentHintAnnotation(false),
				mcplib.WithOpenWorldHintAnnotation(false),
			),
			Handler: s.handleReanalyzeSession,
		},
	}

	for _, t := range tools {
		if err := s.addTool(t); err != nil {
			return err
		}
	}
	return nil
}

// handleIngestPCAP uploads the PCAP, normalises the heterogeneous
// service/local response shapes into a single shape that always includes
// `session_id`, and tells the LLM how to proceed.
func (s *Server) handleIngestPCAP(_ context.Context, req mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
	path, err := req.RequireString("path")
	if err != nil {
		return errResult(err), nil
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return errResult(fmt.Errorf("resolve path %q: %w", path, err)), nil
	}
	fi, statErr := os.Stat(abs)
	if statErr != nil {
		return errResult(fmt.Errorf("stat %s: %w", abs, statErr)), nil
	}
	if fi.IsDir() {
		return errResult(fmt.Errorf("%s is a directory, expected a PCAP/PCAPNG file", abs)), nil
	}

	s.logger.Printf("ingest_pcap: uploading %s (%d bytes)", abs, fi.Size())
	client := s.newClient()
	raw, err := client.UploadPCAP(abs)
	if err != nil {
		return errResult(fmt.Errorf("uploading pcap %s: %w", abs, err)), nil
	}

	// Both local and service-mode upload handlers return JSON. Parse it
	// and normalise. Service mode returns {sessionId, shareUrl, ...};
	// local mode returns {success, id, filename, path, size}.
	var raw1 map[string]any
	if jsonErr := json.Unmarshal(raw, &raw1); jsonErr != nil {
		return errResult(fmt.Errorf("decoding upload response: %w (body: %s)", jsonErr, truncate(string(raw), 200))), nil
	}
	if upErr, ok := raw1["error"].(string); ok && upErr != "" {
		return errResult(fmt.Errorf("upload rejected: %s", upErr)), nil
	}

	var sessionID string
	if v, ok := raw1["sessionId"].(string); ok && v != "" {
		sessionID = v // service mode
	} else if v, ok := raw1["path"].(string); ok && v != "" {
		sessionID = v // local mode — the input file path
	} else {
		return errResult(fmt.Errorf("upload response missing sessionId/path: %s", truncate(string(raw), 200))), nil
	}

	out := map[string]any{
		"session_id":      sessionID,
		"upload_response": raw1,
		"next_step":       "Call get_session_info with this session_id; poll until completed=true, then use analytical tools.",
	}
	if dpi := req.GetBool("dpi", false); dpi {
		out["dpi_requested"] = true
	}
	if bpf := req.GetString("bpf", ""); bpf != "" {
		out["bpf_requested"] = bpf
	}
	if inc := req.GetString("include_decoders", ""); inc != "" {
		out["include_decoders_requested"] = inc
	}
	if exc := req.GetString("exclude_decoders", ""); exc != "" {
		out["exclude_decoders_requested"] = exc
	}
	return jsonResult(out), nil
}

// handleListSessions tries service-mode first, falls back to local-mode
// input-file enumeration. Returns a uniform shape: every session has the
// same set of base keys so an LLM (or tool consumer) doesn't have to
// branch on `mode`. Filters (search/completed_only/failed_only) and
// pagination (limit/offset) are applied after normalisation.
func (s *Server) handleListSessions(_ context.Context, req mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
	limit := req.GetInt("limit", 100)
	if limit <= 0 {
		limit = 100
	}
	if limit > 500 {
		limit = 500
	}
	offset := req.GetInt("offset", 0)
	if offset < 0 {
		offset = 0
	}
	search := strings.ToLower(strings.TrimSpace(req.GetString("search", "")))
	completedOnly := req.GetBool("completed_only", false)
	failedOnly := req.GetBool("failed_only", false)

	client := s.newClient()
	all, mode, err := s.collectSessions(client)
	if err != nil {
		return errResult(err), nil
	}

	filtered := make([]map[string]any, 0, len(all))
	for _, sess := range all {
		if search != "" && !sessionMatchesSearch(sess, search) {
			continue
		}
		comp, _ := sess["completed"].(bool)
		if completedOnly && !comp {
			continue
		}
		if failedOnly {
			status, _ := sess["status"].(string)
			if !strings.EqualFold(status, "failed") {
				continue
			}
		}
		filtered = append(filtered, sess)
	}

	total := len(filtered)
	end := offset + limit
	if offset > total {
		offset = total
	}
	if end > total {
		end = total
	}
	page := filtered[offset:end]

	return jsonResult(map[string]any{
		"mode":     mode,
		"total":    total,
		"limit":    limit,
		"offset":   offset,
		"returned": len(page),
		"sessions": page,
	}), nil
}

// collectSessions probes service mode first, falling back to local-mode
// file enumeration. Always returns sessions in the unified shape.
func (s *Server) collectSessions(client *NetcapClient) ([]map[string]any, string, error) {
	if raw, err := client.Get("/api/try/sessions", nil); err == nil {
		var resp struct {
			Sessions []map[string]any `json:"sessions"`
		}
		if jsonErr := json.Unmarshal(raw, &resp); jsonErr == nil && resp.Sessions != nil {
			out := make([]map[string]any, 0, len(resp.Sessions))
			for _, sess := range resp.Sessions {
				out = append(out, unifiedSession("service", sess))
			}
			return out, "service", nil
		}
	}

	raw, err := client.Get("/api/files/input", nil)
	if err != nil {
		return nil, "", fmt.Errorf("listing input files: %w", err)
	}
	var files []map[string]any
	if jsonErr := json.Unmarshal(raw, &files); jsonErr != nil {
		return nil, "", fmt.Errorf("decoding file list: %w", jsonErr)
	}
	out := make([]map[string]any, 0, len(files)+1)
	for _, f := range files {
		out = append(out, unifiedSession("local", f))
	}
	if s.activeSession != "" && !sessionsContain(out, s.activeSession) {
		// CLI preload not yet visible in /api/files/input — synthesise a
		// minimal row so the LLM can still call analytical tools.
		out = append(out, unifiedSession("local", map[string]any{
			"path":              s.activeSession,
			"name":              s.activeSession,
			"isCompleted":       false,
			"cli_preloaded_flag": true,
		}))
	}
	return out, "local", nil
}

// unifiedSession converts either a service-mode session envelope or a
// local-mode file row into the single shape MCP clients can rely on.
// Mode-specific fields are preserved under their original names so
// callers that want them aren't blocked.
func unifiedSession(mode string, raw map[string]any) map[string]any {
	out := map[string]any{
		"mode":         mode,
		"session_id":   "",
		"input_file":   "",
		"input_name":   "",
		"size_bytes":   nil,
		"completed":    false,
		"status":       "",
		"is_preloaded": false,
	}
	switch mode {
	case "service":
		sid := firstString(raw, "sessionId", "session_id")
		out["session_id"] = sid
		out["input_file"] = firstString(raw, "inputFile", "input_file")
		out["input_name"] = firstString(raw, "inputFilename", "input_name")
		out["size_bytes"] = raw["inputFileSize"]
		out["status"] = firstString(raw, "status")
		out["completed"] = isCompletedAny(raw["status"], raw["resultsReady"])
		if b, ok := raw["isPreloaded"].(bool); ok {
			out["is_preloaded"] = b
		}
		if v := firstString(raw, "shareUrl"); v != "" {
			out["share_url"] = v
		}
		if msg := firstString(raw, "errorMessage", "error"); msg != "" {
			out["error"] = msg
		}
	case "local":
		path := firstString(raw, "path")
		out["session_id"] = path
		out["input_file"] = path
		out["input_name"] = firstString(raw, "name")
		out["size_bytes"] = raw["size"]
		out["completed"] = isCompletedAny(nil, raw["isCompleted"])
		if out["completed"].(bool) {
			out["status"] = "completed"
		} else {
			out["status"] = "processing"
		}
		if fid := firstString(raw, "id"); fid != "" {
			out["file_id"] = fid
		}
		if msg, ok := raw["error"].(string); ok && msg != "" {
			out["error"] = msg
			out["status"] = "failed"
		}
		if b, ok := raw["cli_preloaded_flag"].(bool); ok && b {
			out["source"] = "cli-preloaded"
		}
	}
	return out
}

func sessionsContain(sessions []map[string]any, id string) bool {
	for _, s := range sessions {
		if sid, _ := s["session_id"].(string); sid == id {
			return true
		}
	}
	return false
}

func sessionMatchesSearch(sess map[string]any, lowerNeedle string) bool {
	if name, _ := sess["input_name"].(string); strings.Contains(strings.ToLower(name), lowerNeedle) {
		return true
	}
	if file, _ := sess["input_file"].(string); strings.Contains(strings.ToLower(file), lowerNeedle) {
		return true
	}
	return false
}

func firstString(m map[string]any, keys ...string) string {
	for _, k := range keys {
		if v, ok := m[k].(string); ok && v != "" {
			return v
		}
	}
	return ""
}

func isCompletedAny(status, resultsReady any) bool {
	if b, ok := resultsReady.(bool); ok && b {
		return true
	}
	if s, ok := status.(string); ok && strings.EqualFold(s, "completed") {
		return true
	}
	return false
}

// handleGetSessionInfo selects the session and bundles together the most
// useful poll-progress endpoints: /api/audit-stats, /api/status, and the
// session's record in /api/files/input. If the session has errored, the
// upstream error message is surfaced verbatim in the response so the LLM
// can react rather than spin forever on completed=false.
func (s *Server) handleGetSessionInfo(_ context.Context, req mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
	ref, err := s.requireSessionID(req)
	if err != nil {
		return errResult(err), nil
	}
	client := s.newClient()
	// audit-stats accepts ?scope=<session id> to scope per-session
	// without mutating the global currentSession. /api/status and
	// /api/files/input are global; /api/files/input is filtered locally
	// by deriveCompleted / extractSessionError below.
	statsQ := ref.sessionQueryParams()
	statsQ.Set("scope", ref.ID)
	stats, sErr := client.Get("/api/audit-stats", statsQ)
	if sErr != nil {
		return errResult(fmt.Errorf("audit-stats: %w", sErr)), nil
	}
	status, _ := client.Get("/api/status", nil)
	files, _ := client.Get("/api/files/input", nil)

	completed := deriveCompleted(ref, files, status)
	out := map[string]any{
		"session_id":   ref.ID,
		"mode_path":    ref.isPath,
		"completed":    completed,
		"audit_stats":  json.RawMessage(stats),
		"capture_stat": json.RawMessage(status),
	}

	// Surface per-file errors (local mode) and session error fields
	// (service mode). The upstream FileInfo JSON has an optional `error`
	// (string pointer) plus `errorLogPath`; in service mode the session
	// envelope also has `errorMessage` and `status`.
	if errMsg, errLog, fStatus, found := extractSessionError(ref, files); found {
		if errMsg != "" {
			out["error"] = errMsg
		}
		if errLog != "" {
			out["error_log_path"] = errLog
		}
		if fStatus != "" {
			out["status"] = fStatus
		}
	}
	return jsonResult(out), nil
}

// extractSessionError walks /api/files/input and pulls out the error
// message, error log path, and status for the matching session row.
// Returns found=true when the row was located (regardless of whether
// it carried an error). For local mode we match by `path`; for service
// mode by `sessionId`.
func extractSessionError(ref SessionRef, files json.RawMessage) (msg, logPath, status string, found bool) {
	if len(files) == 0 {
		return "", "", "", false
	}
	var rows []map[string]any
	if err := json.Unmarshal(files, &rows); err != nil {
		return "", "", "", false
	}
	for _, row := range rows {
		var key string
		if ref.isPath {
			key, _ = row["path"].(string)
		} else {
			key, _ = row["sessionId"].(string)
		}
		if key != ref.ID {
			continue
		}
		found = true
		// `error` may be a string (service envelope) or a pointer-to-
		// string after JSON round-trip; both come through as string here.
		if v, ok := row["error"].(string); ok {
			msg = v
		}
		if v, ok := row["errorLogPath"].(string); ok {
			logPath = v
		}
		if v, ok := row["status"].(string); ok {
			status = v
		}
		break
	}
	return msg, logPath, status, found
}

// deriveCompleted reads /api/files/input + /api/status to figure out
// whether the session is ready for analytical queries. Best-effort:
// returns false when uncertain.
func deriveCompleted(ref SessionRef, files, status json.RawMessage) bool {
	if len(files) > 0 {
		var fl []map[string]any
		if err := json.Unmarshal(files, &fl); err == nil {
			for _, f := range fl {
				if ref.isPath {
					if p, _ := f["path"].(string); p == ref.ID {
						if b, _ := f["isCompleted"].(bool); b {
							return true
						}
					}
				} else {
					if sid, _ := f["sessionId"].(string); sid == ref.ID {
						if b, _ := f["isCompleted"].(bool); b {
							return true
						}
					}
				}
			}
		}
	}
	if len(status) > 0 {
		var st map[string]any
		if err := json.Unmarshal(status, &st); err == nil {
			if processing, _ := st["isProcessing"].(bool); !processing {
				return true
			}
		}
	}
	return false
}

func (s *Server) handleListDecoders(_ context.Context, _ mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
	raw, err := s.newClient().Get("/api/decoders", nil)
	if err != nil {
		return errResult(fmt.Errorf("listing decoders: %w", err)), nil
	}
	return rawJSONResult(raw), nil
}

func (s *Server) handleListAuditRecords(_ context.Context, req mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
	ref, err := s.requireSessionID(req)
	if err != nil {
		return errResult(err), nil
	}
	q := ref.sessionQueryParams()
	// /api/files/audit accepts ?scope=<session-id-or-path> via the
	// shared chart-scope resolver.
	q.Set("scope", ref.ID)
	raw, gErr := s.newClient().Get("/api/files/audit", q)
	if gErr != nil {
		return errResult(fmt.Errorf("files/audit: %w", gErr)), nil
	}
	return rawJSONResult(raw), nil
}

// handleReanalyzeSession POSTs the right JSON shape to /api/reanalyze
// based on whether the session id is a path (local) or a hex id (service).
func (s *Server) handleReanalyzeSession(_ context.Context, req mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
	ref, err := s.requireSessionID(req)
	if err != nil {
		return errResult(err), nil
	}
	body := map[string]string{}
	if ref.isPath {
		body["inputFile"] = ref.ID
	} else {
		body["sessionId"] = ref.ID
	}
	raw, err := s.newClient().PostJSON("/api/reanalyze", body)
	if err != nil {
		return errResult(fmt.Errorf("reanalyze: %w", err)), nil
	}
	if len(raw) == 0 {
		return textResult(fmt.Sprintf("Reanalyze triggered for session %s. Poll get_session_info.", ref.ID)), nil
	}
	return rawJSONResult(raw), nil
}
