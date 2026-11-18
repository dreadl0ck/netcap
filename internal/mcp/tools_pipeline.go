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
						"before running analytical tools. Configure future analyses with set_bpf_config, set_decoder_config and set_feature first. Legacy per-ingest options are rejected because the upload API cannot honor them."),
				mcplib.WithString("path",
					mcplib.Description("Absolute filesystem path of the .pcap or .pcapng file to ingest."),
					mcplib.Required()),
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
						"counts and capture_provenance (runId/inputSHA256) when available. Missing provenance has an explicit error field. Use this to poll ingest or child analysis."),
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
						"Use the names returned here as includeDecoders / excludeDecoders "+
						"on set_decoder_config before ingest_pcap or reanalyze_session."),
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
					"Create a separately retained child analysis; parent results remain available. Server-wide BPF/DPI/decoder "+
						"settings apply (use set_bpf_config, set_decoder_config and set_feature before calling). "+
						"Optional bounded BPF/time subsets require run_id and source_sha256 from parent provenance. Poll get_session_info with the returned child ID."),
				mcplib.WithString("session_id",
					mcplib.Description("Session identifier."),
					mcplib.Required()),
				mcplib.WithString("run_id", mcplib.Description("Expected parent capture runId; required for subsets.")),
				mcplib.WithString("source_sha256", mcplib.Description("Parent inputSHA256; required for subsets.")),
				mcplib.WithString("selection_bpf", mcplib.Description("BPF for the retained child input, e.g. host 192.0.2.10 and tcp port 9243.")),
				mcplib.WithString("start_ns", mcplib.Description("Inclusive start capture timestamp as an exact decimal nanosecond string; requires end_ns.")),
				mcplib.WithString("end_ns", mcplib.Description("Inclusive end capture timestamp as an exact decimal nanosecond string; requires start_ns.")),
				mcplib.WithNumber("max_packets", mcplib.Description("Subset packet limit, at most 1000000.")),
				mcplib.WithString("max_output_bytes", mcplib.Description("Subset output-byte limit as a decimal string; default 268435456, maximum 1073741824.")),
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
func (s *Server) handleIngestPCAP(ctx context.Context, req mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
	for key := range req.GetArguments() {
		if key != "path" {
			return errResult(fmt.Errorf("per-ingest option %q is unsupported; configure future analyses before ingest using set_bpf_config, set_decoder_config or set_feature (DPI is a net mcp startup setting)", key)), nil
		}
	}
	path, err := req.RequireString("path")
	if err != nil {
		return errResult(err), nil
	}
	if strings.TrimSpace(path) == "" || !filepath.IsAbs(path) {
		return errResult(fmt.Errorf("path must be an absolute PCAP/PCAPNG file path")), nil
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
	raw, err := client.UploadPCAPContext(ctx, abs)
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
		"session_id":           sessionID,
		"summary_resource_uri": sessionResourceURI(sessionID, "summary"),
		"graph_resource_uri":   sessionResourceURI(sessionID, "graph"),
		"upload_response":      raw1,
		"next_step":            "Call get_session_info with this session_id; poll until completed=true, then use analytical tools.",
	}
	return jsonResult(out), nil
}

// handleListSessions tries service-mode first, falls back to local-mode
// input-file enumeration. Returns a uniform shape: every session has the
// same set of base keys so an LLM (or tool consumer) doesn't have to
// branch on `mode`. Filters (search/completed_only/failed_only) and
// pagination (limit/offset) are applied after normalisation.
func (s *Server) handleListSessions(_ context.Context, req mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
	limit, err := pageInteger(req, "limit", 100, 1, 500)
	if err != nil {
		return errResult(err), nil
	}
	offset, err := pageInteger(req, "offset", 0, 0, 1000000000)
	if err != nil {
		return errResult(err), nil
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
	start := min(offset, total)
	end := min(start+limit, total)
	page := filtered[start:end]

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
	if resp, err := client.GetAs[struct {
		Sessions []map[string]any `json:"sessions"`
	}]("/api/try/sessions", nil); err == nil && resp.Sessions != nil {
		out := make([]map[string]any, 0, len(resp.Sessions))
		for _, sess := range resp.Sessions {
			out = append(out, unifiedSession("service", sess))
		}
		return out, "service", nil
	}

	files, err := client.GetAs[[]map[string]any]("/api/files/input", nil)
	if err != nil {
		return nil, "", fmt.Errorf("listing input files: %w", err)
	}
	out := make([]map[string]any, 0, len(files)+1)
	for _, f := range files {
		out = append(out, unifiedSession("local", f))
	}
	if s.activeSession != "" && !sessionsContain(out, s.activeSession) {
		// CLI preload not yet visible in /api/files/input — synthesise a
		// minimal row so the LLM can still call analytical tools.
		out = append(out, unifiedSession("local", map[string]any{
			"path":               s.activeSession,
			"name":               s.activeSession,
			"isCompleted":        false,
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
		if id := firstString(raw, "sessionId"); id != "" {
			out["session_id"] = id
		}
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
	if id, _ := out["session_id"].(string); id != "" {
		out["summary_resource_uri"] = sessionResourceURI(id, "summary")
		out["graph_resource_uri"] = sessionResourceURI(id, "graph")
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
	stats, sErr := client.Get("/api/audit-stats", statsQ)
	if sErr != nil {
		return errResult(fmt.Errorf("audit-stats: %w", sErr)), nil
	}
	files, filesErr := client.Get("/api/files/input", nil)
	if filesErr != nil {
		return errResult(filesErr), nil
	}

	completed := deriveCompleted(ref, files, nil)
	if completed {
		stats, sErr = client.Get("/api/audit-stats", statsQ)
		if sErr != nil {
			return errResult(fmt.Errorf("audit-stats: %w", sErr)), nil
		}
	}
	out := map[string]any{
		"session_id":   ref.ID,
		"mode_path":    ref.isPath,
		"completed":    completed,
		"audit_stats":  json.RawMessage(stats),
		"capture_stat": map[string]any{"sessionId": ref.ID, "isProcessing": !completed},
	}
	provenance, provenanceErr := client.Get("/api/investigation/capture", ref.sessionQueryParams())
	if provenanceErr != nil {
		out["capture_provenance_error"] = provenanceErr.Error()
	} else if !json.Valid(provenance) || string(provenance) == "null" {
		out["capture_provenance_error"] = "Capture provenance is unavailable"
	} else {
		var manifest map[string]json.RawMessage
		if err := json.Unmarshal(provenance, &manifest); err != nil {
			return errResult(err), nil
		}
		summary := make(map[string]json.RawMessage)
		for _, key := range []string{"runId", "status", "inputSHA256", "inputSize", "inputPath", "version", "startedAt", "finishedAt", "parentRunId", "parentInputSHA256"} {
			if value := manifest[key]; len(value) > 0 && len(value) < 4096 {
				summary[key] = value
			}
		}
		out["capture_provenance"] = summary
		out["capture_provenance_details"] = "get_capture_evidence provides the full manifest or a complete paged JSON artifact"
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
	result := jsonResult(out)
	if message, _ := out["error"].(string); message != "" {
		result.IsError = true
	}
	return result, nil
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
			if key == "" {
				key, _ = row["id"].(string)
			}
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
		if strings.EqualFold(status, "failed") && msg == "" {
			msg = "Analysis failed"
		}
		break
	}
	return msg, logPath, status, found
}

// deriveCompleted reads /api/files/input + /api/status to figure out
// whether the session is ready for analytical queries. Best-effort:
// returns false when uncertain.
func deriveCompleted(ref SessionRef, files, _ json.RawMessage) bool {
	if len(files) > 0 {
		var fl []map[string]any
		if err := json.Unmarshal(files, &fl); err == nil {
			for _, f := range fl {
				if ref.isPath {
					if p, _ := f["path"].(string); p == ref.ID {
						if firstString(f, "error", "errorMessage") != "" || strings.EqualFold(firstString(f, "status"), "failed") {
							return false
						}
						b, _ := f["isCompleted"].(bool)
						return b
					}
				} else {
					sid, _ := f["sessionId"].(string)
					if sid == "" {
						sid, _ = f["id"].(string)
					}
					if sid == ref.ID {
						if firstString(f, "error", "errorMessage") != "" || strings.EqualFold(firstString(f, "status"), "failed") {
							return false
						}
						b, _ := f["isCompleted"].(bool)
						return b
					}
				}
			}
			// Idle does not imply success for failed, unknown, or unqueued files.
			if len(fl) > 0 {
				return false
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

func (s *Server) handleListAuditRecords(ctx context.Context, req mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
	ref, err := s.requireSessionID(req)
	if err != nil {
		return errResult(err), nil
	}
	q := ref.sessionQueryParams()
	raw, gErr := s.newClient().GetContext(ctx, "/api/files/audit", q)
	if gErr != nil {
		return errResult(fmt.Errorf("files/audit: %w", gErr)), nil
	}
	return rawJSONResult(raw), nil
}

// handleReanalyzeSession POSTs the right JSON shape to /api/reanalyze
// based on whether the session id is a path (local) or a hex id (service).
func (s *Server) handleReanalyzeSession(ctx context.Context, req mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
	allowed := map[string]bool{"session_id": true, "run_id": true, "source_sha256": true, "selection_bpf": true, "start_ns": true, "end_ns": true, "max_packets": true, "max_output_bytes": true}
	for name := range req.GetArguments() {
		if !allowed[name] {
			return errResult(fmt.Errorf("unknown reanalysis argument %q", name)), nil
		}
	}
	ref, err := s.requireSessionID(req)
	if err != nil {
		return errResult(err), nil
	}
	client := s.newClient()
	var capabilities struct {
		ChildAnalysisVersion int `json:"childAnalysisVersion"`
	}
	status, err := client.GetContext(ctx, "/api/status", nil)
	if err != nil || json.Unmarshal(status, &capabilities) != nil || capabilities.ChildAnalysisVersion != 1 {
		return errResult(fmt.Errorf("backend does not advertise version 1 child analysis")), nil
	}
	body := map[string]any{}
	if ref.isPath {
		body["inputFile"] = ref.ID
	} else {
		body["sessionId"] = ref.ID
	}
	if run := req.GetString("run_id", ""); run != "" {
		body["runId"] = run
	}
	selection := map[string]any{"version": 1}
	for from, to := range map[string]string{"source_sha256": "sourceSHA256", "selection_bpf": "bpf", "start_ns": "startNs", "end_ns": "endNs", "max_packets": "maxPackets", "max_output_bytes": "maxOutputBytes"} {
		if value, exists := req.GetArguments()[from]; exists {
			selection[to] = value
		}
	}
	if len(selection) > 1 {
		body["selection"] = selection
	}
	raw, err := client.PostJSONContext(ctx, "/api/reanalyze", body)
	if err != nil {
		return errResult(fmt.Errorf("reanalyze: %w", err)), nil
	}
	var child struct {
		Success   bool   `json:"success"`
		SessionID string `json:"sessionId"`
		Path      string `json:"path"`
	}
	if json.Unmarshal(raw, &child) != nil || !child.Success || (child.SessionID == "" && child.Path == "") {
		return errResult(fmt.Errorf("backend did not confirm a child analysis identity")), nil
	}
	return rawJSONResult(raw), nil
}
