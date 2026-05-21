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
						"ingest_pcap in this process. Each entry includes session_id, "+
						"input_file, size, completed status, and any error message."),
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
// input-file enumeration. Returns a uniform shape: each session has
// session_id, input_file, size_bytes, completed, error (optional).
func (s *Server) handleListSessions(_ context.Context, _ mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
	client := s.newClient()

	// Try service mode first.
	if raw, err := client.Get("/api/try/sessions", nil); err == nil {
		var resp struct {
			Sessions []map[string]any `json:"sessions"`
		}
		if jsonErr := json.Unmarshal(raw, &resp); jsonErr == nil && resp.Sessions != nil {
			out := make([]map[string]any, 0, len(resp.Sessions))
			for _, s := range resp.Sessions {
				out = append(out, normaliseServiceSession(s))
			}
			return jsonResult(map[string]any{
				"mode":     "service",
				"sessions": out,
			}), nil
		}
	}

	// Local mode: /api/files/input returns the file list with IsCompleted.
	raw, err := client.Get("/api/files/input", nil)
	if err != nil {
		return errResult(fmt.Errorf("listing input files: %w", err)), nil
	}
	var files []map[string]any
	if jsonErr := json.Unmarshal(raw, &files); jsonErr != nil {
		return errResult(fmt.Errorf("decoding file list: %w", jsonErr)), nil
	}
	out := make([]map[string]any, 0, len(files)+1)
	if s.activeSession != "" {
		// Make the pre-loaded session discoverable even if it hasn't yet
		// shown up in /api/files/input (rare timing case).
		out = append(out, map[string]any{
			"session_id": s.activeSession,
			"source":     "cli-preloaded",
		})
	}
	for _, f := range files {
		out = append(out, normaliseLocalFile(f))
	}
	return jsonResult(map[string]any{
		"mode":     "local",
		"sessions": out,
	}), nil
}

func normaliseServiceSession(s map[string]any) map[string]any {
	out := map[string]any{
		"session_id":   firstString(s, "sessionId", "session_id"),
		"input_file":   firstString(s, "inputFile", "input_file"),
		"input_name":   firstString(s, "inputFilename", "input_name"),
		"size_bytes":   s["inputFileSize"],
		"status":       s["status"],
		"completed":    isCompleted(s["status"], s["resultsReady"]),
		"share_url":    s["shareUrl"],
		"is_preloaded": s["isPreloaded"],
	}
	if errMsg := firstString(s, "errorMessage", "error"); errMsg != "" {
		out["error"] = errMsg
	}
	return out
}

func normaliseLocalFile(f map[string]any) map[string]any {
	out := map[string]any{
		"session_id": firstString(f, "path"),
		"input_name": firstString(f, "name"),
		"size_bytes": f["size"],
		"completed":  isCompleted(nil, f["isCompleted"]),
		"file_id":    firstString(f, "id"),
	}
	if errMsg, ok := f["error"].(string); ok && errMsg != "" {
		out["error"] = errMsg
	} else if errPtr, ok := f["error"].(*string); ok && errPtr != nil {
		out["error"] = *errPtr
	}
	return out
}

func firstString(m map[string]any, keys ...string) string {
	for _, k := range keys {
		if v, ok := m[k].(string); ok && v != "" {
			return v
		}
	}
	return ""
}

func isCompleted(status, resultsReady any) bool {
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
// session's record in /api/files/input.
func (s *Server) handleGetSessionInfo(_ context.Context, req mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
	ref, err := s.requireSessionID(req)
	if err != nil {
		return errResult(err), nil
	}
	client := s.newClient()

	var stats, status, files json.RawMessage
	withErr := s.withSession(client, ref, func() error {
		// audit-stats is the analytical truth; /api/status carries
		// IsProcessing; /api/files/input has IsCompleted per file.
		stats, err = client.Get("/api/audit-stats", nil)
		if err != nil {
			return fmt.Errorf("audit-stats: %w", err)
		}
		status, _ = client.Get("/api/status", nil)
		files, _ = client.Get("/api/files/input", nil)
		return nil
	})
	if withErr != nil {
		return errResult(withErr), nil
	}

	completed := deriveCompleted(ref, files, status)
	out := map[string]any{
		"session_id":   ref.ID,
		"mode_path":    ref.isPath,
		"completed":    completed,
		"audit_stats":  json.RawMessage(stats),
		"capture_stat": json.RawMessage(status),
	}
	return jsonResult(out), nil
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
	client := s.newClient()
	var raw json.RawMessage
	if err := s.withSession(client, ref, func() error {
		body, gErr := client.Get("/api/files/audit", nil)
		raw = body
		return gErr
	}); err != nil {
		return errResult(err), nil
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
