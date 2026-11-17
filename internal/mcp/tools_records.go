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
	"net/url"
	"strconv"
	"strings"

	"github.com/dreadl0ck/netcap/types"

	mcplib "github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

// registerRecordTools registers the generic record-stream tools that
// unlock the full netcap audit-record catalogue (124 record types) via
// the /api/audit/<Type>/{stream,fields,values,meta} endpoints.
func (s *Server) registerRecordTools() error {
	tools := []server.ServerTool{
		{
			Tool: mcplib.NewTool("query_audit_records",
				mcplib.WithDescription(
					"Query one audit-record type from a session (works for ALL ~124 "+
						"netcap record types, not just the ones with dedicated list_* tools). "+
						"Use list_audit_records to discover what's available in the session, "+
						"and get_audit_record_fields to enumerate the queryable fields of a type.\n\n"+
						"Supports the netcap filter-expression language in `filter` (an `expr`-style "+
						"boolean over record fields). limit caps at 500 per call; paginate with offset."),
				mcplib.WithString("session_id",
					mcplib.Description("Session identifier."),
					mcplib.Required()),
				mcplib.WithString("type",
					mcplib.Description("Audit record type without NC_, e.g. DNS, HTTP, Modbus, SMB. Case-insensitive; the canonical name is returned."),
					mcplib.Required()),
				mcplib.WithString("filter",
					mcplib.Description("Optional typed filter expression (Connection: \"SrcPort == '443' && DstIP startsWith '10.'\"; TCP/HTTP ports are numeric). "+
						"Field names are CamelCase as in the proto schema; use get_audit_record_fields to enumerate.")),
				mcplib.WithNumber("limit",
					mcplib.Description("Maximum records to return (default 100, max 500)."),
					mcplib.Max(500)),
				mcplib.WithNumber("offset",
					mcplib.Description("Offset in matching records; also supported with a filter.")),
				mcplib.WithBoolean("count_only",
					mcplib.Description("If true, return only the scanned/matched counts without record bodies.")),
				mcplib.WithBoolean("allow_partial", mcplib.Description("Explicitly query an independently sealed audit stage even if overall analysis failed. The summary always identifies stage coverage, runId and stageGeneration.")),
				mcplib.WithString("run_id", mcplib.Description("Expected capture run generation; required with allow_partial on continuation pages.")),
				mcplib.WithString("stage_generation", mcplib.Description("Stage generation returned by a partial query; required for partial continuation pages.")),
				mcplib.WithString("query_generation", mcplib.Description("Query generation returned in summary.queryGeneration; required for partial continuation pages.")),
				mcplib.WithString("fields", mcplib.Description("Optional comma-separated top-level fields or JSON Pointer paths, e.g. Method,RequestHeader or /RequestHeaders/0/Value. Full values are preserved; oversized records provide a complete JSON artifact readable with read_mcp_artifact.")),
				mcplib.WithReadOnlyHintAnnotation(true),
				mcplib.WithDestructiveHintAnnotation(false),
				mcplib.WithIdempotentHintAnnotation(true),
				mcplib.WithOpenWorldHintAnnotation(false),
			),
			Handler: s.handleQueryAuditRecords,
		},
		{
			Tool: mcplib.NewTool("get_audit_record_fields",
				mcplib.WithDescription(
					"Return the field schema for one audit record type: name, Go-style type "+
						"(string/int/bool/repeated/struct), and whether it's nested. Use the "+
						"returned field names in query_audit_records' filter expressions."),
				mcplib.WithString("type",
					mcplib.Description("Audit record type name without the NC_ prefix, e.g. \"DNS\"."),
					mcplib.Required()),
				mcplib.WithReadOnlyHintAnnotation(true),
				mcplib.WithDestructiveHintAnnotation(false),
				mcplib.WithIdempotentHintAnnotation(true),
				mcplib.WithOpenWorldHintAnnotation(false),
			),
			Handler: s.handleGetAuditRecordFields,
		},
		{
			Tool: mcplib.NewTool("get_audit_record_values",
				mcplib.WithDescription(
					"For one audit record type in a session, return the distinct observed values "+
						"per field (a fast cardinality snapshot — useful before crafting a filter)."),
				mcplib.WithString("session_id",
					mcplib.Description("Session identifier."),
					mcplib.Required()),
				mcplib.WithString("type",
					mcplib.Description("Audit record type name without the NC_ prefix."),
					mcplib.Required()),
				mcplib.WithReadOnlyHintAnnotation(true),
				mcplib.WithDestructiveHintAnnotation(false),
				mcplib.WithIdempotentHintAnnotation(true),
				mcplib.WithOpenWorldHintAnnotation(false),
			),
			Handler: s.handleGetAuditRecordValues,
		},
	}
	for _, t := range tools {
		if err := s.addTool(t); err != nil {
			return err
		}
	}
	return nil
}

func (s *Server) handleQueryAuditRecords(_ context.Context, req mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
	ref, err := s.requireSessionID(req)
	if err != nil {
		return errResult(err), nil
	}
	auditType, err := req.RequireString("type")
	if err != nil {
		return errResult(err), nil
	}
	auditType, err = canonicalAuditTypeName(auditType)
	if err != nil {
		return errResult(err), nil
	}
	limit, err := pageInteger(req, "limit", 100, 1, 500)
	if err != nil {
		return errResult(err), nil
	}
	offset, err := pageInteger(req, "offset", 0, 0, 1000000000)
	if err != nil {
		return errResult(err), nil
	}
	countOnly := req.GetBool("count_only", false)
	filterExpr := req.GetString("filter", "")

	q := ref.sessionQueryParams()
	allowPartial := false
	if run := req.GetString("run_id", ""); run != "" {
		q.Set("runId", run)
	}
	if value, present := req.GetArguments()["allow_partial"]; present {
		allowed, ok := value.(bool)
		if !ok {
			return errResult(fmt.Errorf("allow_partial must be boolean")), nil
		}
		if allowed {
			allowPartial = true
			q.Set("allowPartial", "true")
			if run := req.GetString("run_id", ""); run != "" {
				q.Set("runId", run)
			}
			if generation := req.GetString("stage_generation", ""); generation != "" {
				q.Set("stageGeneration", generation)
			}
			if generation := req.GetString("query_generation", ""); generation != "" {
				q.Set("queryGeneration", generation)
			}
			if offset > 0 && (q.Get("runId") == "" || q.Get("stageGeneration") == "" || q.Get("queryGeneration") == "") {
				return errResult(fmt.Errorf("partial continuation requires run_id, stage_generation and query_generation")), nil
			}
		}
	}
	q.Set("full", "true")
	if fields := req.GetString("fields", ""); fields != "" {
		q.Set("fields", fields)
	}
	if countOnly {
		q.Set("countOnly", "true")
	}
	q.Set("limit", strconv.Itoa(limit))
	if offset > 0 {
		q.Set("offset", strconv.Itoa(offset))
	}
	if filterExpr != "" {
		q.Set("filter", filterExpr)
	}

	client := s.newClient()
	records, completeJSON, terminal, sErr := client.StreamAuditRecords(auditType, q, 32<<20)
	if sErr != nil {
		return errResult(fmt.Errorf("stream %s: %w", auditType, sErr)), nil
	}

	if terminal == "error" {
		var em map[string]any
		_ = json.Unmarshal(completeJSON, &em)
		return errResult(fmt.Errorf("server: %v", em["error"])), nil
	}
	if terminal != "complete" {
		return errResult(fmt.Errorf("audit stream did not complete; no partial success is returned")), nil
	}
	if allowPartial {
		var summary struct {
			Coverage, Stage, RunID, StageGeneration, QueryGeneration string
			PartialAdmission                                         bool
		}
		if err := json.Unmarshal(completeJSON, &summary); err != nil || !summary.PartialAdmission || (summary.Coverage != "partial" && summary.Coverage != "complete") || summary.Stage == "" || summary.RunID == "" || summary.StageGeneration == "" || summary.QueryGeneration == "" {
			return errResult(fmt.Errorf("partial query lacks a sealed stage coverage contract")), nil
		}
		if expected := q.Get("runId"); expected != "" && expected != summary.RunID {
			return errResult(fmt.Errorf("partial query returned a different capture run")), nil
		}
		if expected := q.Get("stageGeneration"); expected != "" && expected != summary.StageGeneration {
			return errResult(fmt.Errorf("partial query returned a different stage generation")), nil
		}
		if expected := q.Get("queryGeneration"); expected != "" && expected != summary.QueryGeneration {
			return errResult(fmt.Errorf("partial query returned a different query generation")), nil
		}
	}
	for i, record := range records {
		records[i], err = s.completeRecordJSON(ref, "query_audit_records:"+auditType, record)
		if err != nil {
			return errResult(err), nil
		}
	}

	out := map[string]any{
		"session_id": ref.ID,
		"type":       auditType,
		"limit":      limit,
		"offset":     offset,
		"terminal":   terminal,
		"count_only": countOnly,
	}
	if filterExpr != "" {
		out["filter"] = filterExpr
	}
	if completeJSON != nil {
		out["summary"] = completeJSON
	}
	if !countOnly {
		out["records"] = records
	}
	out["returned"] = len(records)

	raw, err := json.Marshal(out)
	if err != nil {
		return errResult(err), nil
	}
	return rawJSONResult(raw), nil
}

func (s *Server) handleGetAuditRecordFields(_ context.Context, req mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
	auditType, err := req.RequireString("type")
	if err != nil {
		return errResult(err), nil
	}
	auditType, err = canonicalAuditTypeName(auditType)
	if err != nil {
		return errResult(err), nil
	}
	// /api/audit/<Type>/fields is session-independent (it inspects the
	// proto type), so we don't need to switch session here.
	raw, err := s.newClient().Get("/api/audit/"+url.PathEscape(auditType)+"/fields", nil)
	if err != nil {
		return errResult(fmt.Errorf("fields %s: %w", auditType, err)), nil
	}
	return rawJSONResult(raw), nil
}

func (s *Server) handleGetAuditRecordValues(_ context.Context, req mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
	ref, err := s.requireSessionID(req)
	if err != nil {
		return errResult(err), nil
	}
	auditType, err := req.RequireString("type")
	if err != nil {
		return errResult(err), nil
	}
	auditType, err = canonicalAuditTypeName(auditType)
	if err != nil {
		return errResult(err), nil
	}
	raw, gErr := s.newClient().Get("/api/audit/"+url.PathEscape(auditType)+"/values", ref.sessionQueryParams())
	if gErr != nil {
		return errResult(fmt.Errorf("values %s: %w", auditType, gErr)), nil
	}
	return rawJSONResult(raw), nil
}

// validAuditTypeName enforces a conservative character set on the
// `type` argument so it can be embedded in a URL path without surprises.
// The webui's NC_ enum names are all alphanumeric.
func validAuditTypeName(s string) bool {
	if len(s) == 0 || len(s) > 64 {
		return false
	}
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z',
			r >= 'A' && r <= 'Z',
			r >= '0' && r <= '9',
			r == '_':
		default:
			return false
		}
	}
	return true
}

func canonicalAuditTypeName(name string) (string, error) {
	name = strings.TrimSpace(name)
	if validAuditTypeName(name) {
		for fullName := range types.Type_value {
			canonical := strings.TrimPrefix(fullName, "NC_")
			if strings.EqualFold(name, canonical) {
				return canonical, nil
			}
		}
	}
	return "", fmt.Errorf("unknown audit record type %q; use list_audit_records", name)
}
