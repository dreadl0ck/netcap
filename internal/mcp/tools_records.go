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
					mcplib.Description("Audit record type name without the NC_ prefix, e.g. \"DNS\", \"HTTP\", \"Modbus\", \"SMB\". Case-sensitive."),
					mcplib.Required()),
				mcplib.WithString("filter",
					mcplib.Description("Optional filter expression (e.g. \"SrcPort == 443 && DstIP startsWith '10.'\"). "+
						"Field names are CamelCase as in the proto schema; use get_audit_record_fields to enumerate.")),
				mcplib.WithNumber("limit",
					mcplib.Description("Maximum records to return (default 100, max 500)."),
					mcplib.Max(500)),
				mcplib.WithNumber("offset",
					mcplib.Description("Pagination offset (only honoured when filter is empty).")),
				mcplib.WithBoolean("count_only",
					mcplib.Description("If true, return only the scanned/matched counts without record bodies.")),
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
	if !validAuditTypeName(auditType) {
		return errResult(fmt.Errorf("invalid audit type %q (must be a NetCAP record type name like \"DNS\")", auditType)), nil
	}
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
	countOnly := req.GetBool("count_only", false)
	filterExpr := req.GetString("filter", "")

	q := url.Values{}
	q.Set("limit", strconv.Itoa(limit))
	if offset > 0 {
		q.Set("offset", strconv.Itoa(offset))
	}
	if filterExpr != "" {
		q.Set("filter", filterExpr)
	}

	client := s.newClient()
	var (
		records      []json.RawMessage
		completeJSON json.RawMessage
		terminal     string
	)
	if gateErr := s.withSession(client, ref, func() error {
		recs, comp, term, sErr := client.StreamAuditRecords(auditType, q, 8<<20)
		if sErr != nil {
			return fmt.Errorf("stream %s: %w", auditType, sErr)
		}
		records = recs
		completeJSON = comp
		terminal = term
		return nil
	}); gateErr != nil {
		return errResult(gateErr), nil
	}

	if terminal == "error" {
		var em map[string]any
		_ = json.Unmarshal(completeJSON, &em)
		return errResult(fmt.Errorf("server: %v", em["error"])), nil
	}

	out := map[string]any{
		"session_id": ref.ID,
		"type":       auditType,
		"limit":      limit,
		"offset":     offset,
		"terminal":   terminal,
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

	return jsonResult(out), nil
}

func (s *Server) handleGetAuditRecordFields(_ context.Context, req mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
	auditType, err := req.RequireString("type")
	if err != nil {
		return errResult(err), nil
	}
	if !validAuditTypeName(auditType) {
		return errResult(fmt.Errorf("invalid audit type %q", auditType)), nil
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
	if !validAuditTypeName(auditType) {
		return errResult(fmt.Errorf("invalid audit type %q", auditType)), nil
	}
	client := s.newClient()
	var raw json.RawMessage
	if err := s.withSession(client, ref, func() error {
		body, gErr := client.Get("/api/audit/"+url.PathEscape(auditType)+"/values", nil)
		if gErr != nil {
			return fmt.Errorf("values %s: %w", auditType, gErr)
		}
		raw = body
		return nil
	}); err != nil {
		return errResult(err), nil
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
