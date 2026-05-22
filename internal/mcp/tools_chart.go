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

	mcplib "github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

// registerChartTool exposes /api/chart/data?format=json — a time-series
// aggregator that's perfect for beacon hunting, DGA detection, and
// general per-field-over-time analytics. It works for any audit record
// type and any numeric/categorical field.
func (s *Server) registerChartTool() error {
	return s.addTool(server.ServerTool{
		Tool: mcplib.NewTool("get_chart_data",
			mcplib.WithDescription(
				"Aggregate one audit-record field as a time series. Useful for "+
					"beacon detection (regular interval connections), DGA hunts, "+
					"or any per-field-over-time analytics. Returns JSON: "+
					"{type, field, interval, data: [{timestamp, value}], count, "+
					"min_value, max_value, avg_value}.\n\n"+
					"Use get_audit_record_fields to discover available fields."),
			mcplib.WithString("session_id",
				mcplib.Description("Session identifier."),
				mcplib.Required()),
			mcplib.WithString("type",
				mcplib.Description("Audit record type name (no NC_ prefix), e.g. \"Connection\"."),
				mcplib.Required()),
			mcplib.WithString("field",
				mcplib.Description("Field to aggregate (numeric or boolean). Use dot notation for "+
					"nested fields, e.g. \"Questions[0].Name\"."),
				mcplib.Required()),
			mcplib.WithString("interval",
				mcplib.Description("Bucket size as a Go duration string (1s, 100ms, 1m, 1h). Default 1s.")),
			mcplib.WithNumber("max_data_points",
				mcplib.Description("Down-sample to this many points. Default 1000, max 10000."),
				mcplib.Max(10000)),
			mcplib.WithReadOnlyHintAnnotation(true),
			mcplib.WithDestructiveHintAnnotation(false),
			mcplib.WithIdempotentHintAnnotation(true),
			mcplib.WithOpenWorldHintAnnotation(false),
		),
		Handler: s.handleChartData,
	})
}

func (s *Server) handleChartData(_ context.Context, req mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
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
	field, err := req.RequireString("field")
	if err != nil {
		return errResult(err), nil
	}
	interval := req.GetString("interval", "1s")
	maxPts := req.GetInt("max_data_points", 1000)
	if maxPts <= 0 {
		maxPts = 1000
	}
	if maxPts > 10000 {
		maxPts = 10000
	}

	q := url.Values{}
	q.Set("type", auditType)
	q.Set("field", field)
	q.Set("interval", interval)
	q.Set("maxDataPoints", fmt.Sprintf("%d", maxPts))
	q.Set("format", "json")

	client := s.newClient()
	var raw json.RawMessage
	if err := s.withSession(client, ref, func() error {
		body, gErr := client.Get("/api/chart/data", q)
		if gErr != nil {
			return fmt.Errorf("chart_data %s.%s: %w", auditType, field, gErr)
		}
		raw = body
		return nil
	}); err != nil {
		return errResult(err), nil
	}
	return rawJSONResult(raw), nil
}
