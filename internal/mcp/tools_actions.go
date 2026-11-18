/*
 * NETCAP - Traffic Analysis Framework
 * Copyright (c) Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
 * License: GNU General Public License v3.0
 */

package mcp

import (
	"context"
	"fmt"

	mcplib "github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

// registerActionTools registers tools that trigger side-effects: YARA
// scans and netcap detection-rule execution. Both are synchronous server-
// side (may take seconds to minutes for large sessions) and return inline
// results.
func (s *Server) registerActionTools() error {
	tools := []server.ServerTool{
		simpleSessionTool(s, "list_yara_rules",
			"List YARA rules currently loaded for scanning extracted files.",
			"/api/yara/rules", nil),
		simpleSessionTool(s, "get_yara_status",
			"Return YARA engine status (enabled, rule count, last reload).",
			"/api/yara/status", nil),
		{
			Tool: mcplib.NewTool("execute_yara_scan",
				mcplib.WithDescription(
					"Run all loaded YARA rules against the session's extracted files. "+
						"SYNCHRONOUS: this call blocks until the scan completes (typically "+
						"seconds to a few minutes; HTTP client timeout is 5 min). The "+
						"response contains the full set of matches."),
				mcplib.WithString("session_id", mcplib.Description("Session identifier."), mcplib.Required()),
				mcplib.WithReadOnlyHintAnnotation(false),
				mcplib.WithDestructiveHintAnnotation(false),
				mcplib.WithIdempotentHintAnnotation(true),
				mcplib.WithOpenWorldHintAnnotation(false),
			),
			Handler: s.handleExecuteYaraScan,
		},
		simpleSessionTool(s, "list_alerts",
			"Alerts raised in this session. Use group_id from a grouped result to page every member, with an independent alert-page generation.",
			"/api/alerts", []queryArg{qLimit(500), qOffset(), qSearch(), {Name: "group_id", QueryName: "groupId", Description: "Exact group identifier from list_alerts_grouped."}}),
		simpleSessionTool(s, "list_alerts_grouped",
			"Bounded alert-group summaries with unique-value previews and exact totals. Retrieve full members with list_alerts(group_id). Pagination counts groups; groupCount is the number of groups and totalCount counts underlying alerts.",
			"/api/alerts/grouped", nil),
		simpleSessionTool(s, "get_alert_stats",
			"Summary statistics for alerts in this session.",
			"/api/alerts/stats", nil),
		simpleSessionTool(s, "list_rules",
			"List netcap detection rules available for execution.",
			"/api/rules", nil),
		{
			Tool: mcplib.NewTool("execute_detection_rules",
				mcplib.WithDescription(
					"Execute all enabled netcap detection rules against the session. "+
						"SYNCHRONOUS: blocks until completion. The response includes per-"+
						"rule execution results; new alerts also appear in list_alerts."),
				mcplib.WithString("session_id", mcplib.Description("Session identifier."), mcplib.Required()),
				mcplib.WithReadOnlyHintAnnotation(false),
				mcplib.WithDestructiveHintAnnotation(false),
				mcplib.WithIdempotentHintAnnotation(true),
				mcplib.WithOpenWorldHintAnnotation(false),
			),
			Handler: s.handleExecuteAllRules,
		},
	}
	for _, t := range tools {
		if err := s.addTool(t); err != nil {
			return err
		}
	}
	return nil
}

func (s *Server) handleExecuteYaraScan(ctx context.Context, req mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
	ref, err := s.requireSessionID(req)
	if err != nil {
		return errResult(err), nil
	}
	raw, pErr := s.newClient().PostEmptyContext(ctx, "/api/yara/scan", ref.sessionQueryParams())
	if pErr != nil {
		return errResult(fmt.Errorf("yara scan: %w", pErr)), nil
	}
	if len(raw) == 0 {
		return textResult("YARA scan returned no body. Use list_alerts to inspect any new alerts."), nil
	}
	return rawJSONResult(raw), nil
}

func (s *Server) handleExecuteAllRules(ctx context.Context, req mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
	ref, err := s.requireSessionID(req)
	if err != nil {
		return errResult(err), nil
	}
	raw, pErr := s.newClient().PostEmptyContext(ctx, "/api/rules/execute-all", ref.sessionQueryParams())
	if pErr != nil {
		return errResult(fmt.Errorf("execute rules: %w", pErr)), nil
	}
	if len(raw) == 0 {
		return textResult("Detection rules executed. Use list_alerts to inspect new alerts."), nil
	}
	return rawJSONResult(raw), nil
}
