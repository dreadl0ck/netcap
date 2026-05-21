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
			"Alerts raised by detection rules, YARA, and other sources in this session.",
			"/api/alerts", []queryArg{qLimit(500), qOffset(), qSearch()}),
		simpleSessionTool(s, "list_alerts_grouped",
			"Alerts grouped by rule/source.",
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

func (s *Server) handleExecuteYaraScan(_ context.Context, req mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
	ref, err := s.requireSessionID(req)
	if err != nil {
		return errResult(err), nil
	}
	client := s.newClient()
	var raw json.RawMessage
	if err := s.withSession(client, ref, func() error {
		body, pErr := client.PostEmpty("/api/yara/scan")
		if pErr != nil {
			return fmt.Errorf("yara scan: %w", pErr)
		}
		raw = body
		return nil
	}); err != nil {
		return errResult(err), nil
	}
	if len(raw) == 0 {
		return textResult("YARA scan returned no body. Use list_alerts to inspect any new alerts."), nil
	}
	return rawJSONResult(raw), nil
}

func (s *Server) handleExecuteAllRules(_ context.Context, req mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
	ref, err := s.requireSessionID(req)
	if err != nil {
		return errResult(err), nil
	}
	client := s.newClient()
	var raw json.RawMessage
	if err := s.withSession(client, ref, func() error {
		body, pErr := client.PostEmpty("/api/rules/execute-all")
		if pErr != nil {
			return fmt.Errorf("execute rules: %w", pErr)
		}
		raw = body
		return nil
	}); err != nil {
		return errResult(err), nil
	}
	if len(raw) == 0 {
		return textResult("Detection rules executed. Use list_alerts to inspect new alerts."), nil
	}
	return rawJSONResult(raw), nil
}
