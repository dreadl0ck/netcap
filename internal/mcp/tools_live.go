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

// Start and discovery use the strict backend contract in tools_capabilities.go.
func (s *Server) registerLiveCaptureTools() error {
	tools := []server.ServerTool{
		{
			Tool: mcplib.NewTool("get_live_capture_status",
				mcplib.WithDescription("Read owned live-capture completion/error/deadline and backend live state. Optional session_id pins the owned capture. Legacy backend status remains available without a selector."),
				mcplib.WithString("session_id", mcplib.Description("Optional owned capture ID from start_live_capture.")),
				mcplib.WithReadOnlyHintAnnotation(true),
				mcplib.WithDestructiveHintAnnotation(false),
				mcplib.WithIdempotentHintAnnotation(true),
				mcplib.WithOpenWorldHintAnnotation(false),
			),
			Handler: s.handleLiveStatus,
		},
		{
			Tool: mcplib.NewTool("stop_live_capture",
				mcplib.WithDescription(
					"Stop an in-progress live capture on the netcap webui host. "+
						"Returns immediately; ongoing audit-record processing continues "+
						"until the existing buffers drain. No-op (and returns an error) "+
						"if the webui isn't currently in live-capture mode."),
				mcplib.WithString("session_id", mcplib.Description("Owned capture ID; when supplied a different session cannot be stopped.")),
				mcplib.WithReadOnlyHintAnnotation(false),
				mcplib.WithDestructiveHintAnnotation(true),
				mcplib.WithIdempotentHintAnnotation(true),
				mcplib.WithOpenWorldHintAnnotation(false),
			),
			Handler: s.handleStopLiveCapture,
		},
	}
	for _, t := range tools {
		if err := s.addTool(t); err != nil {
			return err
		}
	}
	return nil
}

func (s *Server) handleLiveStatus(ctx context.Context, req mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
	q := newSessionRef(req.GetString("session_id", "")).sessionQueryParams()
	if raw, err := s.newClient().GetContext(ctx, "/api/live-capture", q); err == nil {
		return rawJSONResult(raw), nil
	} else if len(q) > 0 {
		return errResult(err), nil
	}
	raw, err := s.newClient().GetContext(ctx, "/api/status", nil)
	if err != nil {
		return errResult(fmt.Errorf("status: %w", err)), nil
	}
	var st map[string]any
	if err := json.Unmarshal(raw, &st); err != nil {
		return errResult(err), nil
	}
	out := map[string]any{
		"is_live_mode":    st["isLiveMode"],
		"is_processing":   st["isProcessing"],
		"current_session": st["sessionId"],
		"active_input":    st["activeInputFile"],
		"server_started":  st["serverStarted"],
	}
	return jsonResult(out), nil
}

func (s *Server) handleStopLiveCapture(ctx context.Context, req mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
	q := newSessionRef(req.GetString("session_id", "")).sessionQueryParams()
	if _, present := req.GetArguments()["session_id"]; present && len(q) == 0 {
		return errResult(fmt.Errorf("session_id cannot be empty")), nil
	}
	raw, err := s.newClient().PostEmptyContext(ctx, "/api/stop-capture", q)
	if err != nil {
		return errResult(fmt.Errorf("stop-capture: %w", err)), nil
	}
	if len(raw) == 0 {
		return textResult("Live capture stop requested."), nil
	}
	return rawJSONResult(raw), nil
}
