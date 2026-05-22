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

// registerLiveCaptureTools registers tools that control live capture
// from the MCP layer. We deliberately only expose the read + stop side
// of the live-capture lifecycle; spawning a fresh capture from MCP
// requires CAP_NET_RAW (or root) on the netcap host AND would let an
// LLM run arbitrary BPF on a production interface. That stays out of v1.
//
// list_network_interfaces is already registered by registerInventoryTools;
// here we add get_live_capture_status and stop_live_capture, gated by
// the NETCAP_MCP_ALLOW_LIVE env var (the webui's live-mode flag itself
// is enforced server-side so this is a defence-in-depth gate).
func (s *Server) registerLiveCaptureTools() error {
	tools := []server.ServerTool{
		{
			Tool: mcplib.NewTool("get_live_capture_status",
				mcplib.WithDescription(
					"Report whether the netcap webui is currently in live-capture mode "+
						"(reading from a network interface rather than a finite PCAP file). "+
						"Returns {is_live_mode, is_processing, current_session, ...} from "+
						"the /api/status endpoint."),
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

func (s *Server) handleLiveStatus(_ context.Context, _ mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
	raw, err := s.newClient().Get("/api/status", nil)
	if err != nil {
		return errResult(fmt.Errorf("status: %w", err)), nil
	}
	var st map[string]any
	if jErr := json.Unmarshal(raw, &st); jErr != nil {
		return errResult(fmt.Errorf("decode status: %w", jErr)), nil
	}
	out := map[string]any{
		"is_live_mode":   st["isLiveMode"],
		"is_processing":  st["isProcessing"],
		"current_session": st["sessionId"],
		"active_input":   st["activeInputFile"],
		"server_started": st["serverStarted"],
	}
	return jsonResult(out), nil
}

func (s *Server) handleStopLiveCapture(_ context.Context, _ mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
	raw, err := s.newClient().PostEmpty("/api/stop-capture")
	if err != nil {
		return errResult(fmt.Errorf("stop-capture: %w", err)), nil
	}
	if len(raw) == 0 {
		return textResult("Live capture stop requested."), nil
	}
	return rawJSONResult(raw), nil
}
