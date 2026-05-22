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

// registerFlowTools registers connection-/flow-level analytical tools.
// All the /api/connections/* chart endpoints return HTML so they are
// deliberately omitted; the LLM aggregates over list_connections instead.
func (s *Server) registerFlowTools() error {
	tools := []server.ServerTool{
		simpleSessionTool(s, "list_connections",
			"List all reconstructed connections in the session, with bytes/packets and timing. "+
				"Use search/limit/offset to scope. The LLM can sort by total_size for top talkers.",
			"/api/connections", []queryArg{qLimit(500), qOffset(), qSearch()}),
		simpleSessionTool(s, "get_protocol_hierarchy",
			"Wireshark-style nested protocol hierarchy as JSON: layer counts and bytes.",
			"/api/visualize/protocol-hierarchy", nil),
		{
			Tool: mcplib.NewTool("get_conversation",
				mcplib.WithDescription("Return the detailed conversation (bidirectional flow) for a 4-tuple."),
				mcplib.WithString("session_id", mcplib.Description("Session identifier."), mcplib.Required()),
				mcplib.WithString("src_ip", mcplib.Description("Source IP."), mcplib.Required()),
				mcplib.WithString("src_port", mcplib.Description("Source port."), mcplib.Required()),
				mcplib.WithString("dst_ip", mcplib.Description("Destination IP."), mcplib.Required()),
				mcplib.WithString("dst_port", mcplib.Description("Destination port."), mcplib.Required()),
				mcplib.WithReadOnlyHintAnnotation(true),
				mcplib.WithDestructiveHintAnnotation(false),
				mcplib.WithIdempotentHintAnnotation(true),
				mcplib.WithOpenWorldHintAnnotation(false),
			),
			Handler: s.handleGetConversation,
		},
	}
	for _, t := range tools {
		if err := s.addTool(t); err != nil {
			return err
		}
	}
	return nil
}

func (s *Server) handleGetConversation(_ context.Context, req mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
	ref, err := s.requireSessionID(req)
	if err != nil {
		return errResult(err), nil
	}
	srcIP, err := req.RequireString("src_ip")
	if err != nil {
		return errResult(err), nil
	}
	srcPort, err := req.RequireString("src_port")
	if err != nil {
		return errResult(err), nil
	}
	dstIP, err := req.RequireString("dst_ip")
	if err != nil {
		return errResult(err), nil
	}
	dstPort, err := req.RequireString("dst_port")
	if err != nil {
		return errResult(err), nil
	}

	q := ref.sessionQueryParams()
	q.Set("srcIP", srcIP)
	q.Set("srcPort", srcPort)
	q.Set("dstIP", dstIP)
	q.Set("dstPort", dstPort)

	raw, gErr := s.newClient().Get("/api/connections/conversation", q)
	if gErr != nil {
		return errResult(fmt.Errorf("conversation: %w", gErr)), nil
	}
	return rawJSONResult(raw), nil
}
