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

// registerInventoryTools registers tools that enumerate hosts, devices,
// services, and network interfaces. We only register endpoints that
// actually return JSON (not HTML chart blobs from the *_charts.go files);
// for "top N" views the LLM can client-side sort the list_* results.
func (s *Server) registerInventoryTools() error {
	tools := []server.ServerTool{
		simpleSessionTool(s, "list_hosts",
			"List all hosts (IP profiles) seen in the session, with packet and byte counts. "+
				"Sort client-side to obtain a top-talkers view.",
			"/api/hosts", nil),
		simpleSessionTool(s, "list_devices",
			"List all devices (MAC addresses) seen in the session, with vendor lookups.",
			"/api/devices", nil),
		simpleSessionTool(s, "list_services",
			"List all detected services (host+port+banner+product) in the session.",
			"/api/services", nil),
		simpleSessionTool(s, "list_network_interfaces",
			"List the local network interfaces visible to netcap (host-level info, not session-scoped). "+
				"Useful only when running on a machine with NICs (live capture).",
			"/api/network-interfaces", nil),
	}
	for _, t := range tools {
		if err := s.addTool(t); err != nil {
			return err
		}
	}
	return nil
}

// simpleSessionTool builds a ServerTool that takes only session_id (plus
// any extra queryArgs) and forwards to a single GET endpoint. The handler
// runs under the session gate so two concurrent calls don't race on the
// webui's global currentSession.
func simpleSessionTool(s *Server, name, desc, endpoint string, queryArgs []queryArg) server.ServerTool {
	opts := []mcplib.ToolOption{
		mcplib.WithDescription(desc),
		mcplib.WithString("session_id",
			mcplib.Description("Session identifier."),
			mcplib.Required()),
		mcplib.WithReadOnlyHintAnnotation(true),
		mcplib.WithDestructiveHintAnnotation(false),
		mcplib.WithIdempotentHintAnnotation(true),
		mcplib.WithOpenWorldHintAnnotation(false),
	}
	for _, qa := range queryArgs {
		opts = append(opts, qa.toolOption())
	}
	return server.ServerTool{
		Tool: mcplib.NewTool(name, opts...),
		Handler: func(_ context.Context, req mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
			ref, err := s.requireSessionID(req)
			if err != nil {
				return errResult(err), nil
			}
			client := s.newClient()
			var raw json.RawMessage
			err = s.withSession(client, ref, func() error {
				q := buildQuery(req, queryArgs)
				body, gErr := client.Get(endpoint, q)
				if gErr != nil {
					return fmt.Errorf("%s: %w", endpoint, gErr)
				}
				raw = body
				return nil
			})
			if err != nil {
				return errResult(err), nil
			}
			return rawJSONResult(raw), nil
		},
	}
}
