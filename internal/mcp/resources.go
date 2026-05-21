/*
 * NETCAP - Traffic Analysis Framework
 * Copyright (c) Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
 * License: GNU General Public License v3.0
 */

package mcp

import (
	"context"
	"fmt"
	"strings"

	mcplib "github.com/mark3labs/mcp-go/mcp"
)

// registerResources exposes a small set of MCP resources for clients that
// prefer the resource API to tool calls.
func (s *Server) registerResources() {
	s.mcpSrv.AddResource(
		mcplib.NewResource(
			"netcap://decoders/all",
			"All netcap decoders",
			mcplib.WithResourceDescription(
				"List of packet and stream decoders with descriptions. "+
					"Equivalent to the list_decoders tool."),
			mcplib.WithMIMEType("application/json"),
		),
		s.handleDecodersResource,
	)

	if s.activeSession != "" {
		s.mcpSrv.AddResource(
			mcplib.NewResource(
				"netcap://session/active",
				"Active CLI session",
				mcplib.WithResourceDescription(
					"Identifier of the session pre-loaded via `net mcp --pcap`."),
				mcplib.WithMIMEType("application/json"),
			),
			s.handleActiveSessionResource,
		)
	}

	s.mcpSrv.AddResourceTemplate(
		mcplib.NewResourceTemplate(
			"netcap://session/{session_id}/summary",
			"Session triage summary",
			mcplib.WithTemplateDescription(
				"Per-session audit-record counts and capture status. "+
					"URI template: replace {session_id} with a session id."),
			mcplib.WithTemplateMIMEType("application/json"),
		),
		s.handleSessionSummaryResource,
	)
}

func (s *Server) handleDecodersResource(_ context.Context, _ mcplib.ReadResourceRequest) ([]mcplib.ResourceContents, error) {
	raw, err := s.newClient().Get("/api/decoders", nil)
	if err != nil {
		return nil, fmt.Errorf("decoders resource: %w", err)
	}
	return []mcplib.ResourceContents{
		mcplib.TextResourceContents{
			URI:      "netcap://decoders/all",
			MIMEType: "application/json",
			Text:     string(raw),
		},
	}, nil
}

func (s *Server) handleActiveSessionResource(_ context.Context, _ mcplib.ReadResourceRequest) ([]mcplib.ResourceContents, error) {
	return []mcplib.ResourceContents{
		mcplib.TextResourceContents{
			URI:      "netcap://session/active",
			MIMEType: "application/json",
			Text:     fmt.Sprintf(`{"session_id": %q}`, s.activeSession),
		},
	}, nil
}

func (s *Server) handleSessionSummaryResource(_ context.Context, req mcplib.ReadResourceRequest) ([]mcplib.ResourceContents, error) {
	// URI templates are not auto-bound by mcp-go at this version; parse by hand.
	uri := req.Params.URI
	const prefix = "netcap://session/"
	const suffix = "/summary"
	if !strings.HasPrefix(uri, prefix) || !strings.HasSuffix(uri, suffix) {
		return nil, fmt.Errorf("unexpected resource URI: %s", uri)
	}
	sessionID := strings.TrimSuffix(strings.TrimPrefix(uri, prefix), suffix)
	if sessionID == "" {
		return nil, fmt.Errorf("missing session_id in resource URI %s", uri)
	}

	client := s.newClient()
	ref := newSessionRef(sessionID)
	var raw []byte
	err := s.withSession(client, ref, func() error {
		body, gErr := client.Get("/api/audit-stats", nil)
		if gErr != nil {
			return fmt.Errorf("audit-stats: %w", gErr)
		}
		raw = body
		return nil
	})
	if err != nil {
		return nil, err
	}
	return []mcplib.ResourceContents{
		mcplib.TextResourceContents{
			URI:      uri,
			MIMEType: "application/json",
			Text:     string(raw),
		},
	}, nil
}
