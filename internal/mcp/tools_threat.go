/*
 * NETCAP - Traffic Analysis Framework
 * Copyright (c) Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
 * License: GNU General Public License v3.0
 */

package mcp

import (
	"context"

	mcplib "github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

func (s *Server) handleLookupCVE(_ context.Context, req mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
	id, err := req.RequireString("cve_id")
	if err != nil {
		return errResult(err), nil
	}
	out, err := s.cve.Lookup(id)
	if err != nil {
		return errResult(err), nil
	}
	return jsonResult(out), nil
}

// registerThreatTools registers software inventory and vulnerability
// lookup tools. Top/breakdown variants come from *_charts.go (HTML) and
// are deliberately omitted; aggregate client-side over the list_* tools.
func (s *Server) registerThreatTools() error {
	tools := []server.ServerTool{
		simpleSessionTool(s, "list_software",
			"Software products detected in the session (vendor/product/version, "+
				"sourced from banners, JA4, user-agents, etc.).",
			"/api/software", []queryArg{qLimit(500), qOffset(), qSearch()}),
		simpleSessionTool(s, "list_vulnerabilities",
			"Vulnerabilities flagged against detected software (CVE matches).",
			"/api/vulnerabilities", []queryArg{qLimit(500), qOffset(), qSearch()}),
		{
			Tool: mcplib.NewTool("lookup_cve",
				mcplib.WithDescription(
					"Fetch the NVD record for a CVE id: description, CVSS v3 score and "+
						"vector, CWE classifications, references. Disabled (returns an "+
						"error) when the server was constructed without AllowNetwork, or "+
						"when NETCAP_MCP_DISABLE_NETWORK=1 in the environment. Results "+
						"are cached in-process for 6h (positive) or 5min (negative)."),
				mcplib.WithString("cve_id",
					mcplib.Description("CVE identifier, e.g. \"CVE-2021-44228\"."),
					mcplib.Required()),
				mcplib.WithReadOnlyHintAnnotation(true),
				mcplib.WithDestructiveHintAnnotation(false),
				mcplib.WithIdempotentHintAnnotation(true),
				mcplib.WithOpenWorldHintAnnotation(true), // talks to NVD
			),
			Handler: s.handleLookupCVE,
		},
	}

	for _, t := range tools {
		if err := s.addTool(t); err != nil {
			return err
		}
	}
	return nil
}
