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
					"Return canonical NVD/MITRE URLs for a CVE id. Does not perform live "+
						"HTTP; the caller should fetch the URL with a separate tool."),
				mcplib.WithString("cve_id",
					mcplib.Description("CVE identifier, e.g. \"CVE-2021-44228\"."),
					mcplib.Required()),
				mcplib.WithReadOnlyHintAnnotation(true),
				mcplib.WithDestructiveHintAnnotation(false),
				mcplib.WithIdempotentHintAnnotation(true),
				mcplib.WithOpenWorldHintAnnotation(false),
			),
			Handler: func(_ context.Context, req mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
				id, err := req.RequireString("cve_id")
				if err != nil {
					return errResult(err), nil
				}
				return jsonResult(map[string]any{
					"cve_id": id,
					"nvd":    fmt.Sprintf("https://nvd.nist.gov/vuln/detail/%s", id),
					"mitre":  fmt.Sprintf("https://cve.mitre.org/cgi-bin/cvename.cgi?name=%s", id),
				}), nil
			},
		},
	}

	for _, t := range tools {
		if err := s.addTool(t); err != nil {
			return err
		}
	}
	return nil
}
