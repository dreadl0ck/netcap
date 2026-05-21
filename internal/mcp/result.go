/*
 * NETCAP - Traffic Analysis Framework
 * Copyright (c) Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
 * License: GNU General Public License v3.0
 */

// Package mcp implements a Model Context Protocol server that exposes
// netcap's analytical capabilities as tools, resources, and prompts.
//
// The server is consumed in two deployment modes:
//
//   - "net mcp" CLI subcommand: stdio transport for desktop LLM clients
//     (Claude Desktop, Claude Code, mcp-inspector). PCAP files are ingested
//     locally; an embedded webui.Server is spawned on a loopback port.
//
//   - "net capture --service" HTTP transport at /mcp, protected by a single
//     admin bearer token. Intended for operator access on shared instances
//     (e.g. try.netcap.io). The endpoint is only mounted when a token is
//     configured.
//
// Tool handlers are intentionally thin: they call into the existing webui
// HTTP API over loopback (token-forwarding pattern) so analytical logic
// lives in exactly one place.
package mcp

import (
	"encoding/json"
	"fmt"

	"github.com/mark3labs/mcp-go/mcp"
)

// MaxResponseBytes caps the size of any single tool response body after
// marshalling. Larger payloads are replaced with a short summary that
// instructs the LLM to paginate.
const MaxResponseBytes = 256 * 1024

// errResult wraps a Go error as an MCP CallToolResult with IsError=true.
// This is the canonical way to surface an error to the LLM: returning a
// non-nil Go error from a handler triggers JSON-RPC error semantics which
// most LLM clients render badly.
func errResult(err error) *mcp.CallToolResult {
	return &mcp.CallToolResult{
		Content: []mcp.Content{mcp.NewTextContent("Error: " + err.Error())},
		IsError: true,
	}
}

// textResult returns a plain-text successful CallToolResult.
func textResult(text string) *mcp.CallToolResult {
	return &mcp.CallToolResult{
		Content: []mcp.Content{mcp.NewTextContent(text)},
	}
}

// jsonResult marshals data as pretty JSON and returns it as a single
// TextContent. If the marshalled payload exceeds MaxResponseBytes, a
// summary is returned instead pointing the caller at pagination.
func jsonResult(data any) *mcp.CallToolResult {
	buf, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return errResult(fmt.Errorf("marshalling response: %w", err))
	}
	if len(buf) > MaxResponseBytes {
		return errResult(fmt.Errorf(
			"response too large (%d bytes, max %d); use pagination "+
				"(limit/offset) or a more specific filter",
			len(buf), MaxResponseBytes,
		))
	}
	return &mcp.CallToolResult{
		Content: []mcp.Content{mcp.NewTextContent(string(buf))},
	}
}

// rawJSONResult wraps an already-encoded JSON payload (typically the body
// of an HTTP response from the webui API) as a TextContent without
// re-marshalling. Honors the same size cap as jsonResult.
func rawJSONResult(raw json.RawMessage) *mcp.CallToolResult {
	if len(raw) > MaxResponseBytes {
		return errResult(fmt.Errorf(
			"response too large (%d bytes, max %d); use pagination "+
				"(limit/offset) or a more specific filter",
			len(raw), MaxResponseBytes,
		))
	}
	return &mcp.CallToolResult{
		Content: []mcp.Content{mcp.NewTextContent(string(raw))},
	}
}
