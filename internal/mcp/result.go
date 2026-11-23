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
	"errors"
	"fmt"
	"time"

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
	text := "Error: " + truncate(err.Error(), 4000)
	if after, ok := retryAfter(err); ok {
		text += fmt.Sprintf("; retry_after_ms=%d", max(after.Milliseconds(), 1))
	}
	return &mcp.CallToolResult{
		Content: []mcp.Content{mcp.NewTextContent(text)},
		IsError: true,
	}
}

// busyError is a transient admission refusal; clients should back off and retry.
type busyError struct {
	msg   string
	after time.Duration
}

func (e busyError) Error() string { return e.msg }

// retryAfter reports whether err is transient: a local admission refusal or a
// backend 429/503. Size, storage and validation errors are not retryable.
func retryAfter(err error) (time.Duration, bool) {
	var busy busyError
	if errors.As(err, &busy) {
		return busy.after, true
	}
	var backend *BackendError
	if errors.As(err, &backend) && backend.RetryAfter > 0 {
		return backend.RetryAfter, true
	}
	return 0, false
}

// toolBackendError prefixes a backend diagnostic with the tool name and keeps
// the BackendError reachable for retry classification.
type toolBackendError struct {
	tool    string
	backend *BackendError
}

func (e toolBackendError) Error() string { return e.tool + ": " + e.backend.diagnostic() }
func (e toolBackendError) Unwrap() error { return e.backend }

// textResult returns a plain-text successful CallToolResult.
func textResult(text string) *mcp.CallToolResult {
	return &mcp.CallToolResult{
		Content: []mcp.Content{mcp.NewTextContent(text)},
	}
}

// jsonResult leaves whole-response sizing and artifact fallback to structuredToolResult.
func jsonResult(data any) *mcp.CallToolResult {
	buf, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return errResult(fmt.Errorf("marshalling response: %w", err))
	}
	return &mcp.CallToolResult{
		Content: []mcp.Content{mcp.NewTextContent(string(buf))},
	}
}

// rawJSONResult wraps an already-encoded JSON payload (typically the body
// of an HTTP response from the webui API) as a TextContent without
// re-marshalling. Whole-response sizing happens after structured output is attached.
func rawJSONResult(raw json.RawMessage) *mcp.CallToolResult {
	return &mcp.CallToolResult{
		Content: []mcp.Content{mcp.NewTextContent(string(raw))},
	}
}
