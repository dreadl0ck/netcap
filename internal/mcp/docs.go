/*
 * NETCAP - Traffic Analysis Framework
 * Copyright (c) Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
 * License: GNU General Public License v3.0
 */

package mcp

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	mcplib "github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

// GenerateToolDocs produces the canonical markdown tool catalogue
// derived from the live registered tool set. The output is intended for
// docs/mcp/tools.md; a CI parity test (TestToolDocsUpToDate) compares
// this to the on-disk file and fails the build if they drift.
//
// The format is stable: tool sections are alphabetical, argument tables
// are emitted in JSON-schema property order. Hand-edit the markdown
// header by passing it as `header`; the body is fully regenerated.
func (s *Server) GenerateToolDocs(header string) string {
	tools := s.mcpSrv.ListTools()
	names := make([]string, 0, len(tools))
	for n := range tools {
		names = append(names, n)
	}
	sort.Strings(names)

	var b strings.Builder
	if header != "" {
		b.WriteString(strings.TrimRight(header, "\n"))
		b.WriteString("\n\n")
	}
	fmt.Fprintf(&b, "## Tool catalogue (%d tools)\n\n", len(names))
	b.WriteString("Auto-generated from the live tool registry. Do not edit by hand; ")
	b.WriteString("run `go test ./internal/mcp/ -run TestToolDocsUpToDate -update` to regenerate.\n\n")

	for _, n := range names {
		writeToolSection(&b, tools[n])
	}
	return b.String()
}

func writeToolSection(b *strings.Builder, t *server.ServerTool) {
	if t == nil {
		return
	}
	fmt.Fprintf(b, "### `%s`\n\n", t.Tool.Name)
	if d := strings.TrimSpace(t.Tool.Description); d != "" {
		b.WriteString(d)
		b.WriteString("\n\n")
	}

	writeAnnotations(b, t.Tool.Annotations)
	writeArguments(b, t.Tool.InputSchema)
	b.WriteString("\n")
}

func writeAnnotations(b *strings.Builder, a mcplib.ToolAnnotation) {
	hints := []string{}
	if v := a.ReadOnlyHint; v != nil && *v {
		hints = append(hints, "read-only")
	}
	if v := a.DestructiveHint; v != nil && *v {
		hints = append(hints, "destructive")
	}
	if v := a.IdempotentHint; v != nil && *v {
		hints = append(hints, "idempotent")
	}
	if v := a.OpenWorldHint; v != nil && *v {
		hints = append(hints, "open-world")
	}
	if len(hints) > 0 {
		fmt.Fprintf(b, "**Hints:** %s\n\n", strings.Join(hints, ", "))
	}
}

func writeArguments(b *strings.Builder, schema mcplib.ToolInputSchema) {
	// mcplib's InputSchema uses Properties as map[string]any; JSON-encode
	// it so we get a stable structural view independent of mcp-go's
	// internal representation.
	raw, err := json.Marshal(schema)
	if err != nil {
		return
	}
	var parsed struct {
		Properties map[string]json.RawMessage `json:"properties"`
		Required   []string                   `json:"required"`
	}
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return
	}
	if len(parsed.Properties) == 0 {
		b.WriteString("**Arguments:** none\n\n")
		return
	}
	requiredSet := make(map[string]bool, len(parsed.Required))
	for _, r := range parsed.Required {
		requiredSet[r] = true
	}
	keys := make([]string, 0, len(parsed.Properties))
	for k := range parsed.Properties {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	b.WriteString("**Arguments:**\n\n")
	b.WriteString("| name | type | required | description |\n")
	b.WriteString("| --- | --- | --- | --- |\n")
	for _, k := range keys {
		var p map[string]any
		_ = json.Unmarshal(parsed.Properties[k], &p)
		typeStr, _ := p["type"].(string)
		desc, _ := p["description"].(string)
		desc = strings.ReplaceAll(desc, "|", "\\|")
		req := ""
		if requiredSet[k] {
			req = "yes"
		}
		fmt.Fprintf(b, "| `%s` | %s | %s | %s |\n", k, typeStr, req, desc)
	}
	b.WriteString("\n")
}
