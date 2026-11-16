package mcp

import (
	"encoding/json"
	"fmt"
	"strings"

	mcplib "github.com/mark3labs/mcp-go/mcp"
)

func toolOutputSchema(name string) json.RawMessage {
	properties := map[string]any{
		"text": map[string]any{"type": "string"}, "data": map[string]any{},
		"artifact_id": map[string]any{"type": "string"}, "sha256": map[string]any{"type": "string"},
		"size_bytes": map[string]any{"type": "integer", "minimum": 0},
	}
	if key := pagedCollectionKeys[name]; key != "" {
		properties[key] = map[string]any{"type": "array", "items": map[string]any{"type": "object"}}
		for _, field := range []string{"totalCount", "returned", "offset", "next_offset", "limit"} {
			properties[field] = map[string]any{"type": "integer", "minimum": 0}
		}
		properties["generation"] = map[string]any{"type": "string"}
		properties["has_more"] = map[string]any{"type": "boolean"}
	}
	if name == "query_audit_records" {
		properties["records"] = map[string]any{"type": "array", "items": map[string]any{"type": "object"}}
		properties["summary"] = map[string]any{"type": "object"}
		properties["returned"] = map[string]any{"type": "integer", "minimum": 0}
	}
	if name == "get_session_info" || name == "wait_for_session" {
		properties["completed"] = map[string]any{"type": "boolean"}
	}
	raw, _ := json.Marshal(map[string]any{"type": "object", "properties": properties, "additionalProperties": true, "description": "Successful structured result. Object fields remain native; arrays/scalars use data and plain text uses text. Oversized results provide a complete session-bound JSON artifact readable with read_mcp_artifact."})
	return raw
}

func (s *Server) structuredToolResult(req mcplib.CallToolRequest, name string, result *mcplib.CallToolResult) *mcplib.CallToolResult {
	if result == nil || result.IsError {
		return result
	}
	payload := result.RawStructuredContent
	if len(payload) == 0 && result.StructuredContent != nil {
		payload, _ = json.Marshal(result.StructuredContent)
	}
	if len(payload) == 0 {
		var text strings.Builder
		textOnly := true
		for _, content := range result.Content {
			value, ok := content.(mcplib.TextContent)
			if !ok {
				textOnly = false
				break
			}
			text.WriteString(value.Text)
		}
		if textOnly && json.Valid([]byte(text.String())) {
			payload = json.RawMessage(text.String())
		} else if textOnly {
			payload, _ = json.Marshal(map[string]any{"text": text.String()})
		} else {
			payload, _ = json.Marshal(map[string]any{"content": result.Content})
		}
	}
	trimmed := strings.TrimSpace(string(payload))
	if !strings.HasPrefix(trimmed, "{") {
		payload, _ = json.Marshal(map[string]any{"data": json.RawMessage(payload)})
	}
	result.RawStructuredContent = payload
	result.StructuredContent = nil
	wire, err := json.Marshal(result)
	if err != nil {
		return errResult(err)
	}
	if len(wire) <= MaxResponseBytes {
		return result
	}
	if len(payload) > 16<<20 {
		return errResult(fmt.Errorf("structured result exceeds 16 MiB; select smaller fields"))
	}
	ref, _ := s.requireSessionID(req)
	entry, uri, err := s.carve.PutTyped(ref.ID, "tool-result", name, "application/json", payload)
	if err != nil {
		return errResult(err)
	}
	metadata := map[string]any{"_oversized": true, "artifact_id": entry.ID, "resource_uri": uri, "size_bytes": entry.SizeBytes, "sha256": entry.SHA256, "next_step": "Read the complete structured JSON with read_mcp_artifact, using the original session_id for session-derived results."}
	raw, _ := json.Marshal(metadata)
	return &mcplib.CallToolResult{Content: []mcplib.Content{mcplib.NewTextContent(string(raw))}, RawStructuredContent: raw}
}
