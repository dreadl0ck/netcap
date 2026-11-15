package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	mcplib "github.com/mark3labs/mcp-go/mcp"
)

func (s *Server) registerLiveDeletion() error {
	return s.registerAPITool(apiTool{name: "delete_live_capture", post: true, destructive: true, description: "Delete one completed owned local live capture and its output, freeing the eight-capture capacity. Explicit session_id required; running captures must first be stopped and reach completion. Ordinary uploads and foreign directories are never removed.", options: []mcplib.ToolOption{apiString("session_id", "Owned live capture ID or input selector.", true)}, run: func(ctx context.Context, raw json.RawMessage) (any, error) {
		var request struct {
			SessionID string `json:"session_id"`
		}
		if json.Unmarshal(raw, &request) != nil || strings.TrimSpace(request.SessionID) == "" {
			return nil, fmt.Errorf("explicit live session_id required")
		}
		return s.newClient().jsonContext(ctx, http.MethodDelete, "/api/live-capture?"+newSessionRef(request.SessionID).sessionQueryParams().Encode(), nil)
	}})
}
