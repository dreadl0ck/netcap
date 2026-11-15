package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/dreadl0ck/netcap/internal/analyst"
	mcplib "github.com/mark3labs/mcp-go/mcp"
)

type protobufChange struct {
	Operation        string `json:"operation" jsonschema:"enum=add-path,enum=remove-path,enum=map-port,enum=unmap-port,enum=preferences,enum=recompile"`
	Path             string `json:"path,omitempty"`
	Port             int    `json:"port,omitempty"`
	MessageType      string `json:"messageType,omitempty"`
	ShowAlternatives *bool  `json:"showAlternatives,omitempty"`
}

func (s *Server) registerProtobufConfiguration() error {
	return s.registerAPITool(apiTool{name: "configure_protobuf", post: true, description: "Manage the complete custom Protobuf configuration lifecycle: add/remove path, map/unmap port, set showAlternatives, or recompile. Read get_protobuf_status afterward. Current configuration is forwarded to subsequent helper analyses and child reanalysis; no existing result is rewritten.", options: []mcplib.ToolOption{wireInputSchema[protobufChange]()}, run: func(ctx context.Context, raw json.RawMessage) (any, error) {
		var r protobufChange
		if err := analyst.DecodeStrict(raw, &r); err != nil {
			return nil, err
		}
		method, path := http.MethodPost, ""
		body := map[string]any{}
		switch r.Operation {
		case "add-path", "remove-path":
			if r.Path == "" {
				return nil, fmt.Errorf("path required")
			}
			path = "/api/proto/search-paths"
			body["path"] = r.Path
			if r.Operation == "remove-path" {
				method = http.MethodDelete
			}
		case "map-port", "unmap-port":
			if r.Port < 1 || r.Port > 65535 {
				return nil, fmt.Errorf("port must be 1..65535")
			}
			path = "/api/proto/mappings"
			body["port"] = r.Port
			if r.Operation == "map-port" {
				if r.MessageType == "" {
					return nil, fmt.Errorf("messageType required")
				}
				body["messageType"] = r.MessageType
			} else {
				method = http.MethodDelete
			}
		case "preferences":
			if r.ShowAlternatives == nil {
				return nil, fmt.Errorf("showAlternatives required")
			}
			path = "/api/proto/preferences"
			body["showAlternatives"] = *r.ShowAlternatives
		case "recompile":
			path = "/api/proto/recompile"
		default:
			return nil, fmt.Errorf("unknown Protobuf operation")
		}
		return s.newClient().jsonContext(ctx, method, path, body)
	}})
}
