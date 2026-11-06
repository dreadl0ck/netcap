package enforcer

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"slices"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

// MCPMaxRequestBytes bounds each JSON-RPC envelope, including tool arguments.
const MCPMaxRequestBytes = 16 << 10

type leaseRequest struct {
	ID         string `json:"id"`
	Source     string `json:"source"`
	TTLSeconds int64  `json:"ttl_seconds"`
}

type enforcerCapabilities struct {
	Scope           Scope    `json:"scope"`
	DryRun          bool     `json:"dry_run"`
	MaxLeases       int      `json:"max_leases"`
	MaxTTLSeconds   int64    `json:"max_ttl_seconds"`
	ProtectedCIDRs  []string `json:"protected_cidrs"`
	Actions         []string `json:"actions"`
	ScopeMutable    bool     `json:"scope_mutable"`
	GenericCommands bool     `json:"generic_commands"`
}

// mcpHandler is private so the only HTTP entry point is Handler's bearer boundary.
// It never creates an executor or changes scope. NFT ownership still requires the
// canonical shared /run mount documented on NFTBackend, regardless of transport.
func (c *Controller) mcpHandler() http.Handler {
	s := server.NewMCPServer("netcap-enforcer", "1.0.0", server.WithToolCapabilities(false), server.WithInstructions("Manage finite source-address blocks only within the immutable configured scope. No command execution or scope edits. Active lease retries preserve the original expiry."))
	stringSchema := func() map[string]any { return map[string]any{"type": "string"} }
	register := func(name, description string, properties map[string]any, required []string, readOnly bool, handler server.ToolHandlerFunc) {
		schema, _ := json.Marshal(map[string]any{"type": "object", "properties": properties, "required": required, "additionalProperties": false})
		tool := mcp.NewTool(name, mcp.WithDescription(description), mcp.WithReadOnlyHintAnnotation(readOnly), mcp.WithDestructiveHintAnnotation(!readOnly), mcp.WithOpenWorldHintAnnotation(false))
		tool.InputSchema = mcp.ToolInputSchema{}
		tool.RawInputSchema = schema
		s.AddTool(tool, handler)
	}
	register("get_enforcer_capabilities", "Read immutable enforcement scope, dry-run mode, protected CIDRs and limits.", map[string]any{}, []string{}, true, func(_ context.Context, r mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		if err := toolArguments(r, &struct{}{}); err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}
		return mcp.NewToolResultJSON(enforcerCapabilities{c.config.Scope, c.config.DryRun, c.config.MaxLeases, int64(c.config.MaxTTL / time.Second), append([]string{}, c.config.ProtectedCIDRs...), []string{"block_source"}, false, false})
	})
	register("list_action_leases", "List active leases using controller reconciliation; expired/orphaned rules may be cleaned up.", map[string]any{}, []string{}, false, func(ctx context.Context, r mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		if err := toolArguments(r, &struct{}{}); err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}
		ls, err := c.List(ctx)
		if err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}
		return mcp.NewToolResultJSON(map[string]any{"leases": ls})
	})
	register("create_action_lease", "Temporarily block one source IP in the fixed scope. An active matching ID retry preserves expiry; expired IDs can be reused.", map[string]any{"id": map[string]any{"type": "string", "pattern": identifier.String(), "maxLength": 48}, "source": stringSchema(), "ttl_seconds": map[string]any{"type": "integer", "minimum": 1, "maximum": int64(c.config.MaxTTL / time.Second)}}, []string{"id", "source", "ttl_seconds"}, false, func(ctx context.Context, r mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		var req leaseRequest
		if err := toolArguments(r, &req, "id", "source", "ttl_seconds"); err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}
		if req.TTLSeconds < 1 || req.TTLSeconds > int64(HardMaxTTL/time.Second) {
			return mcp.NewToolResultError("invalid TTL"), nil
		}
		l, err := c.Create(ctx, req.ID, req.Source, time.Duration(req.TTLSeconds)*time.Second)
		if err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}
		return mcp.NewToolResultJSON(l)
	})
	register("revoke_action_lease", "Revoke one lease by ID using exact controller deletion; missing IDs are idempotent.", map[string]any{"id": stringSchema()}, []string{"id"}, false, func(ctx context.Context, r mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		var req struct {
			ID string `json:"id"`
		}
		if err := toolArguments(r, &req, "id"); err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}
		if !identifier.MatchString(req.ID) {
			return mcp.NewToolResultError("invalid ID"), nil
		}
		if err := c.Delete(ctx, req.ID); err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}
		return mcp.NewToolResultJSON(map[string]any{"revoked": req.ID})
	})
	transport := server.NewStreamableHTTPServer(s, server.WithStateLess(true), server.WithDisableStreaming(true))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if version := r.Header.Get("MCP-Protocol-Version"); version != "" && !slices.Contains(mcp.ValidProtocolVersions, version) {
			http.Error(w, `{"error":"unsupported MCP version"}`, 400)
			return
		}
		if r.Method == http.MethodPost {
			raw, err := readJSONBody(w, r, MCPMaxRequestBytes)
			if err != nil {
				status := http.StatusBadRequest
				var oversized *http.MaxBytesError
				if errors.As(err, &oversized) {
					status = http.StatusRequestEntityTooLarge
				}
				http.Error(w, `{"error":"invalid, duplicate or oversized JSON request"}`, status)
				return
			}
			if err = validateRPC(raw); err != nil {
				http.Error(w, `{"error":"invalid MCP request fields"}`, 400)
				return
			}
			r.Body = io.NopCloser(bytes.NewReader(raw))
		}
		transport.ServeHTTP(w, r)
	})
}

func toolArguments(r mcp.CallToolRequest, target any, allowed ...string) error {
	args := r.GetRawArguments()
	if args == nil {
		args = map[string]any{}
	}
	raw, err := json.Marshal(args)
	if err != nil {
		return err
	}
	return decodeObject(raw, target, allowed...)
}

func validateRPC(raw []byte) error {
	var request struct {
		JSONRPC string          `json:"jsonrpc"`
		ID      json.RawMessage `json:"id"`
		Method  string          `json:"method"`
		Params  json.RawMessage `json:"params"`
	}
	if err := decodeObject(raw, &request, "jsonrpc", "id", "method", "params"); err != nil {
		return err
	}
	if request.JSONRPC != "2.0" || request.Method == "" {
		return errors.New("invalid JSON-RPC envelope")
	}
	var allowed []string
	switch request.Method {
	case "initialize":
		allowed = []string{"protocolVersion", "capabilities", "clientInfo", "_meta"}
	case "tools/call":
		allowed = []string{"name", "arguments", "_meta"}
	case "tools/list":
		allowed = []string{"cursor", "_meta"}
	case "ping", "notifications/initialized":
		allowed = []string{"_meta"}
	case "notifications/cancelled":
		allowed = []string{"requestId", "reason", "_meta"}
	default:
		return nil // The SDK returns method-not-found; no tool is dispatched.
	}
	if request.Method == "initialize" || request.Method == "tools/call" || request.Method == "tools/list" {
		if len(request.ID) == 0 || bytes.Equal(request.ID, []byte("null")) {
			return errors.New("request ID required")
		}
	}
	if len(request.Params) == 0 {
		request.Params = []byte("{}")
	}
	var params map[string]json.RawMessage
	return decodeObject(request.Params, &params, allowed...)
}
