package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"

	"github.com/dreadl0ck/netcap/internal/analyst"
	mcplib "github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

func analystTool[T any](s *Server, name, path, description string, readOnly bool) server.ServerTool {
	return server.ServerTool{Tool: mcplib.NewTool(name, mcplib.WithDescription(description), mcplib.WithInputSchema[T](), mcplib.WithReadOnlyHintAnnotation(readOnly), mcplib.WithDestructiveHintAnnotation(false), mcplib.WithOpenWorldHintAnnotation(false)), Handler: func(ctx context.Context, req mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
		data, err := json.Marshal(req.GetArguments())
		if err != nil || len(data) > 256<<10 {
			return errResult(fmt.Errorf("invalid analyst payload bounds")), nil
		}
		var body T
		if err = analyst.DecodeStrict(data, &body); err != nil {
			return errResult(err), nil
		}
		capability, err := s.newClient().GetContext(ctx, "/api/analyst/capabilities", nil)
		if err != nil {
			return errResult(err), nil
		}
		var caps map[string]json.RawMessage
		feature := map[string]string{"/api/analyst/catalogue": "catalogueVersion", "/api/analyst/resolve": "occurrenceVersion", "/api/analyst/occurrences": "occurrenceVersion", "/api/analyst/workspace": "workspaceVersion", "/api/analyst/log-review": "reviewedLogVersion", "/api/analyst/inspect": "inspectionVersion"}[path]
		if json.Unmarshal(capability, &caps) != nil || string(caps["version"]) != "1" || string(caps[feature]) != "1" {
			return errResult(fmt.Errorf("backend analyst contract version 1 required")), nil
		}
		result, err := s.newClient().PostJSONContext(ctx, path, body)
		if err != nil {
			return errResult(err), nil
		}
		return rawJSONResult(result), nil
	}}
}
func (s *Server) registerAnalystTools() error {
	tools := []server.ServerTool{
		{Tool: mcplib.NewTool("get_analyst_capabilities", mcplib.WithDescription("Read analyst contract versions, finite limits, explicit-source policy and supported catalogue field paths. No capture is selected or scanned."), mcplib.WithReadOnlyHintAnnotation(true), mcplib.WithOpenWorldHintAnnotation(false)), Handler: func(ctx context.Context, req mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
			if len(req.GetArguments()) != 0 {
				return errResult(fmt.Errorf("capability lookup takes no arguments")), nil
			}
			data, err := s.newClient().GetContext(ctx, "/api/analyst/capabilities", nil)
			if err != nil {
				return errResult(err), nil
			}
			return rawJSONResult(data), nil
		}},
		analystTool[analyst.CatalogueRequest](s, "query_capture_catalogue", "/api/analyst/catalogue", "Search 1–8 explicitly included bound finalized captures; every matching occurrence retains source/run/file/frame identity. Supported kinds sha256, domain, endpoint IP/socket, allowlisted text. Explicit tcp:// or udp:// endpoints require Connection transport evidence. First source is novelty target, remaining sources baseline. No estate scanning; overflow fails.", true),
		analystTool[analyst.ResolveRequest](s, "resolve_audit_occurrence", "/api/analyst/resolve", "Resolve the exact original content-bound audit occurrence. Stale source, manifest, file or frame bindings fail instead of rebinding an ordinal.", true),
		analystTool[analyst.OccurrencesRequest](s, "list_bound_occurrences", "/api/analyst/occurrences", "List at most 4096 exact occurrence references for one explicitly bound audit type; larger scopes must use catalogue search.", true),
		analystTool[analyst.WorkspaceRequest](s, "analyst_workspace", "/api/analyst/workspace", "Load local saved queries/reports when document is absent. Explicit document saves use expectedRevision CAS; new documents must be draft. Review requires unchanged persisted content and explicit reviewer. No automatic approval.", false),
		analystTool[analyst.LogReviewRequest](s, "review_diagnostic_log", "/api/analyst/log-review", "Preview a finite log-line projection containing only hashes and fixed diagnostic classes, never raw log text. Explicit approve persists the exact unchanged preview. Intended for analyst review before reproduction attachment.", false),
		analystTool[analyst.InspectRequest](s, "inspect_bound_capture", "/api/analyst/inspect", "Bounded original capture metadata, interfaces, exact time bounds, wire/captured bytes, truncation and ordering. Verify the stored source hash against the included run.", true),
	}
	for _, tool := range tools {
		if err := s.addTool(tool); err != nil {
			return err
		}
	}
	return s.addTool(server.ServerTool{Tool: mcplib.NewTool("get_analyst_binding", mcplib.WithDescription("Get explicit registered capture binding for analyst version 1 workflows; diagnostic=true permits failed captures for log review."), mcplib.WithString("sessionId"), mcplib.WithString("inputFile"), mcplib.WithBoolean("diagnostic"), mcplib.WithReadOnlyHintAnnotation(true)), Handler: func(ctx context.Context, req mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
		for key, raw := range req.GetArguments() {
			switch key {
			case "sessionId", "inputFile":
				value, ok := raw.(string)
				if !ok || strings.TrimSpace(value) == "" {
					return errResult(fmt.Errorf("invalid explicit capture selector")), nil
				}
			case "diagnostic":
				if _, ok := raw.(bool); !ok {
					return errResult(fmt.Errorf("diagnostic must be boolean")), nil
				}
			default:
				return errResult(fmt.Errorf("unknown analyst binding argument")), nil
			}
		}
		q := url.Values{}
		for _, key := range []string{"sessionId", "inputFile"} {
			if v := req.GetString(key, ""); v != "" {
				q.Set(key, v)
			}
		}
		if len(q) == 0 {
			return errResult(fmt.Errorf("explicit capture inclusion required")), nil
		}
		if req.GetBool("diagnostic", false) {
			q.Set("diagnostic", "true")
		}
		data, err := s.newClient().GetContext(ctx, "/api/analyst/binding", q)
		if err != nil {
			return errResult(err), nil
		}
		return rawJSONResult(data), nil
	}})
}
