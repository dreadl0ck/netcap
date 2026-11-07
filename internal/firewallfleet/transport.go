package firewallfleet

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/dreadl0ck/netcap/internal/firewallstate"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

type tokenContext struct{}
type descriptor struct {
	op               string
	fields, required []string
}

var descriptors = []descriptor{
	{"capabilities", []string{"scope"}, nil},
	{"status", []string{"scope"}, nil},
	{"audit", []string{"scope"}, nil},
	{"stage", []string{"scope", "bundle"}, []string{"bundle"}},
	{"rollout", []string{"scope", "id", "revision", "targets", "canary", "expected", "deadline", "rollback_on_failure"}, []string{"id", "revision", "targets", "expected", "deadline"}},
	{"activate", []string{"scope", "id", "expected_phase"}, []string{"id", "expected_phase"}},
	{"promote", []string{"scope", "id", "expected_phase"}, []string{"id", "expected_phase"}},
	{"rollback", []string{"scope", "id", "expected_phase"}, []string{"id", "expected_phase"}},
	{"drain", []string{"scope", "targets", "expected"}, []string{"targets", "expected"}},
	{"revoke", []string{"scope", "targets", "expected"}, []string{"targets", "expected"}},
	{"resume", []string{"scope", "targets", "expected"}, []string{"targets", "expected"}},
}

func descriptorFor(op string) (descriptor, bool) {
	for _, d := range descriptors {
		if d.op == op {
			return d, true
		}
	}
	return descriptor{}, false
}
func decodeOperation(op string, raw []byte) (Request, error) {
	d, ok := descriptorFor(op)
	if !ok {
		return Request{}, firewallstate.Fail(404, "unknown operation")
	}
	var fields map[string]json.RawMessage
	var r Request
	if len(raw) > MaxRequestBytes || firewallstate.Decode(raw, &fields) != nil || fields == nil {
		return r, firewallstate.Fail(400, "invalid request JSON")
	}
	allowed := map[string]bool{}
	for _, f := range d.fields {
		allowed[f] = true
	}
	for f := range fields {
		if !allowed[f] {
			return r, firewallstate.Fail(400, "unexpected operation field")
		}
	}
	for _, f := range d.required {
		if _, ok := fields[f]; !ok {
			return r, firewallstate.Fail(400, "missing "+f)
		}
	}
	if err := firewallstate.Decode(raw, &r); err != nil {
		return r, firewallstate.Fail(400, "invalid operation arguments")
	}
	return r, nil
}

// Handler includes authenticated REST and streamable MCP. Serve with TLS for
// remote peers and http.Server ReadHeaderTimeout/ReadTimeout/WriteTimeout set.
// Desired and ack never read tenant, app, or target ID from caller input.
func (s *Service) Handler() http.Handler {
	mcpHandler := server.NewStreamableHTTPServer(s.newMCP(), server.WithStateLess(true), server.WithDisableStreaming(true))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		token := firewallstate.Bearer(r)
		isTarget := r.URL.Path == "/api/v1/fleet/desired" || r.URL.Path == "/api/v1/fleet/ack"
		if isTarget {
			if _, err := s.target(token); err != nil {
				firewallstate.WriteError(w, err)
				return
			}
		} else {
			valid := firewallstate.MatchToken(token, s.cfg.Token)
			for _, p := range s.cfg.Identities {
				valid = valid || firewallstate.MatchToken(token, p.Token)
			}
			if !valid {
				firewallstate.WriteError(w, firewallstate.Fail(401, "administrative bearer required"))
				return
			}
		}
		if r.Header.Get("Origin") != "" {
			firewallstate.WriteError(w, firewallstate.Fail(403, "browser origins refused"))
			return
		}
		select {
		case s.httpSlots <- struct{}{}:
			defer func() { <-s.httpSlots }()
		default:
			firewallstate.WriteError(w, firewallstate.Fail(429, "controller overloaded"))
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		defer cancel()
		ctx = context.WithValue(ctx, tokenContext{}, token)
		r = r.WithContext(ctx)
		r.Body = http.MaxBytesReader(w, r.Body, MaxRequestBytes)
		if r.URL.Path == "/mcp" {
			if r.Method == "POST" {
				raw, err := io.ReadAll(r.Body)
				var envelope map[string]json.RawMessage
				if err != nil || firewallstate.Decode(raw, &envelope) != nil {
					firewallstate.WriteError(w, firewallstate.Fail(400, "invalid MCP envelope"))
					return
				}
				r.Body = io.NopCloser(bytes.NewReader(raw))
			}
			mcpHandler.ServeHTTP(w, r)
			return
		}
		var out any
		var err error
		switch r.URL.Path {
		case "/api/v1/fleet/desired":
			if r.Method != "GET" {
				w.WriteHeader(405)
				return
			}
			if r.URL.RawQuery != "" {
				firewallstate.WriteError(w, firewallstate.Fail(400, "desired takes no identity parameters"))
				return
			}
			out, err = s.Desired(ctx, token)
		case "/api/v1/fleet/ack":
			if r.Method != "POST" {
				w.WriteHeader(405)
				return
			}
			var a Ack
			var raw []byte
			raw, err = io.ReadAll(r.Body)
			if err == nil {
				err = firewallstate.Decode(raw, &a)
			}
			if err != nil {
				err = firewallstate.Fail(400, "invalid ack")
			} else {
				err = s.Acknowledge(ctx, token, a)
				out = map[string]bool{"accepted": err == nil}
			}
		default:
			op := strings.TrimPrefix(r.URL.Path, "/api/v1/fleet/")
			if op == r.URL.Path {
				http.NotFound(w, r)
				return
			}
			if _, ok := descriptorFor(op); !ok {
				http.NotFound(w, r)
				return
			}
			var raw []byte
			if op == "status" || op == "audit" || op == "capabilities" {
				if r.Method != "GET" {
					w.WriteHeader(405)
					return
				}
				raw, _ = json.Marshal(map[string]any{"scope": Scope{Tenant: r.URL.Query().Get("tenant"), App: r.URL.Query().Get("app")}})
			} else {
				if r.Method != "POST" {
					w.WriteHeader(405)
					return
				}
				raw, err = io.ReadAll(r.Body)
			}
			var req Request
			if err == nil {
				req, err = decodeOperation(op, raw)
			}
			if err == nil {
				out, err = s.Execute(ctx, token, op, req)
			}
		}
		if err != nil {
			firewallstate.WriteError(w, err)
			return
		}
		firewallstate.WriteJSON(w, 200, out)
	})
}

func schemaFor(d descriptor) mcp.ToolInputSchema {
	props := map[string]any{}
	id := map[string]any{"type": "string", "pattern": "^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$", "maxLength": 128}
	for _, f := range d.fields {
		switch f {
		case "scope":
			props[f] = map[string]any{"type": "object", "properties": map[string]any{"tenant": id, "app": id}, "required": []string{"tenant", "app"}, "additionalProperties": false}
		case "bundle":
			props[f] = map[string]any{"type": "string", "minLength": 1, "maxLength": MaxArtifactBytes}
		case "revision":
			props[f] = map[string]any{"type": "string", "pattern": "^[0-9a-f]{64}$"}
		case "targets", "canary":
			min := 0
			if f == "targets" {
				min = 1
			}
			props[f] = map[string]any{"type": "array", "items": id, "minItems": min, "maxItems": MaxTargets, "uniqueItems": true}
		case "expected":
			props[f] = map[string]any{"type": "object", "minProperties": 1, "maxProperties": MaxTargets, "propertyNames": id, "additionalProperties": map[string]any{"type": "integer", "minimum": 0, "maximum": int64(1<<53 - 1)}}
		case "deadline":
			props[f] = map[string]any{"type": "string", "format": "date-time"}
		case "rollback_on_failure":
			props[f] = map[string]any{"type": "boolean"}
		case "expected_phase":
			phases := []string{"canary", "active"}
			if d.op == "activate" {
				phases = []string{"staged"}
			}
			if d.op == "promote" {
				phases = []string{"canary"}
			}
			props[f] = map[string]any{"type": "string", "enum": phases}
		default:
			props[f] = id
		}
	}
	return mcp.ToolInputSchema{Type: "object", Properties: props, Required: d.required, AdditionalProperties: false}
}
func (s *Service) newMCP() *server.MCPServer {
	srv := server.NewMCPServer("netcap-firewall-fleet", "1.0.0", server.WithToolCapabilities(false))
	for _, d := range descriptors {
		read := d.op == "capabilities" || d.op == "audit"
		tool := mcp.Tool{Name: "fleet_" + d.op, Description: "Scoped fleet " + d.op + ". Per-target CAS; one fenced controller; no globally atomic activation.", InputSchema: schemaFor(d), Annotations: mcp.ToolAnnotation{ReadOnlyHint: &read}}
		srv.AddTool(tool, func(ctx context.Context, call mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			raw, err := json.Marshal(call.Params.Arguments)
			if err != nil {
				return mcp.NewToolResultError("invalid arguments"), nil
			}
			r, err := decodeOperation(d.op, raw)
			if err != nil {
				return mcp.NewToolResultError(err.Error()), nil
			}
			token, _ := ctx.Value(tokenContext{}).(string)
			out, err := s.Execute(ctx, token, d.op, r)
			if err != nil {
				return mcp.NewToolResultError(err.Error()), nil
			}
			raw, err = json.Marshal(out)
			if err != nil {
				return mcp.NewToolResultError("encoding failed"), nil
			}
			return mcp.NewToolResultText(string(raw)), nil
		})
	}
	return srv
}
