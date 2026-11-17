package mcp

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/mark3labs/mcp-go/client"
	mcplib "github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/santhosh-tekuri/jsonschema/v6"
)

func TestSerializedToolContractsHaveSchemasAndConsistentHints(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/stream") {
			io.WriteString(w, "event: complete\ndata: {\"total\":0,\"scanned\":0}\n\n")
			return
		}
		if r.URL.Path == "/api/decoders" {
			io.WriteString(w, `[{"name":"HTTP"}]`)
			return
		}
		io.WriteString(w, `{"hosts":[],"totalCount":0,"returned":0,"offset":0,"next_offset":0,"limit":100,"has_more":false,"generation":"fixture"}`)
	}))
	defer backend.Close()
	s, err := New(Options{BaseURL: backend.URL, CarveDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	cli, err := client.NewInProcessClient(s.mcpSrv)
	if err != nil {
		t.Fatal(err)
	}
	defer cli.Close()
	ctx := context.Background()
	if err := cli.Start(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := cli.Initialize(ctx, mcplib.InitializeRequest{Params: mcplib.InitializeParams{ProtocolVersion: "2025-11-25", ClientInfo: mcplib.Implementation{Name: "output-contract", Version: "1"}}}); err != nil {
		t.Fatal(err)
	}
	catalogue, err := cli.ListTools(ctx, mcplib.ListToolsRequest{})
	if err != nil {
		t.Fatal(err)
	}
	schemas := map[string]*jsonschema.Schema{}
	for _, tool := range catalogue.Tools {
		raw, err := json.Marshal(tool)
		if err != nil {
			t.Fatal(err)
		}
		var object map[string]any
		if err := json.Unmarshal(raw, &object); err != nil {
			t.Fatal(err)
		}
		output, _ := object["outputSchema"].(map[string]any)
		if output == nil {
			t.Fatal("missing output schema", tool.Name)
		}
		annotations, _ := object["annotations"].(map[string]any)
		if annotations["readOnlyHint"] == true && annotations["destructiveHint"] == true {
			t.Fatal("contradictory hints", tool.Name)
		}
		for _, name := range []string{"get_analyst_binding", "get_analyst_capabilities", "get_capability_inventory", "read_mcp_artifact"} {
			if tool.Name == name && annotations["openWorldHint"] != false {
				t.Fatal("local read marked open-world", name)
			}
		}
		compiler := jsonschema.NewCompiler()
		uri := "urn:output:" + tool.Name
		if err := compiler.AddResource(uri, output); err != nil {
			t.Fatal(err)
		}
		schemas[tool.Name], err = compiler.Compile(uri)
		if err != nil {
			t.Fatal(tool.Name, err)
		}
	}
	for _, name := range []string{"list_hosts", "list_decoders", "query_audit_records"} {
		result, err := cli.CallTool(ctx, mcplib.CallToolRequest{Params: mcplib.CallToolParams{Name: name, Arguments: map[string]any{"session_id": "owned", "type": "DNS"}}})
		if err != nil || result.IsError || result.StructuredContent == nil {
			t.Fatal(name, result, err)
		}
		if err := schemas[name].Validate(result.StructuredContent); err != nil {
			t.Fatal(name, err)
		}
	}
	count, err := cli.CallTool(ctx, mcplib.CallToolRequest{Params: mcplib.CallToolParams{Name: "query_audit_records", Arguments: map[string]any{"session_id": "owned", "type": "DNS", "count_only": true}}})
	if err != nil || count.IsError {
		t.Fatal(count, err)
	}
	if err := schemas["query_audit_records"].Validate(count.StructuredContent); err != nil {
		t.Fatal(err)
	}
}

func TestOutputSchemasRejectMissingAndNullSuccessFields(t *testing.T) {
	for _, name := range []string{"query_audit_records", "list_hosts", "list_alerts_grouped"} {
		var document any
		if err := json.Unmarshal(toolOutputSchema(name), &document); err != nil {
			t.Fatal(err)
		}
		compiler := jsonschema.NewCompiler()
		if err := compiler.AddResource("urn:negative", document); err != nil {
			t.Fatal(err)
		}
		schema, err := compiler.Compile("urn:negative")
		if err != nil {
			t.Fatal(err)
		}
		for _, raw := range []string{`{}`, `{"records":null}`, `{"hosts":null}`, `{"groups":null}`, `{"_oversized":true,"artifact_id":"incomplete"}`} {
			var value any
			json.Unmarshal([]byte(raw), &value)
			if err := schema.Validate(value); err == nil {
				t.Fatal("invalid success passed schema", name, raw)
			}
		}
	}
}

func TestStructuredOutputHonorsWholeResultByteCap(t *testing.T) {
	s, err := New(Options{BaseURL: "http://127.0.0.1:1", CarveDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.addTool(server.ServerTool{Tool: mcplib.NewTool("large_structured_control"), Handler: func(context.Context, mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
		return jsonResult(map[string]any{"value": strings.Repeat("x", 300000), "integer": int64(9223372036854775807)}), nil
	}}); err != nil {
		t.Fatal(err)
	}
	result, err := s.mcpSrv.GetTool("large_structured_control").Handler(context.Background(), mcplib.CallToolRequest{Params: mcplib.CallToolParams{Arguments: map[string]any{"session_id": "owned"}}})
	if err != nil || result.IsError {
		t.Fatal(result, err)
	}
	wire, err := json.Marshal(result)
	if err != nil || len(wire) > MaxResponseBytes || len(result.RawStructuredContent) == 0 {
		t.Fatal("whole structured response exceeded bound", len(wire), err)
	}
	var ref struct {
		ID string `json:"artifact_id"`
	}
	if err := json.Unmarshal(result.RawStructuredContent, &ref); err != nil {
		t.Fatal(err)
	}
	entry := s.carve.Get(ref.ID)
	if entry == nil || entry.SessionID != "owned" || !strings.Contains(string(entry.Bytes), "9223372036854775807") {
		t.Fatal("oversized structured payload was not retained exactly")
	}
}

func TestRawResponseReachesArtifactFallback(t *testing.T) {
	s, err := New(Options{BaseURL: "http://127.0.0.1:1", CarveDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	payload, _ := json.Marshal(map[string]any{"value": strings.Repeat("\"\n", 150000)})
	req := mcplib.CallToolRequest{Params: mcplib.CallToolParams{Arguments: map[string]any{"session_id": "owned"}}}
	result := s.structuredToolResult(req, "large_raw_control", rawJSONResult(payload))
	if result.IsError {
		t.Fatal(result)
	}
	var ref struct {
		ID string `json:"artifact_id"`
	}
	if err := json.Unmarshal(result.RawStructuredContent, &ref); err != nil {
		t.Fatal(err)
	}
	entry := s.carve.Get(ref.ID)
	if entry == nil || string(entry.Bytes) != string(payload) {
		t.Fatal("raw response was not retained exactly")
	}
	wire, err := json.Marshal(result)
	if err != nil || len(wire) > MaxResponseBytes {
		t.Fatal("artifact response exceeds bound", len(wire), err)
	}
}
