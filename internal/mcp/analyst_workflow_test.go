package mcp

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	mcplib "github.com/mark3labs/mcp-go/mcp"
)

func TestCarveGenerationConflictNeverPublishesBytes(t *testing.T) {
	for _, name := range []string{"carve_subpcap_for_host", "carve_subpcap_for_connection", "carve_subpcap_for_http_pair", "carve_subpcap_for_certificate"} {
		t.Run(name, func(t *testing.T) {
			calls := 0
			backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls++
				if r.URL.Query().Get("runId") != "expected-run" || r.URL.Query().Get("sessionId") != "owned" {
					t.Errorf("lost generation: %s", r.URL)
				}
				http.Error(w, "Capture generation is unavailable or stale", http.StatusConflict)
			}))
			defer backend.Close()
			s, err := New(Options{BaseURL: backend.URL, CarveDir: t.TempDir()})
			if err != nil {
				t.Fatal(err)
			}
			tool := s.mcpSrv.GetTool(name)
			if tool == nil {
				t.Fatal("missing tool")
			}
			result, err := tool.Handler(context.Background(), mcplib.CallToolRequest{Params: mcplib.CallToolParams{Name: name, Arguments: map[string]any{
				"session_id": "owned", "run_id": "expected-run", "host": "192.0.2.1", "protocol": "TCP",
				"src_ip": "192.0.2.1", "dst_ip": "192.0.2.2", "src_port": "1234", "dst_port": "443",
			}}})
			if err != nil || !result.IsError || calls != 1 {
				t.Fatalf("conflict became success: %+v %v calls=%d", result, err, calls)
			}
			if count, _ := s.carve.Stats(); count != 0 {
				t.Fatal("conflicted carve published")
			}
		})
	}
}

func TestAnalystPlaybooksRequireEvidenceAndReview(t *testing.T) {
	s := &Server{}
	request := mcplib.GetPromptRequest{}
	request.Params.Arguments = map[string]string{"session_id": "owned", "ip": "192.0.2.1"}
	for _, handler := range []func(context.Context, mcplib.GetPromptRequest) (*mcplib.GetPromptResult, error){s.handleTriagePrompt, s.handleInvestigateHostPrompt, s.handleHuntMalwarePrompt} {
		result, err := handler(context.Background(), request)
		if err != nil {
			t.Fatal(err)
		}
		text := result.Messages[0].Content.(mcplib.TextContent).Text
		for _, required := range []string{"Saved queries", "exact quoted timestampNs", "analyst review required", "Do not execute payloads", "not a complete inventory", "Missing/disabled/failed analysis is not a no-match"} {
			if !strings.Contains(text, required) {
				t.Fatalf("missing %q", required)
			}
		}
	}
}

func TestCarveGenerationNeverDropsMalformedExplicitSelectors(t *testing.T) {
	for _, raw := range []any{"", " ", 7, nil} {
		q := url.Values{}
		request := mcplib.CallToolRequest{Params: mcplib.CallToolParams{Arguments: map[string]any{"run_id": raw}}}
		if err := addCarveGeneration(request, q); err == nil || q.Has("runId") {
			t.Fatalf("invalid generation accepted: %#v", raw)
		}
	}
}
