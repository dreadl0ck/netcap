package mcp

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	mcplib "github.com/mark3labs/mcp-go/mcp"
)

func TestQueryValidatesNumbersAndCanonicalizesTypes(t *testing.T) {
	requests := 0
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		if !strings.Contains(r.URL.Path, "/DNS/") {
			t.Error("noncanonical audit type", r.URL)
		}
		w.Header().Set("Content-Type", "text/event-stream")
		io.WriteString(w, "event: complete\ndata: {\"total\":0,\"count\":0}\n\n")
	}))
	defer backend.Close()
	s, err := New(Options{BaseURL: backend.URL})
	if err != nil {
		t.Fatal(err)
	}
	call := func(args map[string]any) *mcplib.CallToolResult {
		result, _ := s.handleQueryAuditRecords(context.Background(), mcplib.CallToolRequest{Params: mcplib.CallToolParams{Arguments: args}})
		return result
	}
	if result := call(map[string]any{"session_id": "owned", "type": "dns"}); result.IsError || !strings.Contains(contentText(result), `"type":"DNS"`) {
		t.Fatal(contentText(result))
	}
	for _, value := range []any{0, -1, 1.5, 501, "3", 1e30} {
		if result := call(map[string]any{"session_id": "owned", "type": "DNS", "limit": value}); !result.IsError {
			t.Fatal("invalid limit accepted", value)
		}
	}
	if result := call(map[string]any{"session_id": "owned", "type": "doesNotExist"}); !result.IsError || strings.Contains(contentText(result), "/api/") {
		t.Fatal(contentText(result))
	}
	for _, path := range []string{"", ".", "relative.pcap"} {
		result, _ := s.handleIngestPCAP(context.Background(), mcplib.CallToolRequest{Params: mcplib.CallToolParams{Arguments: map[string]any{"path": path}}})
		if !result.IsError || strings.Contains(contentText(result), "stat ") {
			t.Fatal("invalid ingest read filesystem", contentText(result))
		}
	}
	if requests != 1 {
		t.Fatalf("rejected inputs reached backend: %d requests", requests)
	}
}
