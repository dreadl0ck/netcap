package mcp

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	mcplib "github.com/mark3labs/mcp-go/mcp"
)

func TestQueryCountOnlyRequestsBackendCounts(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/audit/Connection/stream" || r.URL.Query().Get("countOnly") != "true" || r.URL.Query().Get("filter") != "SrcPort == '443'" {
			t.Errorf("count-only request lost backend options: %s", r.URL)
		}
		w.Header().Set("Content-Type", "text/event-stream")
		io.WriteString(w, "event: complete\ndata: {\"total\":600,\"scanned\":1200,\"count\":0}\n\n")
	}))
	defer ts.Close()
	s, err := New(Options{BaseURL: ts.URL})
	if err != nil {
		t.Fatal(err)
	}
	result, err := s.mcpSrv.GetTool("query_audit_records").Handler(context.Background(), mcplib.CallToolRequest{Params: mcplib.CallToolParams{Name: "query_audit_records", Arguments: map[string]any{"session_id": "owned", "type": "Connection", "count_only": true, "limit": 1, "filter": "SrcPort == '443'"}}})
	if err != nil || result.IsError {
		t.Fatal(result, err)
	}
	var out struct {
		Returned int
		Records  json.RawMessage
		Summary  struct{ Total, Scanned, Count int }
	}
	if err := json.Unmarshal([]byte(contentText(result)), &out); err != nil {
		t.Fatal(err)
	}
	if out.Returned != 0 || out.Records != nil || out.Summary.Total != 600 || out.Summary.Scanned != 1200 || out.Summary.Count != 0 {
		t.Fatalf("wrong count-only result: %+v", out)
	}
}
