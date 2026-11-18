package mcp

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	mcplib "github.com/mark3labs/mcp-go/mcp"
)

func TestAuditQueryAdmissionRecoversAfterCancellation(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	started := make(chan struct{}, 2)
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("filter") == "hold" {
			started <- struct{}{}
			<-r.Context().Done()
			return
		}
		io.WriteString(w, "event: complete\ndata: {\"total\":0,\"count\":0}\n\n")
	}))
	defer backend.Close()
	defer cancel()
	s, err := New(Options{BaseURL: backend.URL})
	if err != nil {
		t.Fatal(err)
	}
	query := func(ctx context.Context, filter string, countOnly bool) *mcplib.CallToolResult {
		result, _ := s.handleQueryAuditRecords(ctx, mcplib.CallToolRequest{Params: mcplib.CallToolParams{Arguments: map[string]any{
			"session_id": "owned", "type": "Connection", "filter": filter, "count_only": countOnly,
		}}})
		return result
	}
	done := make(chan *mcplib.CallToolResult, 2)
	for _, countOnly := range []bool{false, true} {
		go func() { done <- query(ctx, "hold", countOnly) }()
	}
	for range 2 {
		select {
		case <-started:
		case <-ctx.Done():
			t.Fatal("both audit requests did not reach the backend")
		}
	}
	if busy := query(t.Context(), "", false); !busy.IsError || !strings.Contains(contentText(busy), "audit queries are busy") {
		t.Fatalf("saturated query returned %s", contentText(busy))
	}
	cancel()
	for range 2 {
		select {
		case result := <-done:
			if !result.IsError {
				t.Fatal("canceled query succeeded")
			}
		case <-time.After(2 * time.Second):
			t.Fatal("canceled query did not return")
		}
	}
	if retry := query(t.Context(), "", false); retry.IsError {
		t.Fatalf("retry failed: %s", contentText(retry))
	}
}

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
