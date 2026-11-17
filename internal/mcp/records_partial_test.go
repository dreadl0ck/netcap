package mcp

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	mcplib "github.com/mark3labs/mcp-go/mcp"
)

func TestPartialAuditQueryPreservesQualificationAndBoundContinuation(t *testing.T) {
	generation := strings.Repeat("a", 64)
	requests := 0
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		q := r.URL.Query()
		if q.Get("allowPartial") != "true" || q.Get("runId") != "run-A" || q.Get("stageGeneration") != generation || q.Get("offset") != "1" {
			t.Errorf("partial selector not forwarded: %s", r.URL)
		}
		w.Header().Set("Content-Type", "text/event-stream")
		io.WriteString(w, "event: record\ndata: {\"SrcIP\":\"192.0.2.2\"}\n\nevent: complete\ndata: {\"total\":2,\"scanned\":2,\"count\":1,\"coverage\":\"partial\",\"coverageReason\":\"input gap\",\"stage\":\"aggregate\",\"runId\":\"run-A\",\"stageGeneration\":\""+generation+"\",\"partialAdmission\":true}\n\n")
	}))
	defer ts.Close()
	s, err := New(Options{BaseURL: ts.URL})
	if err != nil {
		t.Fatal(err)
	}
	arguments := map[string]any{"session_id": "owned", "type": "Connection", "allow_partial": true, "run_id": "run-A", "stage_generation": generation, "offset": 1}
	result, err := s.handleQueryAuditRecords(context.Background(), mcplib.CallToolRequest{Params: mcplib.CallToolParams{Arguments: arguments}})
	if err != nil || result.IsError {
		t.Fatal("qualified query failed", result, err)
	}
	var output struct {
		Returned int
		Summary  struct {
			Coverage, RunID, StageGeneration string
			PartialAdmission                 bool
		}
	}
	if err := json.Unmarshal([]byte(contentText(result)), &output); err != nil {
		t.Fatal(err)
	}
	if output.Returned != 1 || output.Summary.Coverage != "partial" || output.Summary.RunID != "run-A" || output.Summary.StageGeneration != generation || !output.Summary.PartialAdmission {
		t.Fatal("partial metadata was lost", output)
	}
	delete(arguments, "stage_generation")
	result, err = s.handleQueryAuditRecords(context.Background(), mcplib.CallToolRequest{Params: mcplib.CallToolParams{Arguments: arguments}})
	if err != nil || !result.IsError || requests != 1 {
		t.Fatal("unbound continuation reached backend", result, err, requests)
	}
}

func TestPartialAuditQueryRejectsUnqualifiedBackendSuccess(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		io.WriteString(w, "event: complete\ndata: {\"total\":0,\"scanned\":0,\"count\":0}\n\n")
	}))
	defer ts.Close()
	s, err := New(Options{BaseURL: ts.URL})
	if err != nil {
		t.Fatal(err)
	}
	result, err := s.handleQueryAuditRecords(context.Background(), mcplib.CallToolRequest{Params: mcplib.CallToolParams{Arguments: map[string]any{"session_id": "owned", "type": "HTTP", "allow_partial": true}}})
	if err != nil || !result.IsError {
		t.Fatal("legacy backend success lost coverage qualification", result, err)
	}
}
