package mcp

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	mcplib "github.com/mark3labs/mcp-go/mcp"
)

func TestAnalystMCPSharedSchemasAndStrictCapabilities(t *testing.T) {
	for _, version := range []int{0, 1} {
		t.Run(string(rune('0'+version)), func(t *testing.T) {
			var calls atomic.Int32
			backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/api/analyst/capabilities" {
					_ = json.NewEncoder(w).Encode(map[string]int{"version": version, "catalogueVersion": version})
					return
				}
				if r.URL.Path != "/api/analyst/catalogue" {
					t.Errorf("unexpected %s", r.URL)
				}
				calls.Add(1)
				var body map[string]any
				if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
					t.Error(err)
				}
				if len(body["sources"].([]any)) != 2 {
					t.Error("source scope lost")
				}
				_, _ = w.Write([]byte(`{"version":1,"occurrences":[]}`))
			}))
			defer backend.Close()
			s, err := New(Options{BaseURL: backend.URL, CarveDir: t.TempDir()})
			if err != nil {
				t.Fatal(err)
			}
			tool := s.mcpSrv.GetTool("query_capture_catalogue")
			if tool == nil || !strings.Contains(string(tool.Tool.RawInputSchema), "manifestSHA256") {
				t.Fatal("shared binding schema missing")
			}
			args := map[string]any{"sources": []any{map[string]any{"sessionId": "one", "binding": map[string]any{"runId": "one", "sourceSHA256": strings.Repeat("a", 64), "manifestSHA256": strings.Repeat("b", 64)}}, map[string]any{"sessionId": "two", "binding": map[string]any{"runId": "two", "sourceSHA256": strings.Repeat("a", 64), "manifestSHA256": strings.Repeat("c", 64)}}}, "query": map[string]any{"kind": "endpoint", "value": "192.0.2.1", "types": []string{"Connection"}}}
			result, err := tool.Handler(context.Background(), mcplib.CallToolRequest{Params: mcplib.CallToolParams{Arguments: args}})
			if err != nil || result.IsError != (version != 1) || calls.Load() != int32(version) {
				t.Fatalf("capability fallback %+v %v calls=%d", result, err, calls.Load())
			}
			args["unknown"] = true
			before := calls.Load()
			result, err = tool.Handler(context.Background(), mcplib.CallToolRequest{Params: mcplib.CallToolParams{Arguments: args}})
			if err != nil || !result.IsError || calls.Load() != before {
				t.Fatal("unknown schema field reached backend")
			}
		})
	}
}

func TestAnalystMCPCancellationReachesBackend(t *testing.T) {
	entered, stopped := make(chan struct{}), make(chan struct{})
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/analyst/capabilities" {
			_, _ = w.Write([]byte(`{"version":1,"inspectionVersion":1}`))
			return
		}
		_, _ = io.Copy(io.Discard, r.Body)
		close(entered)
		<-r.Context().Done()
		close(stopped)
	}))
	defer backend.Close()
	s, err := New(Options{BaseURL: backend.URL, CarveDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	tool := s.mcpSrv.GetTool("inspect_bound_capture")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		_, _ = tool.Handler(ctx, mcplib.CallToolRequest{Params: mcplib.CallToolParams{Arguments: map[string]any{"source": map[string]any{"sessionId": "one", "binding": map[string]any{"runId": "one", "sourceSHA256": strings.Repeat("a", 64), "manifestSHA256": strings.Repeat("b", 64)}}}}})
	}()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("request never entered")
	}
	cancel()
	select {
	case <-finished:
	case <-time.After(5 * time.Second):
		t.Fatal("tool did not cancel")
	}
	select {
	case <-stopped:
	case <-time.After(5 * time.Second):
		t.Fatal("backend request did not cancel")
	}
}
