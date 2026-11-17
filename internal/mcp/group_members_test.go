package mcp

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	mcplib "github.com/mark3labs/mcp-go/mcp"
)

func TestGroupedMemberToolForwardsExactGroupAndPage(t *testing.T) {
	var seen atomic.Bool
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/alerts" || r.URL.Query().Get("groupId") != "exact-group" || r.URL.Query().Get("pageLimit") != "7" || r.URL.Query().Get("pageOffset") != "14" {
			t.Error("group member selector changed", r.URL)
		}
		seen.Store(true)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"alerts":[],"totalCount":14,"returned":0,"offset":14,"next_offset":14,"limit":7,"has_more":false,"generation":"members"}`))
	}))
	defer backend.Close()
	s, err := New(Options{BaseURL: backend.URL, CarveDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	result, err := s.mcpSrv.GetTool("list_alerts").Handler(context.Background(), mcplib.CallToolRequest{Params: mcplib.CallToolParams{Arguments: map[string]any{"session_id": "owned", "group_id": "exact-group", "limit": 7, "offset": 14}}})
	if err != nil || result.IsError || !seen.Load() {
		t.Fatal(result, err, seen.Load())
	}
}
