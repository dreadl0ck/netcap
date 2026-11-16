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

func TestInventoryToolsForwardBackendPaging(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if q.Get("mcpPage") != "true" || q.Get("pageLimit") != "3" || q.Get("pageOffset") != "2" || q.Get("pageSearch") != "needle" || q.Get("pageGeneration") != "generation" {
			t.Errorf("lost paging: %s", r.URL)
		}
		io.WriteString(w, `{}`)
	}))
	defer ts.Close()
	s, err := New(Options{BaseURL: ts.URL})
	if err != nil {
		t.Fatal(err)
	}
	for name := range pagedCollectionKeys {
		result, err := s.mcpSrv.GetTool(name).Handler(context.Background(), mcplib.CallToolRequest{Params: mcplib.CallToolParams{Arguments: map[string]any{"session_id": "owned", "limit": 3, "offset": 2, "search": "needle", "generation": "generation"}}})
		if err != nil || result.IsError {
			t.Fatal(name, result, err)
		}
	}
	for _, value := range []any{-1, 0, 1.5, 501, "3", json.Number("999999999999999999999999")} {
		result, _ := s.mcpSrv.GetTool("list_hosts").Handler(context.Background(), mcplib.CallToolRequest{Params: mcplib.CallToolParams{Arguments: map[string]any{"session_id": "owned", "limit": value}}})
		if !result.IsError {
			t.Fatal("invalid limit accepted", value)
		}
	}
}
