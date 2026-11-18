package mcp

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
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
		if err != nil || !result.IsError {
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

func TestCollectionResultRejectsInconsistentPages(t *testing.T) {
	const valid = `{"groups":[{}],"totalCount":12,"groupCount":2,"offset":1,"next_offset":2,"limit":1,"returned":1,"has_more":false,"generation":"fixture"}`
	s := &Server{}
	for _, tc := range []struct {
		name, body string
		wantError  bool
	}{
		{"group totals", valid, false},
		{"legacy collection", `{"groups":[],"totalCount":0}`, false},
		{"past end", `{"groups":[],"totalCount":12,"groupCount":2,"offset":3,"next_offset":3,"limit":1,"returned":0,"has_more":false,"generation":"fixture"}`, false},
		{"wrong row count", strings.Replace(valid, `"returned":1`, `"returned":0`, 1), true},
		{"wrong next offset", strings.Replace(valid, `"next_offset":2`, `"next_offset":3`, 1), true},
		{"wrong continuation", strings.Replace(valid, `"has_more":false`, `"has_more":true`, 1), true},
		{"missing generation", strings.Replace(valid, `,"generation":"fixture"`, "", 1), true},
		{"missing rows", strings.Replace(valid, `"groups":[{}],`, "", 1), true},
		{"stalled continuation", `{"groups":[],"totalCount":12,"groupCount":2,"offset":1,"next_offset":1,"limit":1,"returned":0,"has_more":true,"generation":"fixture"}`, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			result := s.collectionResult(SessionRef{}, "groups", []byte(tc.body), nil)
			if result.IsError != tc.wantError {
				t.Fatalf("IsError = %t, want %t: %+v", result.IsError, tc.wantError, result)
			}
		})
	}
}

func TestCollectionResultMatchesRequestedPage(t *testing.T) {
	const page = `{"hosts":[{}],"totalCount":2,"offset":1,"next_offset":2,"limit":1,"returned":1,"has_more":false,"generation":"fixture"}`
	s := &Server{}
	for _, tc := range []struct {
		name, offset, limit, generation string
		wantError                       bool
	}{
		{"match", "1", "1", "fixture", false},
		{"unbound generation", "1", "1", "", false},
		{"wrong offset", "0", "1", "fixture", true},
		{"wrong limit", "1", "2", "fixture", true},
		{"stale generation", "1", "1", "old", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			q := url.Values{"pageOffset": {tc.offset}, "pageLimit": {tc.limit}, "pageGeneration": {tc.generation}}
			if result := s.collectionResult(SessionRef{}, "hosts", []byte(page), q); result.IsError != tc.wantError {
				t.Fatalf("IsError = %t, want %t: %+v", result.IsError, tc.wantError, result)
			}
		})
	}
}

func TestBoundCollectionRejectsLegacyResponse(t *testing.T) {
	s := &Server{}
	for _, body := range []string{`{}`, `{"hosts":[],"totalCount":0}`} {
		if s.collectionResult(SessionRef{}, "hosts", []byte(body), nil).IsError {
			t.Fatalf("unbound legacy response failed: %s", body)
		}
		query := url.Values{"pageGeneration": {"fixture"}}
		if !s.collectionResult(SessionRef{}, "hosts", []byte(body), query).IsError {
			t.Fatalf("unpaged response accepted for bound continuation: %s", body)
		}
	}
}
