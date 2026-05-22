/*
 * NETCAP - Traffic Analysis Framework
 * Copyright (c) Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
 * License: GNU General Public License v3.0
 */

package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	mcplib "github.com/mark3labs/mcp-go/mcp"
)

// TestGetLiveCaptureStatusForwardsFromAPI: the tool normalises /api/status
// into a compact MCP-friendly shape.
func TestGetLiveCaptureStatusForwardsFromAPI(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/status", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{
			"isLiveMode": true,
			"isProcessing": true,
			"sessionId": "abc",
			"activeInputFile": "eth0",
			"serverStarted": "2026-05-21T10:00:00Z"
		}`)
	})
	ts := httptest.NewServer(mux)
	defer ts.Close()

	srv, _ := New(Options{BaseURL: ts.URL})
	tool := srv.mcpSrv.GetTool("get_live_capture_status")
	if tool == nil {
		t.Fatal("get_live_capture_status not registered")
	}
	res, err := tool.Handler(context.Background(), mcplib.CallToolRequest{
		Params: mcplib.CallToolParams{Name: "get_live_capture_status"},
	})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	if res.IsError {
		t.Fatalf("error: %s", contentText(res))
	}
	var out map[string]any
	_ = json.Unmarshal([]byte(contentText(res)), &out)
	if out["is_live_mode"] != true {
		t.Errorf("is_live_mode = %v", out["is_live_mode"])
	}
	if out["current_session"] != "abc" {
		t.Errorf("current_session = %v", out["current_session"])
	}
}

// TestStopLiveCaptureForwardsPost: a 200 OK with empty body returns a
// human-readable text result; a non-empty body is forwarded verbatim.
func TestStopLiveCaptureForwardsPost(t *testing.T) {
	called := false
	mux := http.NewServeMux()
	mux.HandleFunc("/api/stop-capture", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method = %s, want POST", r.Method)
		}
		called = true
		fmt.Fprint(w, `{"success":true,"message":"stopped"}`)
	})
	ts := httptest.NewServer(mux)
	defer ts.Close()

	srv, _ := New(Options{BaseURL: ts.URL})
	tool := srv.mcpSrv.GetTool("stop_live_capture")
	res, err := tool.Handler(context.Background(), mcplib.CallToolRequest{
		Params: mcplib.CallToolParams{Name: "stop_live_capture"},
	})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	if res.IsError {
		t.Fatalf("error: %s", contentText(res))
	}
	if !called {
		t.Error("upstream POST /api/stop-capture not called")
	}
	body := contentText(res)
	if body == "" || !contains(body, "stopped") {
		t.Errorf("body = %q", body)
	}
}

// TestStopLiveCaptureSurfacesErrors propagates 4xx as IsError=true.
func TestStopLiveCaptureSurfacesErrors(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/stop-capture", func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "Not in live capture mode", http.StatusBadRequest)
	})
	ts := httptest.NewServer(mux)
	defer ts.Close()

	srv, _ := New(Options{BaseURL: ts.URL})
	tool := srv.mcpSrv.GetTool("stop_live_capture")
	res, _ := tool.Handler(context.Background(), mcplib.CallToolRequest{
		Params: mcplib.CallToolParams{Name: "stop_live_capture"},
	})
	if !res.IsError {
		t.Errorf("expected IsError=true, got %s", contentText(res))
	}
}
