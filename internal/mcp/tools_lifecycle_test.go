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
	"sync/atomic"
	"testing"

	mcplib "github.com/mark3labs/mcp-go/mcp"
)

// TestDeleteSessionForwardsDELETE: the tool issues an HTTP DELETE to
// /api/try/session/<id> and surfaces the response.
func TestDeleteSessionForwardsDELETE(t *testing.T) {
	called := false
	mux := http.NewServeMux()
	mux.HandleFunc("/api/try/session/", func(w http.ResponseWriter, r *http.Request) {
		called = true
		if r.Method != http.MethodDelete {
			t.Errorf("method = %s, want DELETE", r.Method)
		}
		fmt.Fprint(w, `{"success":true,"session_id":"abc","removed_paths":["/tmp/uploads/abc","/tmp/results/abc"]}`)
	})
	ts := httptest.NewServer(mux)
	defer ts.Close()

	srv, _ := New(Options{BaseURL: ts.URL})
	tool := srv.mcpSrv.GetTool("delete_session")
	res, err := tool.Handler(context.Background(), mcplib.CallToolRequest{
		Params: mcplib.CallToolParams{
			Name:      "delete_session",
			Arguments: map[string]any{"session_id": "abcdef0123456789abcdef0123456789"},
		},
	})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	if res.IsError {
		t.Fatalf("error: %s", contentText(res))
	}
	if !called {
		t.Fatal("DELETE not called")
	}
	if !contains(contentText(res), "removed_paths") {
		t.Errorf("body = %q", contentText(res))
	}
}

// TestDeleteSessionRefusesPathStyle: local-mode sessions can't be
// deleted via this tool; they're CLI-process owned.
func TestDeleteSessionRefusesPathStyle(t *testing.T) {
	srv, _ := New(Options{BaseURL: "http://127.0.0.1:1"})
	tool := srv.mcpSrv.GetTool("delete_session")
	res, _ := tool.Handler(context.Background(), mcplib.CallToolRequest{
		Params: mcplib.CallToolParams{
			Name:      "delete_session",
			Arguments: map[string]any{"session_id": "/tmp/x.pcap"},
		},
	})
	if !res.IsError {
		t.Errorf("expected IsError for path-style session, got %s", contentText(res))
	}
	if !contains(contentText(res), "service-mode only") {
		t.Errorf("error message: %s", contentText(res))
	}
}

// TestWaitForSessionPollsUntilCompleted: simulates a session that
// reports isCompleted=false twice, then true. The tool should poll
// and return when completed=true.
func TestWaitForSessionPollsUntilCompleted(t *testing.T) {
	var poll int32
	mux := http.NewServeMux()
	mux.HandleFunc("/api/audit-stats", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"totalRecords":42}`)
	})
	mux.HandleFunc("/api/status", func(w http.ResponseWriter, r *http.Request) {
		// Stay "processing" until the per-file row also flips, so
		// deriveCompleted can't short-circuit via isProcessing=false.
		fmt.Fprint(w, `{"isProcessing":true}`)
	})
	mux.HandleFunc("/api/files/input", func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt32(&poll, 1)
		complete := "false"
		if n >= 3 {
			complete = "true"
		}
		fmt.Fprintf(w, `[{"path":"/data/x.pcap","isCompleted":%s}]`, complete)
	})
	ts := httptest.NewServer(mux)
	defer ts.Close()

	srv, _ := New(Options{BaseURL: ts.URL})
	tool := srv.mcpSrv.GetTool("wait_for_session")
	res, err := tool.Handler(context.Background(), mcplib.CallToolRequest{
		Params: mcplib.CallToolParams{
			Name: "wait_for_session",
			Arguments: map[string]any{
				"session_id":      "/data/x.pcap",
				"timeout_seconds": 5,
				"poll_interval_ms": 100,
			},
		},
	})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	if res.IsError {
		t.Fatalf("error: %s", contentText(res))
	}
	var out map[string]any
	_ = json.Unmarshal([]byte(contentText(res)), &out)
	if out["completed"] != true {
		t.Errorf("completed = %v", out["completed"])
	}
	if atomic.LoadInt32(&poll) < 3 {
		t.Errorf("polled %d times, expected >=3", poll)
	}
}

// TestWaitForSessionTimesOut returns a structured timed_out=true result
// rather than an error when the deadline elapses.
func TestWaitForSessionTimesOut(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/audit-stats", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"totalRecords":0}`)
	})
	mux.HandleFunc("/api/status", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"isProcessing":true}`)
	})
	mux.HandleFunc("/api/files/input", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `[{"path":"/data/x.pcap","isCompleted":false}]`)
	})
	ts := httptest.NewServer(mux)
	defer ts.Close()

	srv, _ := New(Options{BaseURL: ts.URL})
	tool := srv.mcpSrv.GetTool("wait_for_session")
	res, _ := tool.Handler(context.Background(), mcplib.CallToolRequest{
		Params: mcplib.CallToolParams{
			Name: "wait_for_session",
			Arguments: map[string]any{
				"session_id":       "/data/x.pcap",
				"timeout_seconds":  1,
				"poll_interval_ms": 100,
			},
		},
	})
	if res.IsError {
		t.Fatalf("error: %s", contentText(res))
	}
	var out map[string]any
	_ = json.Unmarshal([]byte(contentText(res)), &out)
	if out["timed_out"] != true {
		t.Errorf("timed_out = %v", out["timed_out"])
	}
	if out["completed"] != false {
		t.Errorf("completed = %v", out["completed"])
	}
}

// TestWaitForSessionSurfacesError returns immediately with the error
// message when the session has failed (no point polling further).
func TestWaitForSessionSurfacesError(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/audit-stats", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{}`)
	})
	mux.HandleFunc("/api/status", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"isProcessing":true}`)
	})
	mux.HandleFunc("/api/files/input", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `[{"path":"/data/x.pcap","isCompleted":false,"error":"corrupt pcap","errorLogPath":"/var/log/x.err"}]`)
	})
	ts := httptest.NewServer(mux)
	defer ts.Close()

	srv, _ := New(Options{BaseURL: ts.URL})
	tool := srv.mcpSrv.GetTool("wait_for_session")
	res, _ := tool.Handler(context.Background(), mcplib.CallToolRequest{
		Params: mcplib.CallToolParams{
			Name: "wait_for_session",
			Arguments: map[string]any{
				"session_id":      "/data/x.pcap",
				"timeout_seconds": 30,
			},
		},
	})
	var out map[string]any
	_ = json.Unmarshal([]byte(contentText(res)), &out)
	if out["error"] != "corrupt pcap" {
		t.Errorf("error = %v", out["error"])
	}
	if out["completed"] != false {
		t.Errorf("completed = %v", out["completed"])
	}
}
