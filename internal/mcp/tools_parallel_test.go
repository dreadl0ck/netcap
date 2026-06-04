/*
 * NETCAP - Traffic Analysis Framework
 * Copyright (c) Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
 * License: GNU General Public License v3.0
 */

package mcp

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	mcplib "github.com/mark3labs/mcp-go/mcp"
)

// TestSimpleSessionToolUsesQueryParam verifies the post-T2.1 contract:
// session_id arrives as a ?sessionId= query parameter rather than via
// /api/set-directory. The fake server inspects the param and echoes it
// back in the body so the test can assert per-request routing.
func TestSimpleSessionToolUsesQueryParam(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/set-directory", func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("simpleSessionTool should not call /api/set-directory after T2.1")
		http.Error(w, "should not be called", http.StatusInternalServerError)
	})
	mux.HandleFunc("/api/try/session/", func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("simpleSessionTool should not call /api/try/session/ after T2.1")
		http.Error(w, "should not be called", http.StatusInternalServerError)
	})
	mux.HandleFunc("/api/hosts", func(w http.ResponseWriter, r *http.Request) {
		sid := r.URL.Query().Get("sessionId")
		inp := r.URL.Query().Get("inputFile")
		fmt.Fprintf(w, `{"hosts":[],"sessionId":%q,"inputFile":%q}`, sid, inp)
	})
	ts := httptest.NewServer(mux)
	defer ts.Close()

	srv, err := New(Options{BaseURL: ts.URL})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	cases := []struct {
		name string
		sess string
		want string
	}{
		{"local-path", "/data/x.pcap", `"inputFile":"/data/x.pcap"`},
		{"service-hex", "abcdef0123456789abcdef0123456789", `"sessionId":"abcdef0123456789abcdef0123456789"`},
	}
	tool := srv.mcpSrv.GetTool("list_hosts")
	if tool == nil {
		t.Fatal("list_hosts not registered")
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			res, hErr := tool.Handler(context.Background(), mcplib.CallToolRequest{
				Params: mcplib.CallToolParams{
					Name:      "list_hosts",
					Arguments: map[string]any{"session_id": c.sess},
				},
			})
			if hErr != nil {
				t.Fatalf("handler: %v", hErr)
			}
			if res.IsError {
				t.Fatalf("error result: %s", contentText(res))
			}
			body := contentText(res)
			if !strings.Contains(body, c.want) {
				t.Errorf("body = %s\nwant substring %q", body, c.want)
			}
		})
	}
}

// TestSimpleSessionToolParallelCallsDoNotInterleave fires 32 concurrent
// list_hosts calls against three different sessions. The fake endpoint
// records every (sessionId|inputFile) it sees, sleeps 10 ms (to simulate
// I/O), then echoes it back. Without the session gate the requests
// should run in parallel and every response should match the request.
func TestSimpleSessionToolParallelCallsDoNotInterleave(t *testing.T) {
	var calls int32
	mux := http.NewServeMux()
	mux.HandleFunc("/api/hosts", func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		sid := r.URL.Query().Get("sessionId")
		inp := r.URL.Query().Get("inputFile")
		// Sleep so concurrent requests genuinely overlap.
		time.Sleep(10 * time.Millisecond)
		fmt.Fprintf(w, `{"sessionId":%q,"inputFile":%q}`, sid, inp)
	})
	ts := httptest.NewServer(mux)
	defer ts.Close()

	srv, _ := New(Options{BaseURL: ts.URL})
	tool := srv.mcpSrv.GetTool("list_hosts")

	sessions := []string{
		"/data/a.pcap",
		"/data/b.pcap",
		"abc123def456abc123def456abc123de", // service-mode hex
	}

	start := time.Now()
	var wg sync.WaitGroup
	mismatches := int32(0)
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			sid := sessions[idx%len(sessions)]
			res, _ := tool.Handler(context.Background(), mcplib.CallToolRequest{
				Params: mcplib.CallToolParams{
					Name:      "list_hosts",
					Arguments: map[string]any{"session_id": sid},
				},
			})
			body := contentText(res)
			if !strings.Contains(body, sid) {
				atomic.AddInt32(&mismatches, 1)
				t.Errorf("expected body to mention %q, got %s", sid, body)
			}
		}(i)
	}
	wg.Wait()
	elapsed := time.Since(start)
	if mismatches != 0 {
		t.Fatalf("%d mismatches", mismatches)
	}
	if got := atomic.LoadInt32(&calls); int(got) != 32 {
		t.Errorf("calls = %d, want 32", got)
	}
	// 32 calls × 10 ms = 320 ms serial. Parallel should be much faster
	// (~30 ms is typical). Allow a generous bound (200 ms) to avoid
	// flake on busy CI runners; if the gate was still in place we'd see
	// ~320 ms.
	if elapsed > 200*time.Millisecond {
		t.Errorf("parallel calls took %s — gate may still be serialising", elapsed)
	}
}


