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

// fakeWebui hosts canned responses for the endpoints list_sessions calls.
// Used to drive handleListSessions end-to-end without spawning a real
// webui binary.
type fakeWebui struct {
	tryResp   string // /api/try/sessions response (empty = 404 so we fall through)
	filesResp string // /api/files/input response
}

func (f *fakeWebui) handler(t *testing.T) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/try/sessions", func(w http.ResponseWriter, r *http.Request) {
		if f.tryResp == "" {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, f.tryResp)
	})
	mux.HandleFunc("/api/files/input", func(w http.ResponseWriter, r *http.Request) {
		if f.filesResp == "" {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, f.filesResp)
	})
	return mux
}

// TestListSessionsServiceMode drives the service-mode path through the
// full tool handler: filter, paginate, completed_only.
func TestListSessionsServiceMode(t *testing.T) {
	f := &fakeWebui{
		tryResp: `{"sessions":[
			{"sessionId":"aaa","inputFile":"/d/a.pcap","inputFilename":"a.pcap","inputFileSize":100,"status":"completed","resultsReady":true},
			{"sessionId":"bbb","inputFile":"/d/b.pcap","inputFilename":"b.pcap","inputFileSize":200,"status":"failed","errorMessage":"oom"},
			{"sessionId":"ccc","inputFile":"/d/cabana.pcap","inputFilename":"cabana.pcap","inputFileSize":300,"status":"processing","resultsReady":false}
		]}`,
	}
	ts := httptest.NewServer(f.handler(t))
	defer ts.Close()

	srv := mustNewServer(t, ts.URL)

	// 1. Unfiltered: total=3, returned=3, mode=service.
	res := callListSessions(t, srv, nil)
	if res["mode"] != "service" {
		t.Errorf("mode = %v", res["mode"])
	}
	if int(res["total"].(float64)) != 3 {
		t.Errorf("total = %v", res["total"])
	}

	// 2. completed_only=true → only "aaa".
	res = callListSessions(t, srv, map[string]any{"completed_only": true})
	if int(res["total"].(float64)) != 1 {
		t.Errorf("completed_only total = %v", res["total"])
	}

	// 3. failed_only=true → only "bbb"; check the error surfaces.
	res = callListSessions(t, srv, map[string]any{"failed_only": true})
	if int(res["total"].(float64)) != 1 {
		t.Errorf("failed_only total = %v", res["total"])
	}
	first := res["sessions"].([]any)[0].(map[string]any)
	if first["error"] != "oom" {
		t.Errorf("error = %v", first["error"])
	}

	// 4. search=cabana → 1 hit.
	res = callListSessions(t, srv, map[string]any{"search": "cabana"})
	if int(res["total"].(float64)) != 1 {
		t.Errorf("search total = %v", res["total"])
	}

	// 5. Pagination: limit=2, offset=1 → returned=2 (rows 1 and 2 of 3).
	res = callListSessions(t, srv, map[string]any{"limit": 2, "offset": 1})
	if int(res["returned"].(float64)) != 2 {
		t.Errorf("paginated returned = %v", res["returned"])
	}
}

// TestListSessionsLocalMode drives the local-mode fallback (/api/try
// returns 404 → fall through to /api/files/input).
func TestListSessionsLocalMode(t *testing.T) {
	f := &fakeWebui{
		filesResp: `[
			{"id":"hash1","name":"a.pcap","path":"/u/a.pcap","size":100,"isCompleted":true},
			{"id":"hash2","name":"b.pcap","path":"/u/b.pcap","size":200,"isCompleted":false,"error":"bad magic"}
		]`,
	}
	ts := httptest.NewServer(f.handler(t))
	defer ts.Close()

	srv := mustNewServer(t, ts.URL)
	res := callListSessions(t, srv, nil)
	if res["mode"] != "local" {
		t.Errorf("mode = %v", res["mode"])
	}
	if int(res["total"].(float64)) != 2 {
		t.Errorf("total = %v", res["total"])
	}

	// failed_only filters to b.pcap whose status was forced to "failed".
	res = callListSessions(t, srv, map[string]any{"failed_only": true})
	if int(res["total"].(float64)) != 1 {
		t.Errorf("failed_only total = %v", res["total"])
	}
}

func TestCollectSessionsDecodeFallback(t *testing.T) {
	for _, body := range []string{`{"sessions":`, `null`, `{}`, `{"sessions":null}`, `{"sessions":[]}`} {
		t.Run(body, func(t *testing.T) {
			f := &fakeWebui{tryResp: body, filesResp: `[]`}
			ts := httptest.NewServer(f.handler(t))
			defer ts.Close()
			srv := mustNewServer(t, ts.URL)
			sessions, mode, err := srv.collectSessions(NewNetcapClient(ts.URL))
			wantMode := "local"
			if body == `{"sessions":[]}` {
				wantMode = "service"
			}
			if err != nil || mode != wantMode || sessions == nil || len(sessions) != 0 {
				t.Fatalf("got %v, %q, %v; want non-nil empty sessions in %s mode", sessions, mode, err, wantMode)
			}
		})
	}
}

func mustNewServer(t *testing.T, baseURL string) *Server {
	t.Helper()
	srv, err := New(Options{BaseURL: baseURL})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return srv
}

func callListSessions(t *testing.T, srv *Server, args map[string]any) map[string]any {
	t.Helper()
	req := mcplib.CallToolRequest{
		Params: mcplib.CallToolParams{
			Name:      "list_sessions",
			Arguments: args,
		},
	}
	res, err := srv.handleListSessions(context.Background(), req)
	if err != nil {
		t.Fatalf("handleListSessions: %v", err)
	}
	if res.IsError {
		t.Fatalf("error result: %s", contentText(res))
	}
	var parsed map[string]any
	if jErr := json.Unmarshal([]byte(contentText(res)), &parsed); jErr != nil {
		t.Fatalf("decode: %v\n%s", jErr, contentText(res))
	}
	return parsed
}

func contentText(r *mcplib.CallToolResult) string {
	if r == nil || len(r.Content) == 0 {
		return ""
	}
	if tc, ok := r.Content[0].(mcplib.TextContent); ok {
		return tc.Text
	}
	return ""
}
