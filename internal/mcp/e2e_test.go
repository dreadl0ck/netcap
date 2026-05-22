/*
 * NETCAP - Traffic Analysis Framework
 * Copyright (c) Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
 * License: GNU General Public License v3.0
 */

package mcp

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestHTTPInitializeAndToolsList drives a real initialize → tools/list
// roundtrip over the admin-authenticated HTTP transport. This is the
// canary that wires everything together: streamable HTTP transport,
// admin middleware, tool registration, JSON-RPC framing.
func TestHTTPInitializeAndToolsList(t *testing.T) {
	const token = "test-token-1234567890"
	srv, err := New(Options{BaseURL: "http://127.0.0.1:1", AdminToken: token})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ts := httptest.NewServer(srv.HTTPHandler())
	defer ts.Close()

	// 1. initialize
	initReq := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"e2e","version":"0"}}}`
	body := doRPC(t, ts.URL, token, initReq)
	if !strings.Contains(body, `"serverInfo"`) || !strings.Contains(body, `"netcap-mcp"`) {
		t.Fatalf("initialize response missing serverInfo: %s", body)
	}

	// 2. tools/list
	listReq := `{"jsonrpc":"2.0","id":2,"method":"tools/list"}`
	body = doRPC(t, ts.URL, token, listReq)

	var resp struct {
		Result struct {
			Tools []struct {
				Name string `json:"name"`
			} `json:"tools"`
		} `json:"result"`
	}
	// Streamable HTTP can return either application/json or SSE-framed
	// JSON. doRPC returns the body verbatim; extract the first JSON
	// object we find.
	body = extractJSON(body)
	if err := json.Unmarshal([]byte(body), &resp); err != nil {
		t.Fatalf("decode tools/list: %v\nbody: %s", err, body)
	}
	if len(resp.Result.Tools) < 30 {
		t.Errorf("expected >=30 tools, got %d", len(resp.Result.Tools))
	}

	// Spot-check a few canonical tool names.
	want := map[string]bool{
		"ingest_pcap":            true,
		"list_hosts":             true,
		"list_connections":       true,
		"list_http_records":      true,
		"carve_subpcap_for_host": true,
	}
	for _, tl := range resp.Result.Tools {
		delete(want, tl.Name)
	}
	for name := range want {
		t.Errorf("expected tool %q to be registered", name)
	}
}

func doRPC(t *testing.T, url, token, body string) string {
	t.Helper()
	req, _ := http.NewRequest("POST", url+"/mcp", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		t.Fatalf("HTTP %d", resp.StatusCode)
	}
	buf := new(bytes.Buffer)
	_, _ = buf.ReadFrom(resp.Body)
	return buf.String()
}

// extractJSON peels off any SSE framing ("event: message\ndata: <json>\n\n")
// and returns the inner JSON payload. If the body is already plain JSON,
// it's returned unchanged.
//
// We anchor the match on a line-prefix ("\ndata: " or a leading "data: ")
// so a tool description that happens to contain the literal substring
// "data: " doesn't trip the parser.
func extractJSON(body string) string {
	trimmed := strings.TrimLeft(body, " \r\n")
	switch {
	case strings.HasPrefix(trimmed, "{"), strings.HasPrefix(trimmed, "["):
		return strings.TrimSpace(trimmed)
	}
	prefix := "\ndata: "
	i := strings.Index(body, prefix)
	if i < 0 {
		// Try leading "data: " at the start of the body.
		if strings.HasPrefix(trimmed, "data: ") {
			body = strings.TrimPrefix(trimmed, "data: ")
		} else {
			return strings.TrimSpace(body)
		}
	} else {
		body = body[i+len(prefix):]
	}
	if j := strings.Index(body, "\n"); j >= 0 {
		body = body[:j]
	}
	return strings.TrimSpace(body)
}
