/*
 * NETCAP - Traffic Analysis Framework
 * Copyright (c) Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
 * License: GNU General Public License v3.0
 */

package mcp

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	mcplib "github.com/mark3labs/mcp-go/mcp"
)

// TestMetricsRecordsToolCall drives one tool through the middleware and
// asserts the resulting Prometheus scrape contains the expected counter
// + histogram bumps.
func TestMetricsRecordsToolCall(t *testing.T) {
	srv, err := New(Options{BaseURL: "http://127.0.0.1:1"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// Drive the lookup_cve tool (cheap, no upstream HTTP needed because
	// AllowNetwork is false → the handler returns a "disabled" error).
	tool := srv.mcpSrv.GetTool("lookup_cve")
	if tool == nil {
		t.Fatal("lookup_cve not registered")
	}
	for i := 0; i < 3; i++ {
		_, _ = tool.Handler(context.Background(), mcplib.CallToolRequest{
			Params: mcplib.CallToolParams{
				Name:      "lookup_cve",
				Arguments: map[string]any{"cve_id": "CVE-2021-44228"},
			},
		})
	}
	// The middleware fires from the MCP server's request path, not the
	// direct handler call. Simulate that by going through the wrapped
	// middleware ourselves.
	wrapped := srv.toolLogMiddleware(tool.Handler)
	for i := 0; i < 3; i++ {
		_, _ = wrapped(context.Background(), mcplib.CallToolRequest{
			Params: mcplib.CallToolParams{
				Name:      "lookup_cve",
				Arguments: map[string]any{"cve_id": "CVE-2021-44228"},
			},
		})
	}

	// Scrape /metrics and look for our counters.
	rec := httptest.NewRecorder()
	srv.MetricsHandler().ServeHTTP(rec, httptest.NewRequest("GET", "/metrics", nil))
	body := rec.Body.String()
	if rec.Code != http.StatusOK {
		t.Fatalf("scrape: %d", rec.Code)
	}
	// Expected metric names + a labelled counter line.
	for _, want := range []string{
		"netcap_mcp_tool_calls_total",
		"netcap_mcp_tool_errors_total",
		"netcap_mcp_tool_duration_seconds",
		"netcap_mcp_tool_response_bytes",
		"netcap_mcp_carve_entries",
		`netcap_mcp_tool_calls_total{status="error_result",tool="lookup_cve"} 3`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("scrape missing %q\n--- body ---\n%s", want, truncateForLog(body, 2048))
		}
	}
}

// TestAuthedMetricsHandlerRequiresToken: the metrics endpoint should
// reject scrapes without the admin token in service-mode posture.
func TestAuthedMetricsHandlerRequiresToken(t *testing.T) {
	srv, err := New(Options{BaseURL: "http://127.0.0.1:1", AdminToken: "secret"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ts := httptest.NewServer(srv.AuthedMetricsHandler())
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/mcp/metrics")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected 401 for missing token, got %d", resp.StatusCode)
	}

	// With token: 200.
	req, _ := http.NewRequest("GET", ts.URL+"/mcp/metrics", nil)
	req.Header.Set("Authorization", "Bearer secret")
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET with token: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200 with token, got %d", resp.StatusCode)
	}
}

func truncateForLog(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "...[truncated]"
}
