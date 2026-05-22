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

// TestGetChartDataHandlerEndToEnd drives the chart_data tool against a
// fake webui that returns canned ChartDataResponse JSON, verifying the
// tool forwards arguments correctly and surfaces the payload.
func TestGetChartDataHandlerEndToEnd(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/set-directory", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"success":true}`)
	})
	mux.HandleFunc("/api/try/session/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"success":true}`)
	})
	mux.HandleFunc("/api/chart/data", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if q.Get("format") != "json" {
			t.Errorf("expected format=json, got %q", q.Get("format"))
		}
		if q.Get("type") != "Connection" {
			t.Errorf("type = %q", q.Get("type"))
		}
		if q.Get("field") != "TotalSize" {
			t.Errorf("field = %q", q.Get("field"))
		}
		if q.Get("interval") != "1m" {
			t.Errorf("interval = %q", q.Get("interval"))
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"type":"Connection","field":"TotalSize","interval":"1m","data":[{"timestamp":1700000000000,"value":1024},{"timestamp":1700000060000,"value":2048}],"count":2,"minValue":1024,"maxValue":2048,"avgValue":1536}`)
	})
	ts := httptest.NewServer(mux)
	defer ts.Close()

	srv, err := New(Options{BaseURL: ts.URL})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	tool := srv.mcpSrv.GetTool("get_chart_data")
	if tool == nil {
		t.Fatal("get_chart_data not registered")
	}

	res, err := tool.Handler(context.Background(), mcplib.CallToolRequest{
		Params: mcplib.CallToolParams{
			Name: "get_chart_data",
			Arguments: map[string]any{
				"session_id": "/tmp/x.pcap",
				"type":       "Connection",
				"field":      "TotalSize",
				"interval":   "1m",
			},
		},
	})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	if res.IsError {
		t.Fatalf("error result: %s", contentText(res))
	}
	var out map[string]any
	if jErr := json.Unmarshal([]byte(contentText(res)), &out); jErr != nil {
		t.Fatalf("decode: %v\n%s", jErr, contentText(res))
	}
	if out["type"] != "Connection" {
		t.Errorf("type = %v", out["type"])
	}
	data, _ := out["data"].([]any)
	if len(data) != 2 {
		t.Errorf("data points = %d, want 2", len(data))
	}
	if out["count"].(float64) != 2 {
		t.Errorf("count = %v", out["count"])
	}
}

// TestGetChartDataRejectsBadType protects the URL path.
func TestGetChartDataRejectsBadType(t *testing.T) {
	srv, _ := New(Options{BaseURL: "http://127.0.0.1:1"})
	tool := srv.mcpSrv.GetTool("get_chart_data")
	res, _ := tool.Handler(context.Background(), mcplib.CallToolRequest{
		Params: mcplib.CallToolParams{
			Name: "get_chart_data",
			Arguments: map[string]any{
				"session_id": "/tmp/x.pcap",
				"type":       "../bad",
				"field":      "x",
			},
		},
	})
	if !res.IsError {
		t.Error("expected error for invalid type")
	}
}
