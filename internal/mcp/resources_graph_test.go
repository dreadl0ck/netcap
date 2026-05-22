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

// TestBuildHostGraphAggregates verifies the per-edge aggregation of
// packets/bytes plus the deduplicated services list. The fixtures are
// representative of what /api/hosts and /api/connections actually
// return.
func TestBuildHostGraphAggregates(t *testing.T) {
	hosts := json.RawMessage(`{"hosts":[
		{"ip":"10.0.0.1","packets":100,"bytes":1024,"country":"US"},
		{"ip":"10.0.0.2","packets":50,"bytes":512}
	]}`)
	conns := json.RawMessage(`[
		{"srcIP":"10.0.0.1","dstIP":"10.0.0.2","numPackets":10,"totalSize":256,"service":"http"},
		{"srcIP":"10.0.0.1","dstIP":"10.0.0.2","numPackets":5,"totalSize":128,"service":"http"},
		{"srcIP":"10.0.0.1","dstIP":"10.0.0.2","numPackets":2,"totalSize":64,"service":"dns"},
		{"srcIP":"10.0.0.2","dstIP":"10.0.0.1","numPackets":20,"totalSize":512,"service":"http"}
	]`)

	g, err := buildHostGraph(hosts, conns)
	if err != nil {
		t.Fatalf("buildHostGraph: %v", err)
	}
	if g["node_count"] != 2 {
		t.Errorf("node_count = %v", g["node_count"])
	}
	if g["edge_count"] != 2 {
		t.Errorf("edge_count = %v", g["edge_count"])
	}
	// Find the forward edge and confirm aggregated counters.
	edges := g["edges"].([]map[string]any)
	var forward map[string]any
	for _, e := range edges {
		if e["src"] == "10.0.0.1" && e["dst"] == "10.0.0.2" {
			forward = e
			break
		}
	}
	if forward == nil {
		t.Fatalf("forward edge missing: %v", edges)
	}
	if forward["packets"].(int64) != 17 {
		t.Errorf("packets = %v", forward["packets"])
	}
	if forward["bytes"].(int64) != 448 {
		t.Errorf("bytes = %v", forward["bytes"])
	}
	services, _ := forward["services"].([]string)
	if len(services) != 2 {
		t.Errorf("services = %v", services)
	}
}

// TestBuildHostGraphHandlesAlternateConnsShape: /api/connections may
// return {connections: [...]} instead of a bare array; the builder
// accepts both.
func TestBuildHostGraphHandlesAlternateConnsShape(t *testing.T) {
	hosts := json.RawMessage(`{"hosts":[{"ip":"1.1.1.1"}]}`)
	conns := json.RawMessage(`{"connections":[
		{"srcIP":"1.1.1.1","dstIP":"2.2.2.2","totalSize":10}
	]}`)
	g, err := buildHostGraph(hosts, conns)
	if err != nil {
		t.Fatalf("buildHostGraph: %v", err)
	}
	if g["edge_count"] != 1 {
		t.Errorf("edge_count = %v", g["edge_count"])
	}
}

// TestSessionGraphResourceEndToEnd drives the resource read against a
// fake webui that returns both endpoints.
func TestSessionGraphResourceEndToEnd(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/hosts", func(w http.ResponseWriter, r *http.Request) {
		// session_id is passed via ?inputFile= because the heuristic
		// treats /tmp/x.pcap as a path. Confirm it arrives.
		if r.URL.Query().Get("inputFile") != "/tmp/x.pcap" {
			t.Errorf("inputFile = %q", r.URL.Query().Get("inputFile"))
		}
		fmt.Fprint(w, `{"hosts":[{"ip":"10.0.0.1","packets":1},{"ip":"10.0.0.2"}]}`)
	})
	mux.HandleFunc("/api/connections", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `[{"srcIP":"10.0.0.1","dstIP":"10.0.0.2","numPackets":1}]`)
	})
	ts := httptest.NewServer(mux)
	defer ts.Close()

	srv, _ := New(Options{BaseURL: ts.URL})
	contents, err := srv.handleSessionGraphResource(context.Background(), mcplib.ReadResourceRequest{
		Params: mcplib.ReadResourceParams{URI: "netcap://session//tmp/x.pcap/graph"},
	})
	if err != nil {
		t.Fatalf("handleSessionGraphResource: %v", err)
	}
	if len(contents) != 1 {
		t.Fatalf("contents = %d", len(contents))
	}
	tc, ok := contents[0].(mcplib.TextResourceContents)
	if !ok {
		t.Fatalf("not TextResourceContents: %T", contents[0])
	}
	var g map[string]any
	if err := json.Unmarshal([]byte(tc.Text), &g); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if g["session_id"] != "/tmp/x.pcap" {
		t.Errorf("session_id = %v", g["session_id"])
	}
	if g["node_count"].(float64) != 2 {
		t.Errorf("node_count = %v", g["node_count"])
	}
	if g["edge_count"].(float64) != 1 {
		t.Errorf("edge_count = %v", g["edge_count"])
	}
}
