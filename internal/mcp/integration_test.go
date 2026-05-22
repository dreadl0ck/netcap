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
	"strings"
	"testing"
	"time"

	"github.com/mark3labs/mcp-go/client"
	mcplib "github.com/mark3labs/mcp-go/mcp"
)

// TestIntegrationFullWorkflow exercises the canonical analyst workflow
// end-to-end via mcp-go's in-process client:
//
//  1. tools/list — confirm catalogue
//  2. CallTool(ingest_pcap, path) — get session_id
//  3. CallTool(wait_for_session, session_id) — block until completed
//  4. CallTool(list_hosts, session_id) — read hosts
//  5. CallTool(query_audit_records, type=DNS, filter=...) — typed query
//  6. CallTool(get_chart_data) — time-series
//  7. ReadResource(netcap://session/<id>/graph) — derived graph
//  8. CallTool(delete_session) — cleanup
//
// The webui is stubbed via httptest so the test is hermetic. This is
// the test we'd otherwise want to write with the real net binary, but
// running a full collector pipeline takes >1s per case which makes the
// suite painful. The fake mirrors the surface area the MCP layer
// actually depends on.
func TestIntegrationFullWorkflow(t *testing.T) {
	fake := &fakeNetcapWebui{
		t:          t,
		sessionID:  "0123456789abcdef0123456789abcdef",
		inputFile:  "/tmp/uploads/sample.pcap",
		recordType: "DNS",
		records: []json.RawMessage{
			json.RawMessage(`{"Timestamp":1700000000,"QR":false,"Questions":[{"Name":"evil.example"}],"SrcIP":"10.0.0.1","DstIP":"10.0.0.2"}`),
			json.RawMessage(`{"Timestamp":1700000001,"QR":true, "Questions":[{"Name":"evil.example"}],"SrcIP":"10.0.0.2","DstIP":"10.0.0.1"}`),
		},
	}
	ts := httptest.NewServer(fake)
	defer ts.Close()

	srv, err := New(Options{BaseURL: ts.URL})
	if err != nil {
		t.Fatalf("mcp.New: %v", err)
	}

	cli, err := client.NewInProcessClient(srv.mcpSrv)
	if err != nil {
		t.Fatalf("NewInProcessClient: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := cli.Start(ctx); err != nil {
		t.Fatalf("client Start: %v", err)
	}
	if _, err := cli.Initialize(ctx, mcplib.InitializeRequest{
		Params: mcplib.InitializeParams{
			ProtocolVersion: "2024-11-05",
			ClientInfo:      mcplib.Implementation{Name: "integration-test", Version: "0"},
		},
	}); err != nil {
		t.Fatalf("Initialize: %v", err)
	}

	// 1. tools/list — catalogue sanity check.
	tools, err := cli.ListTools(ctx, mcplib.ListToolsRequest{})
	if err != nil {
		t.Fatalf("ListTools: %v", err)
	}
	expected := []string{
		"ingest_pcap", "list_sessions", "get_session_info", "list_decoders",
		"list_hosts", "list_connections", "query_audit_records",
		"get_audit_record_fields", "get_chart_data", "lookup_cve",
		"resolve", "extract_iocs_from_file", "delete_session",
		"wait_for_session",
	}
	have := map[string]bool{}
	for _, tt := range tools.Tools {
		have[tt.Name] = true
	}
	for _, n := range expected {
		if !have[n] {
			t.Errorf("missing tool %q in catalogue", n)
		}
	}

	// 2. ingest_pcap — this stub doesn't actually shell out to net capture,
	// the fake webui's /api/upload returns a canned session id.
	ingest := callTool(t, cli, ctx, "ingest_pcap", map[string]any{
		"path": "/etc/hosts", // any existing file; only the upload path is exercised
	})
	if ingest.IsError {
		t.Fatalf("ingest_pcap error: %s", contentText(ingest))
	}
	var ingestOut map[string]any
	_ = json.Unmarshal([]byte(contentText(ingest)), &ingestOut)
	sid, _ := ingestOut["session_id"].(string)
	if sid == "" {
		t.Fatalf("session_id missing from ingest result: %s", contentText(ingest))
	}

	// 3. wait_for_session — fake marks isCompleted=true immediately.
	wait := callTool(t, cli, ctx, "wait_for_session", map[string]any{
		"session_id":       sid,
		"timeout_seconds":  5,
		"poll_interval_ms": 100,
	})
	if wait.IsError {
		t.Fatalf("wait_for_session error: %s", contentText(wait))
	}
	var waitOut map[string]any
	_ = json.Unmarshal([]byte(contentText(wait)), &waitOut)
	if waitOut["completed"] != true {
		t.Errorf("wait completed = %v", waitOut["completed"])
	}

	// 4. list_hosts — verify ?sessionId= / ?inputFile= passthrough.
	hosts := callTool(t, cli, ctx, "list_hosts", map[string]any{"session_id": sid})
	if hosts.IsError {
		t.Fatalf("list_hosts error: %s", contentText(hosts))
	}
	if !strings.Contains(contentText(hosts), "10.0.0.1") {
		t.Errorf("hosts missing canned IPs: %s", contentText(hosts))
	}

	// 5. query_audit_records DNS QR=true — should return one record.
	q := callTool(t, cli, ctx, "query_audit_records", map[string]any{
		"session_id": sid,
		"type":       "DNS",
		"filter":     "QR == true",
		"limit":      10,
	})
	if q.IsError {
		t.Fatalf("query_audit_records error: %s", contentText(q))
	}
	var qOut map[string]any
	_ = json.Unmarshal([]byte(contentText(q)), &qOut)
	if qOut["terminal"] != "complete" {
		t.Errorf("terminal = %v", qOut["terminal"])
	}
	recs, _ := qOut["records"].([]any)
	if len(recs) != 1 {
		t.Errorf("records = %d, want 1 (filter QR == true)", len(recs))
	}

	// 6. get_chart_data — exercise the JSON output path.
	chart := callTool(t, cli, ctx, "get_chart_data", map[string]any{
		"session_id": sid,
		"type":       "Connection",
		"field":      "TotalSize",
	})
	if chart.IsError {
		t.Fatalf("get_chart_data error: %s", contentText(chart))
	}
	if !strings.Contains(contentText(chart), `"data"`) {
		t.Errorf("chart missing data: %s", contentText(chart))
	}

	// 7. Resource read: netcap://session/<sid>/graph.
	graph, err := cli.ReadResource(ctx, mcplib.ReadResourceRequest{
		Params: mcplib.ReadResourceParams{URI: "netcap://session/" + sid + "/graph"},
	})
	if err != nil {
		t.Fatalf("ReadResource graph: %v", err)
	}
	if len(graph.Contents) != 1 {
		t.Fatalf("graph contents = %d", len(graph.Contents))
	}
	gText, _ := graph.Contents[0].(mcplib.TextResourceContents)
	if !strings.Contains(gText.Text, `"node_count"`) {
		t.Errorf("graph missing node_count: %s", gText.Text)
	}

	// 8. delete_session — service-mode session id.
	del := callTool(t, cli, ctx, "delete_session", map[string]any{"session_id": fake.sessionID})
	if del.IsError {
		t.Fatalf("delete_session error: %s", contentText(del))
	}
	if !strings.Contains(contentText(del), "removed_paths") {
		t.Errorf("delete body missing removed_paths: %s", contentText(del))
	}
}

func callTool(t *testing.T, cli *client.Client, ctx context.Context, name string, args map[string]any) *mcplib.CallToolResult {
	t.Helper()
	req := mcplib.CallToolRequest{Params: mcplib.CallToolParams{Name: name, Arguments: args}}
	res, err := cli.CallTool(ctx, req)
	if err != nil {
		t.Fatalf("CallTool(%s): %v", name, err)
	}
	return res
}

// fakeNetcapWebui implements the subset of /api endpoints the MCP layer
// uses, with just enough state to drive the full integration workflow.
type fakeNetcapWebui struct {
	t          *testing.T
	sessionID  string
	inputFile  string
	recordType string
	records    []json.RawMessage
}

func (f *fakeNetcapWebui) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch {
	case r.URL.Path == "/api/upload":
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"success":true,"id":"hash123","filename":"sample.pcap","path":%q,"size":468,"sessionId":%q}`,
			f.inputFile, f.sessionID)
	case r.URL.Path == "/api/audit-stats":
		fmt.Fprint(w, `{"totalRecords":2}`)
	case r.URL.Path == "/api/status":
		fmt.Fprint(w, `{"isProcessing":false,"sessionId":"","activeInputFile":""}`)
	case r.URL.Path == "/api/files/input":
		fmt.Fprintf(w, `[{"path":%q,"name":"sample.pcap","size":468,"isCompleted":true,"sessionId":%q}]`,
			f.inputFile, f.sessionID)
	case r.URL.Path == "/api/hosts":
		fmt.Fprint(w, `{"hosts":[{"ip":"10.0.0.1","packets":1,"bytes":100},{"ip":"10.0.0.2","packets":1,"bytes":100}]}`)
	case r.URL.Path == "/api/connections":
		fmt.Fprint(w, `[{"srcIP":"10.0.0.1","dstIP":"10.0.0.2","numPackets":2,"totalSize":200,"service":"dns"}]`)
	case strings.HasPrefix(r.URL.Path, "/api/audit/") && strings.HasSuffix(r.URL.Path, "/stream"):
		w.Header().Set("Content-Type", "text/event-stream")
		filter := r.URL.Query().Get("filter")
		// Cheap "QR == true" filter: only emit records that contain QR:true.
		matched := 0
		for _, rec := range f.records {
			if filter == "QR == true" && !strings.Contains(string(rec), `"QR":true`) {
				continue
			}
			fmt.Fprintf(w, "event: record\ndata: %s\n\n", string(rec))
			matched++
		}
		fmt.Fprintf(w, "event: complete\ndata: {\"total\":%d,\"scanned\":%d,\"executionTimeMs\":1}\n\n",
			matched, len(f.records))
	case r.URL.Path == "/api/chart/data":
		fmt.Fprint(w, `{"type":"Connection","field":"TotalSize","interval":"1s","data":[{"timestamp":1700000000,"value":200}],"count":1,"minValue":200,"maxValue":200,"avgValue":200}`)
	case strings.HasPrefix(r.URL.Path, "/api/try/session/"):
		// Only DELETE is exercised by the workflow after T2.1.
		if r.Method == http.MethodDelete {
			fmt.Fprintf(w, `{"success":true,"session_id":%q,"removed_paths":["/tmp/uploads/x","/tmp/results/x"]}`, f.sessionID)
			return
		}
		http.NotFound(w, r)
	default:
		http.NotFound(w, r)
	}
}
