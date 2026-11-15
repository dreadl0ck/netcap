package mcp_test

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/dreadl0ck/netcap/cmd/capture/webui"
	"github.com/dreadl0ck/netcap/internal/behavior"
	"github.com/dreadl0ck/netcap/internal/delimited"
	"github.com/dreadl0ck/netcap/internal/evidence"
	netmcp "github.com/dreadl0ck/netcap/internal/mcp"
	"github.com/dreadl0ck/netcap/internal/rules"
	"github.com/dreadl0ck/netcap/types"
	mcplib "github.com/mark3labs/mcp-go/mcp"
)

// Exercise the real HTTP selection/authentication middleware and flow/rule
// handlers, not a second implementation of their request contract.
func TestCapabilityRealBackendWorkflow(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("NC_CONFIG_ROOT", t.TempDir())
	input := filepath.Join(dir, "source.pcap")
	if err := os.WriteFile(input, []byte("registered fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	var data bytes.Buffer
	gz := gzip.NewWriter(&data)
	writer := delimited.NewWriter(gz)
	if err := writer.PutProto(&types.Header{Type: types.Type_NC_Connection}); err != nil {
		t.Fatal(err)
	}
	for _, snapshot := range []struct {
		sequence uint64
		bytes    int64
	}{{1, 100}, {2, 150}} {
		if err := writer.PutProto(&types.Connection{SrcIP: "192.0.2.1", DstIP: "192.0.2.2", SrcPort: "1234", DstPort: "443", NetworkProto: "IPv4", TransportProto: "TCP", TimestampFirst: 100, TimestampLast: 200, CounterSemantics: "tuple-cumulative", ObservationID: "fixture-observation", SnapshotSequence: snapshot.sequence, TotalSize64: snapshot.bytes, NumPackets64: int64(snapshot.sequence)}); err != nil {
			t.Fatal(err)
		}
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "Connection.ncap.gz"), data.Bytes(), 0600); err != nil {
		t.Fatal(err)
	}
	data.Reset()
	writer = delimited.NewWriter(&data)
	if err := writer.PutProto(&types.Header{Type: types.Type_NC_TCP}); err != nil {
		t.Fatal(err)
	}
	for _, timestamp := range []int64{100, 200} {
		if err := writer.PutProto(&types.TCP{Timestamp: timestamp, SrcIP: "192.0.2.1", DstIP: "192.0.2.2", DstPort: 443, CommunityID: "1:test"}); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(dir, "TCP.ncap"), data.Bytes(), 0600); err != nil {
		t.Fatal(err)
	}
	manifest := evidence.CaptureManifest{Version: 1, RunID: "test-run", Status: "complete", Config: evidence.CaptureConfig{Kind: "file"}, CommunityScopes: &evidence.ScopeLedger{Schema: 1, Complete: true, Entries: []evidence.CommunityScope{{CommunityID: "1:test", Scope: evidence.FlowScope{Sensor: "local", InterfaceIndex: 0, VLANs: []uint16{}}}}}}
	for name, value := range map[string]any{"capture-manifest.json": manifest, rules.OfflineReadyFile: rules.OfflineReadyMarker{Version: 1, RunID: "test-run"}} {
		encoded, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, name), encoded, 0600); err != nil {
			t.Fatal(err)
		}
	}
	sink, err := rules.NewFileAlertWriter(dir)
	if err != nil {
		t.Fatal(err)
	}
	engine, err := behavior.Open(behavior.Config{Path: filepath.Join(dir, "Behavior.json"), MinLearning: time.Second, MinSamples: 2, MaxFacts: 100}, sink)
	if err != nil {
		t.Fatal(err)
	}
	if err := engine.Close(); err != nil {
		t.Fatal(err)
	}
	if err := sink.Close(); err != nil {
		t.Fatal(err)
	}
	backend := webui.NewServer("127.0.0.1:0", dir, []string{input}, "", false, false, false, nil, nil, false)
	backend.MarkFileCompleted(input)
	backend.SetFileOutputDir(input, dir)
	if err := backend.Start(); err != nil {
		t.Fatal(err)
	}
	defer backend.Stop(context.Background())
	s, err := netmcp.New(netmcp.Options{BaseURL: backend.GetURL(), AdminToken: backend.LocalAccessToken(), CarveDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	endpoint := httptest.NewServer(s.HTTPHandler())
	defer endpoint.Close()
	call := func(name string, arguments map[string]any, wantError bool) string {
		t.Helper()
		payload, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": map[string]any{"name": name, "arguments": arguments}})
		req, _ := http.NewRequest(http.MethodPost, endpoint.URL+"/mcp", bytes.NewReader(payload))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json, text/event-stream")
		req.Header.Set("Authorization", "Bearer "+backend.LocalAccessToken())
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		encoded := strings.TrimSpace(string(body))
		if strings.HasPrefix(encoded, "event:") {
			for _, line := range strings.Split(encoded, "\n") {
				if strings.HasPrefix(line, "data: ") {
					encoded = strings.TrimPrefix(line, "data: ")
					break
				}
			}
		}
		var result struct {
			Result mcplib.CallToolResult `json:"result"`
			Error  any                   `json:"error"`
		}
		if err := json.Unmarshal([]byte(encoded), &result); err != nil {
			t.Fatalf("%s: %s: %v", name, body, err)
		}
		if result.Error != nil || result.Result.IsError != wantError || len(result.Result.Content) == 0 {
			t.Fatalf("%s: %s", name, body)
		}
		return result.Result.Content[0].(mcplib.TextContent).Text
	}
	flow := map[string]any{"session_id": input, "startNs": "0", "endNs": "300", "filter": "DstPort == '443'", "limit": 10}
	call("set_bpf_config", map[string]any{"filter": "tcp port 443"}, false)
	if text := call("get_bpf_config", nil, false); !strings.Contains(text, "tcp port 443") {
		t.Fatal(text)
	}
	call("set_decoder_config", map[string]any{"includeDecoders": "TCP,DNS", "excludeDecoders": ""}, false)
	if text := call("get_decoder_config", nil, false); !strings.Contains(text, "TCP,DNS") {
		t.Fatal(text)
	}
	text := call("query_flows", flow, false)
	if !strings.Contains(text, `"bytes":"150"`) || !strings.Contains(text, `"collapsedSnapshots":1`) || !strings.Contains(text, `"recordFileSHA256"`) {
		t.Fatalf("cumulative snapshots double counted or lost provenance: %s", text)
	}
	var result struct {
		Hash string `json:"recordFileSHA256"`
	}
	if err := json.Unmarshal([]byte(text), &result); err != nil {
		t.Fatal(err)
	}
	flow["offset"], flow["expectedSHA256"] = 1, strings.Repeat("0", 64)
	if text := call("query_flows", flow, true); !strings.Contains(text, "hash changed") {
		t.Fatal(text)
	}
	flow["session_id"] = filepath.Join(dir, "foreign.pcap")
	if text := call("query_flows", flow, true); !strings.Contains(text, "Unknown capture input") {
		t.Fatal(text)
	}
	pack := "format: netcap-offline-rules/v1\nrules:\n  - id: fixture.https\n    name: HTTPS\n    type: TCP\n    expression: DstPort == 443\n    enabled: true\n    severity: low\n    threshold:\n      count: 2\n      window: 60s\n      group_by: [SrcIP]\n"
	if text := call("validate_offline_rule_pack", map[string]any{"yaml": pack}, false); !strings.Contains(text, `"valid":true`) {
		t.Fatal(text)
	}
	if text := call("execute_offline_rule_pack", map[string]any{"session_id": input, "yaml": pack}, false); !strings.Contains(text, `"report"`) {
		t.Fatal(text)
	}
	if text := call("list_offline_evaluations", map[string]any{"session_id": input}, false); !strings.Contains(text, "fixture.https") {
		t.Fatal(text)
	}
	text = call("get_behavior", map[string]any{"session_id": input}, false)
	var baseline struct {
		Version uint64 `json:"version"`
	}
	if err := json.Unmarshal([]byte(text), &baseline); err != nil {
		t.Fatal(err)
	}
	if text := call("change_behavior", map[string]any{"session_id": input, "action": "pause", "version": baseline.Version, "reason": "maintenance"}, false); !strings.Contains(text, `"mode":"paused"`) {
		t.Fatal(text)
	}
	if text := call("change_behavior", map[string]any{"session_id": input, "action": "resume", "version": baseline.Version + 99, "reason": "stale decision"}, true); !strings.Contains(text, "version changed") {
		t.Fatal(text)
	}
	call("set_feature", map[string]any{"name": "evidence-links", "enabled": false}, false)
	if text := call("get_related_evidence", map[string]any{"session_id": input, "type": "Connection", "ordinal": 0}, true); !strings.Contains(text, "disabled") {
		t.Fatal(text)
	}
}
