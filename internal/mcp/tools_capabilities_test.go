package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/dreadl0ck/netcap/internal/behavior"
	mcplib "github.com/mark3labs/mcp-go/mcp"
)

func callCapability(t *testing.T, s *Server, name string, args map[string]any) *mcplib.CallToolResult {
	t.Helper()
	tool := s.mcpSrv.GetTool(name)
	if tool == nil {
		t.Fatalf("missing tool %s", name)
	}
	result, err := tool.Handler(context.Background(), mcplib.CallToolRequest{Params: mcplib.CallToolParams{Name: name, Arguments: args}})
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func TestCapabilitySchemasAndSelectors(t *testing.T) {
	calls := 0
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.Header.Get("Authorization") != "Bearer test-run" {
			t.Error("lost per-run authentication")
		}
		if r.URL.Path == "/api/flows/exports/query" {
			q := r.URL.Query()
			if q.Get("domain") != "0" || q.Get("startNs") != "1800000000000000001" || q.Get("inputFile") != "/owned.pcap" {
				t.Errorf("inexact query %s", r.URL)
			}
		}
		if r.URL.Path == "/api/rules/offline/execute" {
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatal(err)
			}
			if body["sessionId"] != "owned" || body["yaml"] != "test pack" || len(body) != 2 {
				t.Errorf("unexpected body %#v", body)
			}
		}
		if r.URL.Path == "/api/behavior/change" {
			var body map[string]any
			_ = json.NewDecoder(r.Body).Decode(&body)
			if r.URL.Query().Get("sessionId") != "owned" || body["version"] != float64(0) || body["action"] != "pause" {
				t.Errorf("lost baseline CAS: %s %#v", r.URL, body)
			}
		}
		w.Write([]byte(`{"qualification":"partial evidence","success":true}`))
	}))
	defer backend.Close()
	s, err := New(Options{BaseURL: backend.URL, AdminToken: "test-run", ActiveSession: "/fallback.pcap"})
	if err != nil {
		t.Fatal(err)
	}
	for name, tool := range s.mcpSrv.ListTools() {
		if len(tool.Tool.RawInputSchema) == 0 {
			continue
		}
		encoded, err := json.Marshal(tool.Tool)
		if err != nil {
			t.Fatalf("%s cannot be advertised: %v", name, err)
		}
		if !strings.Contains(string(encoded), `"inputSchema"`) {
			t.Fatalf("%s missing schema", name)
		}
	}
	for _, tc := range []struct {
		name string
		args map[string]any
	}{
		{"query_flow_exports", map[string]any{"session_id": "/owned.pcap", "exporter": "192.0.2.1:2055", "format": "netflow-v5", "domain": 0, "startNs": "1800000000000000001", "endNs": "1800000000000000002"}},
		{"execute_offline_rule_pack", map[string]any{"session_id": "owned", "yaml": "test pack"}},
		{"change_behavior", map[string]any{"session_id": "owned", "action": "pause", "version": 0, "reason": "maintenance"}},
	} {
		if result := callCapability(t, s, tc.name, tc.args); result.IsError || !strings.Contains(result.Content[0].(mcplib.TextContent).Text, "partial evidence") {
			t.Fatalf("%s: %+v", tc.name, result)
		}
	}
	before := calls
	for _, tc := range []struct {
		name string
		args map[string]any
	}{
		{"get_capture_evidence", map[string]any{}},
		{"get_capture_evidence", map[string]any{"session_id": ""}},
		{"get_capture_evidence", map[string]any{"session_id": " "}},
		{"get_capture_evidence", map[string]any{"session_id": "owned", "inputFile": "/foreign.pcap"}},
		{"set_feature", map[string]any{"name": "evidence-links"}},
		{"set_feature", map[string]any{"name": "typo", "enabled": true}},
		{"set_protobuf_mapping", map[string]any{"port": 1.5, "messageType": "test.Msg"}},
		{"set_protobuf_mapping", map[string]any{"port": 65536, "messageType": "test.Msg"}},
		{"change_behavior", map[string]any{"session_id": "owned", "action": "pause", "reason": "maintenance"}},
		{"change_behavior", map[string]any{"session_id": "owned", "action": "pause", "reason": "maintenance", "version": float64(9007199254740992)}},
		{"query_flows", map[string]any{"session_id": "owned", "startNs": 1800000000000000001, "endNs": "1800000000000000002"}},
		{"validate_offline_rule_pack", map[string]any{"yaml": strings.Repeat("x", MaxResponseBytes+1)}},
	} {
		if result := callCapability(t, s, tc.name, tc.args); !result.IsError {
			t.Errorf("%s accepted %#v", tc.name, tc.args)
		}
	}
	if calls != before {
		t.Fatalf("invalid inputs reached backend: %d -> %d", before, calls)
	}
}

func TestCapabilityCancellationAndTypedBackendErrors(t *testing.T) {
	started := make(chan struct{})
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/features" {
			http.Error(w, "stale contract", 409)
			return
		}
		close(started)
		<-r.Context().Done()
	}))
	defer backend.Close()
	c := NewNetcapClient(backend.URL)
	_, err := c.GetContext(context.Background(), "/api/features", nil)
	var typed *BackendError
	if !errors.As(err, &typed) || typed.StatusCode != 409 || !strings.Contains(string(typed.Body), "stale contract") {
		t.Fatalf("lost typed error: %v", err)
	}
	s, err := New(Options{BaseURL: backend.URL})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan *mcplib.CallToolResult, 1)
	go func() {
		result, _ := s.mcpSrv.GetTool("get_capture_evidence").Handler(ctx, mcplib.CallToolRequest{Params: mcplib.CallToolParams{Arguments: map[string]any{"session_id": "owned"}}})
		done <- result
	}()
	<-started
	cancel()
	select {
	case result := <-done:
		if !result.IsError {
			t.Fatal("cancelled call succeeded")
		}
	case <-time.After(time.Second):
		t.Fatal("backend request ignored cancellation")
	}
}

func TestScanCancellationReachesBackend(t *testing.T) {
	t.Run("detection rules", func(t *testing.T) {
		testScanCancellationReachesBackend(t, "execute_detection_rules", "/api/rules/execute-all")
	})
	t.Run("YARA", func(t *testing.T) {
		testScanCancellationReachesBackend(t, "execute_yara_scan", "/api/yara/scan")
	})
}

func testScanCancellationReachesBackend(t *testing.T, tool, path string) {
	t.Helper()
	started, stopped, release := make(chan struct{}), make(chan struct{}), make(chan struct{})
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != path {
			http.NotFound(w, r)
			return
		}
		close(started)
		select {
		case <-r.Context().Done():
			close(stopped)
		case <-release:
		}
	}))
	defer backend.Close()
	defer close(release)
	s, err := New(Options{BaseURL: backend.URL})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan *mcplib.CallToolResult, 1)
	go func() {
		result, _ := s.mcpSrv.GetTool(tool).Handler(ctx, mcplib.CallToolRequest{Params: mcplib.CallToolParams{Arguments: map[string]any{"session_id": "owned"}}})
		done <- result
	}()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("scan did not reach backend")
	}
	cancel()
	select {
	case <-stopped:
	case <-time.After(time.Second):
		t.Fatal("backend scan ignored cancellation")
	}
	select {
	case result := <-done:
		if result == nil || !result.IsError {
			t.Fatal("cancelled call did not return a tool error")
		}
	case <-time.After(time.Second):
		t.Fatal("cancelled tool did not return")
	}
}

func TestCapabilityResponseBounds(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"data":"` + strings.Repeat("x", MaxResponseBytes) + `"}`))
	}))
	defer backend.Close()
	s, err := New(Options{BaseURL: backend.URL})
	if err != nil {
		t.Fatal(err)
	}
	result := callCapability(t, s, "get_features", nil)
	if result.IsError || contentSize(result) > 1000 {
		t.Fatalf("oversized response escaped: %d", contentSize(result))
	}
	var artifact struct {
		ID string `json:"artifact_id"`
	}
	if err := json.Unmarshal(result.RawStructuredContent, &artifact); err != nil {
		t.Fatal(err)
	}
	entry := s.carve.Get(artifact.ID)
	if entry == nil || len(entry.Bytes) <= MaxResponseBytes {
		t.Fatal("oversized response was not retained")
	}
	if _, err := readAllBounded(strings.NewReader("12345"), 4); err == nil {
		t.Fatal("transport accepted oversized response")
	}
}

func TestIngestRejectsIneffectiveLegacyOptionsBeforeUpload(t *testing.T) {
	s, err := New(Options{BaseURL: "http://127.0.0.1:1"})
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"dpi", "bpf", "include_decoders", "exclude_decoders"} {
		result := callCapability(t, s, "ingest_pcap", map[string]any{"path": "/does-not-exist.pcap", key: true})
		if !result.IsError || !strings.Contains(result.Content[0].(mcplib.TextContent).Text, "per-ingest option") {
			t.Fatalf("%s was silently accepted: %+v", key, result)
		}
	}
}

func TestBehaviorProjectionRetainsCoverageAndStableFactPages(t *testing.T) {
	observed := map[string]any{}
	for i := 0; i < 1000; i++ {
		observed[fmt.Sprintf("fact-%04d", i)] = map[string]any{"fact": map[string]any{"srcIP": "192.0.2.1", "kind": "service"}, "samples": 3, "provenance": strings.Repeat("x", 400)}
	}
	snapshot := map[string]any{"schema": behavior.SchemaVersion, "version": 7, "mode": "learning", "baselineId": "fixture", "overflow": 17, "outOfOrder": 2, "observed": observed, "decisions": []any{map[string]any{"action": "pause", "version": 6}}}
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/behavior" || r.URL.Query().Get("sessionId") != "owned" || len(r.URL.Query()) != 1 {
			t.Errorf("projection args escaped to backend: %s", r.URL)
		}
		_ = json.NewEncoder(w).Encode(snapshot)
	}))
	defer backend.Close()
	s, err := New(Options{BaseURL: backend.URL})
	if err != nil {
		t.Fatal(err)
	}
	result := callCapability(t, s, "get_behavior", map[string]any{"session_id": "owned", "limit": 3, "offset": 3})
	if result.IsError {
		t.Fatal(result)
	}
	var page struct {
		Version    int
		Overflow   int
		OutOfOrder int
		Total      int
		Counts     map[string]int
		Entries    []struct {
			ID    string
			Value json.RawMessage
		}
		HasMore bool `json:"has_more"`
	}
	text := result.Content[0].(mcplib.TextContent).Text
	if err := json.Unmarshal([]byte(text), &page); err != nil {
		t.Fatal(err)
	}
	if page.Version != 7 || page.Overflow != 17 || page.OutOfOrder != 2 || page.Total != 1000 || page.Counts["observed"] != 1000 || len(page.Entries) != 3 || page.Entries[0].ID != "fact-0003" || !page.HasMore {
		t.Fatalf("lost baseline qualifications/page bounds: %s", text)
	}
	if !strings.Contains(string(page.Entries[0].Value), "192.0.2.1") || contentSize(result) > 10000 {
		t.Fatal("fact values lost or page unbounded")
	}
	result = callCapability(t, s, "get_behavior", map[string]any{"session_id": "owned", "section": "summary"})
	if result.IsError || strings.Contains(result.Content[0].(mcplib.TextContent).Text, "fact-0000") {
		t.Fatal("summary leaked full fact collection")
	}
}
