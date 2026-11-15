package mcp

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/dreadl0ck/netcap/internal/distributed"
	"github.com/dreadl0ck/netcap/internal/flowexport"
	"github.com/dreadl0ck/netcap/internal/policy"
	"github.com/dreadl0ck/netcap/internal/protocoltest"
	mcplib "github.com/mark3labs/mcp-go/mcp"
)

func argumentsOf(t *testing.T, value any) map[string]any {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	var args map[string]any
	if err := json.Unmarshal(raw, &args); err != nil {
		t.Fatal(err)
	}
	return args
}

func TestFlowReceiverLifecycleAndNativeQuery(t *testing.T) {
	s, err := New(Options{BaseURL: "http://127.0.0.1:1", CarveDir: t.TempDir(), AllowNetwork: true})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	start := callCapability(t, s, "flow_receiver", argumentsOf(t, receiverRequest{Operation: "start", Listen: "127.0.0.1:0", DurationSeconds: 5, MaxOutputMB: 1}))
	if start.IsError {
		t.Fatal(resultText(t, start))
	}
	var started struct {
		Report struct {
			ID      string `json:"receiver_id"`
			Address string
		}
	}
	json.Unmarshal([]byte(resultText(t, start)), &started)
	address, err := net.ResolveUDPAddr("udp", started.Report.Address)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := net.DialUDP("udp", nil, address)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	data := make([]byte, 72)
	binary.BigEndian.PutUint16(data, 5)
	binary.BigEndian.PutUint16(data[2:], 1)
	binary.BigEndian.PutUint32(data[8:], 1700000000)
	copy(data[24:], []byte{192, 0, 2, 1})
	copy(data[28:], []byte{192, 0, 2, 2})
	binary.BigEndian.PutUint32(data[40:], 7)
	binary.BigEndian.PutUint32(data[44:], 900)
	if _, err := conn.Write(data); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(time.Second)
	for {
		s.protocolJobs.mu.Lock()
		dir := s.protocolJobs.entries[started.Report.ID].directory
		s.protocolJobs.mu.Unlock()
		raw, _ := os.ReadFile(filepath.Join(dir, "FlowExportsHealth.json"))
		var health flowexport.RecorderHealth
		json.Unmarshal(raw, &health)
		if health.Datagrams > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("receiver did not record datagram")
		}
		time.Sleep(5 * time.Millisecond)
	}
	stop := callCapability(t, s, "flow_receiver", argumentsOf(t, receiverRequest{Operation: "stop", ReceiverID: started.Report.ID}))
	if stop.IsError {
		t.Fatal(resultText(t, stop))
	}
	for {
		status := callCapability(t, s, "flow_receiver", argumentsOf(t, receiverRequest{Operation: "status", ReceiverID: started.Report.ID}))
		if strings.Contains(resultText(t, status), `"completed":true`) {
			break
		}
		if time.Now().After(deadline.Add(time.Second)) {
			t.Fatal("receiver did not finalize")
		}
		time.Sleep(5 * time.Millisecond)
	}
	domain := uint32(0)
	query := flowexport.Query{StartNs: 0, EndNs: time.Now().Add(time.Second).UnixNano(), Exporter: conn.LocalAddr().String(), Format: "netflow-v5", Domain: &domain, TimeBasis: "receive", GroupBy: "srcIP", Limit: 10}
	result := callCapability(t, s, "flow_receiver", argumentsOf(t, receiverRequest{Operation: "query", ReceiverID: started.Report.ID, Query: &query}))
	text := resultText(t, result)
	if result.IsError || !strings.Contains(text, `"bytes":"900"`) || !strings.Contains(text, "sourceSHA256") {
		t.Fatal(text)
	}
	deleted := callCapability(t, s, "flow_receiver", argumentsOf(t, receiverRequest{Operation: "delete", ReceiverID: started.Report.ID}))
	if deleted.IsError {
		t.Fatal(resultText(t, deleted))
	}
	if result := callCapability(t, s, "flow_receiver", argumentsOf(t, receiverRequest{Operation: "query", ReceiverID: started.Report.ID, Query: &query})); !result.IsError {
		t.Fatal("deleted receiver remained queryable")
	}
}
func resultText(t *testing.T, result *mcplib.CallToolResult) string {
	t.Helper()
	if result == nil || len(result.Content) == 0 {
		t.Fatal("missing tool result")
	}
	return result.Content[0].(mcplib.TextContent).Text
}

func TestCapabilityInventoryCoversExactRegisteredSurface(t *testing.T) {
	s, err := New(Options{BaseURL: "http://127.0.0.1:1", CarveDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	tools := s.mcpSrv.ListTools()
	seen := map[string]bool{}
	for _, cap := range capabilities() {
		if cap.ID == "" || cap.Contract == "" {
			t.Fatal("unqualified capability")
		}
		for _, name := range cap.Tools {
			if seen[name] {
				t.Errorf("tool %s mapped twice", name)
			}
			seen[name] = true
			if tools[name] == nil {
				t.Errorf("inventory advertises unregistered tool %s", name)
			}
		}
	}
	for name := range tools {
		if !seen[name] {
			t.Errorf("tool %s has no capability/workflow classification", name)
		}
	}
	if err := s.addTool(*s.mcpSrv.GetTool("get_features")); err == nil {
		t.Fatal("duplicate registration silently overwrote a contract")
	}
	for _, contract := range []struct {
		path   string
		tokens []string
	}{
		{"../policycontrol/transport.go", []string{"get_policy_capabilities", "stage_policy_revision", "activate_policy_deployment", "rollback_policy_deployment", "/mcp"}},
		{"../firewallfleet/transport.go", []string{"fleet_", "/mcp", "descriptors"}},
	} {
		raw, err := os.ReadFile(contract.path)
		if err != nil {
			t.Fatal(err)
		}
		for _, token := range contract.tokens {
			if !strings.Contains(string(raw), token) {
				t.Errorf("native MCP discovery drifted: %s lacks %s", contract.path, token)
			}
		}
	}
}

func TestProtocolGrammarGenerationAndArtifactPaging(t *testing.T) {
	s, err := New(Options{BaseURL: "http://127.0.0.1:1", CarveDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	grammar := grammarRequest{Grammar: protocoltest.Grammar{Version: 1, Framing: protocoltest.Framing{Kind: "fixed", FixedSize: 2, MaxBytes: 8}, MaxFrames: 4, Fields: []protocoltest.FieldSpec{{Name: "opcode", Offset: 0, Length: 1, Kind: "unsigned", ByteOrder: "big", Hypothesis: "declared opcode"}}}, Data: []byte{7, 9}}
	result := callCapability(t, s, "interpret_protocol_grammar", argumentsOf(t, grammar))
	text := resultText(t, result)
	if result.IsError || !strings.Contains(text, "declared opcode") || !strings.Contains(text, "inputSHA256") {
		t.Fatal(text)
	}
	result = callCapability(t, s, "generate_protocol_corpus", argumentsOf(t, corpusRequest{Data: []byte{1, 2}, MaxCases: 16, MaxBytes: 256, TargetVersion: "fixture-v1"}))
	if result.IsError || !strings.Contains(resultText(t, result), "protocoltest-v2") {
		t.Fatal(result)
	}
	large := s.operationResult("fixture", map[string]any{"bytes": strings.Repeat("x", MaxResponseBytes+1)}, nil)
	var ref struct {
		ID string `json:"artifact_id"`
	}
	if err := json.Unmarshal([]byte(resultText(t, large)), &ref); err != nil || ref.ID == "" {
		t.Fatal("large report was not retained")
	}
	page := callCapability(t, s, "read_mcp_artifact", map[string]any{"artifact_id": ref.ID, "limit": 32})
	var content struct {
		Data string
		Type string `json:"content_type"`
	}
	json.Unmarshal([]byte(resultText(t, page)), &content)
	decoded, err := base64.StdEncoding.DecodeString(content.Data)
	if err != nil || len(decoded) != 32 || content.Type != "application/json" {
		t.Fatal("invalid report page/MIME")
	}
	entry := s.carve.Get(ref.ID)
	if filepath.Ext(entry.Path) != ".json" {
		t.Fatal("report stored with misleading extension")
	}
	result = callCapability(t, s, "run_protocol_exchange", argumentsOf(t, protocoltest.Exchange{Version: 1, Network: "tcp", Address: "127.0.0.1:1"}))
	if !result.IsError || !strings.Contains(resultText(t, result), "network policy") {
		t.Fatal("existing network-disable policy bypassed")
	}
}

func TestProtocolOwnedListenersAndExchangeWorkflow(t *testing.T) {
	for _, network := range []string{"tcp", "udp"} {
		t.Run(network, func(t *testing.T) {
			s, err := New(Options{BaseURL: "http://127.0.0.1:1", CarveDir: t.TempDir(), AllowNetwork: true})
			if err != nil {
				t.Fatal(err)
			}
			defer s.stopProtocolJobs()
			spec := protocoltest.Exchange{Version: 1, Network: network, Address: "127.0.0.1:0", Framing: protocoltest.Framing{Kind: "fixed", FixedSize: 4, MaxBytes: 16}, TimeoutMilliseconds: 2000, MaxTotalBytes: 64, Steps: []protocoltest.Step{{Name: "fresh", Receive: true, CaptureVariable: "fresh", CaptureLength: 4}, {Name: "reply", SendVariable: "fresh"}}}
			start := callCapability(t, s, "start_protocol_listener", argumentsOf(t, protocolListenerRequest{Mode: "server", Listen: "127.0.0.1:0", Exchange: &spec}))
			if start.IsError {
				t.Fatal(resultText(t, start))
			}
			var started struct {
				Report struct {
					ID      string `json:"job_id"`
					Address string
				}
			}
			json.Unmarshal([]byte(resultText(t, start)), &started)
			spec.Address = started.Report.Address
			spec.Steps = []protocoltest.Step{{Name: "echo", Send: []byte{0, 1, 2, 255}, Receive: true, Expect: []byte{0, 1, 2, 255}}}
			response := callCapability(t, s, "run_protocol_exchange", argumentsOf(t, spec))
			if response.IsError || !strings.Contains(resultText(t, response), "AAEC/w==") {
				t.Fatal(resultText(t, response))
			}
			deadline := time.Now().Add(2 * time.Second)
			for {
				result := callCapability(t, s, "get_protocol_job", map[string]any{"job_id": started.Report.ID, "consume": true})
				text := resultText(t, result)
				if strings.Contains(text, "configurationSHA256") {
					if result.IsError {
						t.Fatal(text)
					}
					break
				}
				if time.Now().After(deadline) {
					t.Fatal("listener did not finish")
				}
				time.Sleep(5 * time.Millisecond)
			}
			if result := callCapability(t, s, "get_protocol_job", map[string]any{"job_id": started.Report.ID}); !result.IsError {
				t.Fatal("consumed job remained addressable")
			}
		})
	}
}

func TestFirewallSimulationAndDistributedPlanUseCoreContracts(t *testing.T) {
	s, err := New(Options{BaseURL: "http://127.0.0.1:1", CarveDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	r := firewallSimulation{Bundle: `{"version":"1","id":"fixture","mode":"enforce","default":"deny","rules":[{"id":"get","expression":"Method == 'GET'","action":"allow"}]}`, Events: []policy.Event{{Method: "GET", Protocol: "http"}, {Method: "POST", Protocol: "http"}}}
	result := callCapability(t, s, "evaluate_firewall_policy", argumentsOf(t, r))
	text := resultText(t, result)
	if result.IsError || !strings.Contains(text, `"verdict":"allow"`) || !strings.Contains(text, `"verdict":"deny"`) || !strings.Contains(text, `"effects_dispatched":false`) {
		t.Fatal(text)
	}
	dir := t.TempDir()
	cert, key := filepath.Join(dir, "agent.crt"), filepath.Join(dir, "agent.key")
	fp, err := distributed.GenerateIdentity(cert, key, "fixture")
	if err != nil {
		t.Fatal(err)
	}
	plan := distributedPlan{Role: "collector", Certificate: cert, Key: key, Address: "127.0.0.1:1335", Clients: fp + " sensor-one\n", OutputDirectory: filepath.Join(dir, "collected"), MaxFrameBytes: 4096, MaxConnections: 2}
	result = callCapability(t, s, "prepare_distributed_configuration", argumentsOf(t, plan))
	text = resultText(t, result)
	if result.IsError || !strings.Contains(text, "-max-conns=2") || !strings.Contains(text, fp) || strings.Contains(text, "PRIVATE KEY") {
		t.Fatal(text)
	}
	plan.Clients = fp + " ../foreign\n"
	if result := callCapability(t, s, "prepare_distributed_configuration", argumentsOf(t, plan)); !result.IsError {
		t.Fatal("enrollment path boundary bypassed")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	tool := s.mcpSrv.GetTool("run_protocol_exchange")
	result, _ = tool.Handler(ctx, mcplib.CallToolRequest{Params: mcplib.CallToolParams{Arguments: argumentsOf(t, protocoltest.Exchange{})}})
	if !result.IsError {
		t.Fatal("canceled operation succeeded")
	}
}
