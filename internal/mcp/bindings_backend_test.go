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
	"sync/atomic"
	"testing"

	"github.com/dreadl0ck/netcap/cmd/capture/webui"
	"github.com/dreadl0ck/netcap/internal/delimited"
	"github.com/dreadl0ck/netcap/internal/evidence"
	netmcp "github.com/dreadl0ck/netcap/internal/mcp"
	"github.com/dreadl0ck/netcap/internal/mcp/bindings"
	"github.com/dreadl0ck/netcap/types"
	mcplib "github.com/mark3labs/mcp-go/mcp"
)

func operatorRPC(t *testing.T, address, token, name string, args map[string]any, wantError bool) map[string]any {
	t.Helper()
	raw, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": map[string]any{"name": name, "arguments": args}})
	r, _ := http.NewRequest("POST", address+"/mcp", bytes.NewReader(raw))
	r.Header.Set("Authorization", "Bearer "+token)
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Accept", "application/json, text/event-stream")
	response, err := http.DefaultClient.Do(r)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	data, _ := io.ReadAll(response.Body)
	text := strings.TrimSpace(string(data))
	if strings.HasPrefix(text, "event:") {
		for _, line := range strings.Split(text, "\n") {
			if strings.HasPrefix(line, "data: ") {
				text = strings.TrimPrefix(line, "data: ")
				break
			}
		}
	}
	var envelope struct {
		Result mcplib.CallToolResult `json:"result"`
		Error  any                   `json:"error"`
	}
	if json.Unmarshal([]byte(text), &envelope) != nil || envelope.Error != nil || len(envelope.Result.Content) == 0 {
		t.Fatalf("invalid operator RPC result: %s", text)
	}
	if envelope.Result.IsError != wantError {
		t.Fatalf("%s error=%v, expected %v: %s", name, envelope.Result.IsError, wantError, text)
	}
	content := envelope.Result.Content[0].(mcplib.TextContent).Text
	if wantError {
		return map[string]any{"error": content}
	}
	var result map[string]any
	if json.Unmarshal([]byte(content), &result) != nil {
		t.Fatal("invalid result JSON")
	}
	if report, ok := result["report"].(map[string]any); ok {
		return report
	}
	return result
}

func TestOperatorBindingsRealMCPBackendWorkflows(t *testing.T) {
	private := t.TempDir()
	key := filepath.Join(private, "sensor.key")
	tokenFile := filepath.Join(private, "webhook.token")
	credential := "controlled-fixture-credential"
	os.WriteFile(key, bytes.Repeat([]byte{29}, 32), 0600)
	os.WriteFile(tokenFile, []byte(credential), 0600)
	var delivered atomic.Int32
	destination := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		delivered.Add(1)
		if r.Header.Get("Authorization") != "Bearer "+credential {
			t.Error("binding credential not attached to enrolled destination")
		}
		w.WriteHeader(204)
	}))
	defer destination.Close()
	cfg := bindings.FileConfig{Version: 1, Sensors: []bindings.SensorConfig{
		{Name: "sender", SensorID: "lab", KeyFile: key, Namespace: filepath.Join(private, "sender"), MaxBytes: 1 << 20, RetentionSeconds: 60, MaxRuns: 4},
		{Name: "receiver", SensorID: "lab", KeyFile: key, Namespace: filepath.Join(private, "receiver"), MaxBytes: 1 << 20, RetentionSeconds: 60, MaxRuns: 4},
	}, Webhooks: []bindings.WebhookConfig{{Name: "notifier", Endpoint: destination.URL, TokenFile: tokenFile, OutboxRoot: filepath.Join(private, "outbox"), MaxNotices: 10, MaxScopes: 4}}}
	configFile := filepath.Join(private, "bindings.json")
	encoded, _ := json.Marshal(cfg)
	os.WriteFile(configFile, encoded, 0600)
	source := t.TempDir()
	input := filepath.Join(t.TempDir(), "fixture.pcap")
	os.WriteFile(input, []byte("registered capture"), 0600)
	capture, err := evidence.NewCapture(context.Background(), source, evidence.CaptureConfig{Kind: "file", Source: input})
	if err != nil {
		t.Fatal(err)
	}
	if err := capture.Close("done", 0, 0, nil); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(filepath.Join(source, "capture-manifest.json"))
	var manifest evidence.CaptureManifest
	json.Unmarshal(raw, &manifest)
	var alertData bytes.Buffer
	gz := gzip.NewWriter(&alertData)
	writer := delimited.NewWriter(gz)
	writer.PutProto(&types.Header{Type: types.Type_NC_Alert})
	writer.PutProto(&types.Alert{Timestamp: 123, RuleName: "bound-rule", Severity: "high", RecordType: "TCP", MatchedRecord: "PRIVATE_RAW_PAYLOAD"})
	gz.Close()
	os.WriteFile(filepath.Join(source, "Alert.ncap.gz"), alertData.Bytes(), 0600)
	network := true
	backend := webui.NewServer("127.0.0.1:0", source, []string{input}, "", false, false, false, nil, &webui.RuntimeConfig{OperatorBindingsFile: &configFile, OperatorNetwork: &network}, false)
	backend.MarkFileCompleted(input)
	backend.SetFileOutputDir(input, source)
	if err := backend.Start(); err != nil {
		t.Fatal(err)
	}
	defer backend.Stop(context.Background())
	mcp, err := netmcp.New(netmcp.Options{BaseURL: backend.GetURL(), AdminToken: backend.LocalAccessToken(), AllowNetwork: true, CarveDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	defer mcp.Close()
	endpoint := httptest.NewServer(mcp.HTTPHandler())
	defer endpoint.Close()
	call := func(name string, args map[string]any, bad bool) map[string]any {
		return operatorRPC(t, endpoint.URL, backend.LocalAccessToken(), name, args, bad)
	}
	public := call("get_operator_bindings", nil, false)
	publicJSON, _ := json.Marshal(public)
	for _, forbidden := range []string{credential, destination.URL, key, configFile, tokenFile, cfg.Sensors[0].Namespace} {
		if bytes.Contains(publicJSON, []byte(forbidden)) {
			t.Fatal("private enrollment data escaped discovery")
		}
	}
	sealed := call("sensor_bundle", map[string]any{"operation": "seal", "binding": "sender", "session_id": input, "run_id": manifest.RunID}, false)
	bundle := sealed["bundle_id"].(string)
	archive := call("sensor_bundle", map[string]any{"operation": "export", "binding": "sender", "bundle_id": bundle}, false)
	imported := call("sensor_bundle", map[string]any{"operation": "import", "binding": "receiver", "artifact_id": archive["artifact_id"]}, false)
	if imported["bundle_id"] != bundle {
		t.Fatal("artifact transport changed identity")
	}
	call("sensor_bundle", map[string]any{"operation": "prune", "binding": "receiver"}, false)
	call("sensor_bundle", map[string]any{"operation": "list", "binding": "missing"}, true)
	call("sensor_bundle", map[string]any{"operation": "import", "binding": "receiver", "bundle_id": "../outside"}, true)
	call("sensor_bundle", map[string]any{"operation": "seal", "binding": "sender", "session_id": input, "run_id": "stale"}, true)
	for _, field := range []string{"key", "keyFile", "sensorId", "namespace"} {
		call("sensor_bundle", map[string]any{"operation": "list", "binding": "sender", field: "substitution"}, true)
	}
	queued := call("alert_delivery", map[string]any{"operation": "enqueue", "binding": "notifier", "session_id": input, "run_id": manifest.RunID}, false)
	id := queued["delivery_id"]
	call("alert_delivery", map[string]any{"operation": "deliver", "binding": "notifier", "delivery_id": id}, false)
	call("alert_delivery", map[string]any{"operation": "status", "binding": "notifier", "delivery_id": id}, false)
	for _, field := range []string{"endpoint", "url", "token", "tokenFile", "outboxRoot", "scope"} {
		call("alert_delivery", map[string]any{"operation": "deliver", "binding": "notifier", "delivery_id": id, field: "substitution"}, true)
	}
	if delivered.Load() != 1 {
		t.Fatal("substitution caused unexpected delivery")
	}
	offline, err := netmcp.New(netmcp.Options{BaseURL: backend.GetURL(), AdminToken: backend.LocalAccessToken(), CarveDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	offlineEndpoint := httptest.NewServer(offline.HTTPHandler())
	defer offlineEndpoint.Close()
	operatorRPC(t, offlineEndpoint.URL, backend.LocalAccessToken(), "alert_delivery", map[string]any{"operation": "deliver", "binding": "notifier", "delivery_id": id}, true)
	unauthorized, _ := http.Get(backend.GetURL() + "/api/mcp/operator/bindings")
	if unauthorized.StatusCode != 401 {
		t.Fatal("private registry bypassed local authentication")
	}
	unauthorized.Body.Close()
}

func TestOperatorBindingsUnconfiguredIsDiscoverable(t *testing.T) {
	backend := webui.NewServer("127.0.0.1:0", t.TempDir(), nil, "", false, false, false, nil, nil, false)
	if err := backend.Start(); err != nil {
		t.Fatal(err)
	}
	defer backend.Stop(context.Background())
	mcp, err := netmcp.New(netmcp.Options{BaseURL: backend.GetURL(), AdminToken: backend.LocalAccessToken(), CarveDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	endpoint := httptest.NewServer(mcp.HTTPHandler())
	defer endpoint.Close()
	result := operatorRPC(t, endpoint.URL, backend.LocalAccessToken(), "get_operator_bindings", nil, false)
	if result["configured"] != false {
		t.Fatal("empty startup registry advertised as configured")
	}
	operatorRPC(t, endpoint.URL, backend.LocalAccessToken(), "sensor_bundle", map[string]any{"operation": "prune", "binding": "missing"}, true)
}
