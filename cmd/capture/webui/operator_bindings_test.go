package webui

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dreadl0ck/netcap/internal/evidence"
	"github.com/dreadl0ck/netcap/internal/mcp/bindings"
)

func TestOperatorBindingHTTPAuthorityAndUnknownFields(t *testing.T) {
	manager, err := bindings.Load("", false)
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{isServiceMode: true, operatorBindings: manager}
	w := httptest.NewRecorder()
	s.handleOperatorBindings(w, httptest.NewRequest("GET", "/api/mcp/operator/bindings", nil))
	if w.Code != 403 {
		t.Fatal("service tenant accessed enrollment registry")
	}
	t.Setenv(EnvMCPAdminToken, "synthetic-operator-admin")
	r := httptest.NewRequest("GET", "/api/mcp/operator/bindings", nil)
	r.Header.Set("Authorization", "Bearer synthetic-operator-admin")
	w = httptest.NewRecorder()
	s.handleOperatorBindings(w, r)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"configured":false`) {
		t.Fatal(w.Body)
	}
	s.isServiceMode = false
	for _, body := range []string{`{"operation":"prune","binding":"bound","key":"substitution"}`, `{"operation":"prune","binding":"bound","namespace":"/outside"}`, `{"operation":"seal","binding":"bound","expectedRun":"override"}`} {
		w := httptest.NewRecorder()
		s.handleSensorBinding(w, httptest.NewRequest("POST", "/api/mcp/operator/sensor", strings.NewReader(body)))
		if w.Code != 400 {
			t.Fatal("binding substitution accepted")
		}
	}
	w = httptest.NewRecorder()
	s.handleSensorArchive(w, httptest.NewRequest("POST", "/api/mcp/operator/sensor-archive?binding=bound&key=substitution", strings.NewReader("not read")))
	if w.Code != 400 {
		t.Fatal("archive query accepted a trust-key override")
	}
	w = httptest.NewRecorder()
	s.handleAlertDeliveryBinding(w, httptest.NewRequest("POST", "/api/mcp/operator/delivery", strings.NewReader(`{"operation":"deliver","binding":"bound","endpoint":"substitution"}`)))
	if w.Code != 400 {
		t.Fatal("destination substitution accepted")
	}
}

func TestOperatorResolvedGenerationCannotRebindReplacedSource(t *testing.T) {
	private := t.TempDir()
	key, token := filepath.Join(private, "key"), filepath.Join(private, "token")
	if err := os.WriteFile(key, bytes.Repeat([]byte{13}, 32), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(token, []byte("synthetic-notice-credential"), 0600); err != nil {
		t.Fatal(err)
	}
	cfg := bindings.FileConfig{Version: 1, Sensors: []bindings.SensorConfig{{Name: "bound", SensorID: "lab", KeyFile: key, Namespace: filepath.Join(private, "sensor"), MaxBytes: 1 << 20, RetentionSeconds: 60, MaxRuns: 4}}, Webhooks: []bindings.WebhookConfig{{Name: "bound", Endpoint: "http://127.0.0.1:1", TokenFile: token, OutboxRoot: filepath.Join(private, "outbox"), MaxNotices: 10, MaxScopes: 4}}}
	config := filepath.Join(private, "config.json")
	encoded, _ := json.Marshal(cfg)
	if err := os.WriteFile(config, encoded, 0600); err != nil {
		t.Fatal(err)
	}
	manager, err := bindings.Load(config, false)
	if err != nil {
		t.Fatal(err)
	}
	source := t.TempDir()
	s := NewServer("127.0.0.1:0", source, []string{"/selected.pcap"}, "", false, false, false, nil, nil, false)
	s.operatorBindings = manager
	expected, replacement := strings.Repeat("a", 32), strings.Repeat("b", 32)
	writeManifest := func(run string) {
		t.Helper()
		data, _ := json.Marshal(evidence.CaptureManifest{Version: 1, RunID: run, Status: "done", InputSHA256: strings.Repeat("c", 64)})
		if err := os.WriteFile(filepath.Join(source, "capture-manifest.json"), data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	for _, operation := range []struct {
		name, code string
		handler    http.HandlerFunc
	}{{"seal", "sensor_capture_generation_changed", s.handleSensorBinding}, {"enqueue", "capture_identity_unavailable_or_stale", s.handleAlertDeliveryBinding}} {
		t.Run(operation.name, func(t *testing.T) {
			writeManifest(expected)
			request := httptest.NewRequest("POST", "/api/mcp/operator/test?"+url.Values{"inputFile": {"/selected.pcap"}, "runId": {expected}}.Encode(), strings.NewReader(`{"operation":"`+operation.name+`","binding":"bound"}`))
			w := httptest.NewRecorder()
			s.captureSelectionMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { writeManifest(replacement); operation.handler(w, r) })).ServeHTTP(w, request)
			if w.Code != 409 || !strings.Contains(w.Body.String(), operation.code) {
				t.Fatalf("replaced source rebound resolved generation: %d %s", w.Code, w.Body)
			}
		})
	}
	if _, err := os.Stat(filepath.Join(private, "sensor", "sealed", "lab", replacement)); !os.IsNotExist(err) {
		t.Fatal("replacement was sealed despite stale requested generation")
	}
}

func TestOperatorStartupConfigurationErrorsAreRedacted(t *testing.T) {
	path := filepath.Join(t.TempDir(), "private.json")
	marker := "SYNTHETIC_PRIVATE_CONFIG_VALUE"
	os.WriteFile(path, []byte(`{"version":1,"unexpected":"`+marker+`"}`), 0600)
	network := false
	s := NewServer("127.0.0.1:0", t.TempDir(), nil, "", false, false, false, nil, &RuntimeConfig{OperatorBindingsFile: &path, OperatorNetwork: &network}, false)
	err := s.Start()
	if err == nil || strings.Contains(err.Error(), marker) || strings.Contains(err.Error(), path) {
		t.Fatal("startup config was accepted or disclosed")
	}
	raw, err := json.Marshal(RuntimeConfig{OperatorBindingsFile: &path, OperatorNetwork: &network})
	if err != nil || strings.Contains(string(raw), path) || strings.Contains(string(raw), "OperatorBindings") {
		t.Fatal("private startup reference entered producer metadata")
	}
}
