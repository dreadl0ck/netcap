package bindings

import (
	"archive/zip"
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
	"time"

	"github.com/dreadl0ck/netcap/internal/delimited"
	"github.com/dreadl0ck/netcap/internal/evidence"
	"github.com/dreadl0ck/netcap/types"
)

func writePrivate(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
}
func writeConfig(t *testing.T, cfg FileConfig) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "bindings.json")
	raw, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	writePrivate(t, path, raw)
	return path
}
func capturedSource(t *testing.T) (string, string) {
	t.Helper()
	input := filepath.Join(t.TempDir(), "fixture.pcap")
	writePrivate(t, input, []byte("owned source fixture"))
	out := t.TempDir()
	capture, err := evidence.NewCapture(context.Background(), out, evidence.CaptureConfig{Kind: "file", Source: input})
	if err != nil {
		t.Fatal(err)
	}
	if err := capture.Close("done", 0, 0, nil); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(out, "capture-manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	var manifest evidence.CaptureManifest
	json.Unmarshal(raw, &manifest)
	var data bytes.Buffer
	gz := gzip.NewWriter(&data)
	writer := delimited.NewWriter(gz)
	if err := writer.PutProto(&types.Header{Type: types.Type_NC_Alert}); err != nil {
		t.Fatal(err)
	}
	if err := writer.PutProto(&types.Alert{Timestamp: 1700000000, RuleName: "fixture", RecordType: "TCP", Severity: "high", MatchedRecord: "RAW-PAYLOAD-SECRET", SrcIP: "192.0.2.1"}); err != nil {
		t.Fatal(err)
	}
	gz.Close()
	writePrivate(t, filepath.Join(out, "Alert.ncap.gz"), data.Bytes())
	return out, manifest.RunID
}
func resultID(t *testing.T, result any, key string) string {
	t.Helper()
	values, ok := result.(map[string]any)
	if !ok {
		t.Fatal("missing result")
	}
	id, ok := values[key].(string)
	if !ok || id == "" {
		t.Fatal("missing identity")
	}
	return id
}
func faultCode(t *testing.T, err error, want string) {
	t.Helper()
	if err == nil || !strings.Contains(err.Error(), want) {
		t.Fatalf("expected %s; got %v", want, err)
	}
}

func TestEnrolledSensorSealArchiveImportPrune(t *testing.T) {
	key := filepath.Join(t.TempDir(), "sensor.key")
	writePrivate(t, key, bytes.Repeat([]byte{19}, 32))
	wrong := filepath.Join(t.TempDir(), "wrong.key")
	writePrivate(t, wrong, bytes.Repeat([]byte{31}, 32))
	cfg := FileConfig{Version: 1}
	for _, entry := range []struct{ name, key string }{{"sender", key}, {"receiver", key}, {"wrong", wrong}} {
		cfg.Sensors = append(cfg.Sensors, SensorConfig{Name: entry.name, SensorID: "lab", KeyFile: entry.key, Namespace: filepath.Join(t.TempDir(), "private"), MaxBytes: 1 << 20, RetentionSeconds: 10, MaxRuns: 4})
	}
	manager, err := Load(writeConfig(t, cfg), false)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	manager.now = func() time.Time { return now }
	source, _ := capturedSource(t)
	sealed, err := manager.Sensor(context.Background(), SensorRequest{Operation: "seal", Binding: "sender", RetentionSeconds: 1}, source)
	if err != nil {
		t.Fatal(err)
	}
	id := resultID(t, sealed, "bundle_id")
	archive, err := manager.Export(context.Background(), "sender", "sealed", id)
	if err != nil {
		t.Fatal(err)
	}
	_, err = manager.ImportArchive(context.Background(), "wrong", archive)
	faultCode(t, err, "verification_failed")
	_, err = manager.ImportArchive(context.Background(), "unknown", archive)
	faultCode(t, err, "unknown_sensor_binding")
	imported, err := manager.ImportArchive(context.Background(), "receiver", archive)
	if err != nil {
		t.Fatal(err)
	}
	if resultID(t, imported, "bundle_id") != id {
		t.Fatal("source identity changed")
	}
	_, err = manager.ImportArchive(context.Background(), "receiver", archive)
	faultCode(t, err, "verification_failed")
	result, err := manager.Sensor(context.Background(), SensorRequest{Operation: "list", Binding: "receiver"}, "")
	if err != nil || result.(map[string]any)["total"] != 1 {
		t.Fatal("import not discoverable")
	}
	now = now.Add(2 * time.Second)
	pruned, err := manager.Sensor(context.Background(), SensorRequest{Operation: "prune", Binding: "receiver"}, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(pruned.(map[string]any)["removed"].([]string)) != 1 {
		t.Fatal("expired enrolled run was not pruned")
	}
	_, err = manager.Sensor(context.Background(), SensorRequest{Operation: "seal", Binding: "sender", RetentionSeconds: 11}, source)
	faultCode(t, err, "retention_outside_enrollment")
	_, err = manager.Sensor(context.Background(), SensorRequest{Operation: "import", Binding: "receiver", BundleID: "../outside"}, "")
	faultCode(t, err, "invalid_bundle_id")
	if err := os.Link(key, filepath.Join(source, "linked-key")); err != nil {
		t.Fatal(err)
	}
	_, err = manager.Sensor(context.Background(), SensorRequest{Operation: "seal", Binding: "receiver"}, source)
	faultCode(t, err, "credential_in_source")
	public, _ := json.Marshal(manager.Public())
	if bytes.Contains(public, bytes.Repeat([]byte{19}, 32)) || bytes.Contains(public, []byte(key)) || bytes.Contains(public, []byte(cfg.Sensors[0].Namespace)) {
		t.Fatal("operator configuration escaped discovery")
	}
}

func TestSensorCapacityAndUnknownSigningIdentity(t *testing.T) {
	key := filepath.Join(t.TempDir(), "key")
	writePrivate(t, key, bytes.Repeat([]byte{12}, 32))
	cfg := FileConfig{Version: 1, Sensors: []SensorConfig{{Name: "enrolled", SensorID: "lab", KeyFile: key, Namespace: filepath.Join(t.TempDir(), "private"), MaxBytes: 1 << 20, RetentionSeconds: 10, MaxRuns: 1}}}
	manager, err := Load(writeConfig(t, cfg), false)
	if err != nil {
		t.Fatal(err)
	}
	source, _ := capturedSource(t)
	if _, err := manager.Sensor(context.Background(), SensorRequest{Operation: "seal", Binding: "enrolled"}, source); err != nil {
		t.Fatal(err)
	}
	other, _ := capturedSource(t)
	_, err = manager.Sensor(context.Background(), SensorRequest{Operation: "seal", Binding: "enrolled"}, other)
	faultCode(t, err, "sensor_run_capacity")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = manager.Sensor(ctx, SensorRequest{Operation: "list", Binding: "enrolled"}, "")
	if err != context.Canceled {
		t.Fatal("cancellation ignored")
	}
}

func TestControlledDeliveryDurabilityAndCredentialDestinationPin(t *testing.T) {
	token := filepath.Join(t.TempDir(), "token")
	writePrivate(t, token, []byte("fixture-credential-not-returned"))
	var accepted, foreign atomic.Int32
	destination := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		accepted.Add(1)
		if r.Header.Get("Authorization") != "Bearer fixture-credential-not-returned" || r.Header.Get("Idempotency-Key") == "" {
			t.Error("missing bound authentication/idempotency")
		}
		raw, _ := io.ReadAll(r.Body)
		if bytes.Contains(raw, []byte("RAW-PAYLOAD-SECRET")) || bytes.Contains(raw, []byte("fixture-credential-not-returned")) {
			t.Error("raw material included in notice")
		}
		w.WriteHeader(204)
	}))
	defer destination.Close()
	attacker := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { foreign.Add(1) }))
	defer attacker.Close()
	root := filepath.Join(t.TempDir(), "private")
	cfg := FileConfig{Version: 1, Webhooks: []WebhookConfig{{Name: "notify", Endpoint: destination.URL, TokenFile: token, OutboxRoot: root, MaxNotices: 10, MaxScopes: 4}}}
	path := writeConfig(t, cfg)
	manager, err := Load(path, true)
	if err != nil {
		t.Fatal(err)
	}
	source, run := capturedSource(t)
	queued, err := manager.Delivery(context.Background(), DeliveryRequest{Operation: "enqueue", Binding: "notify"}, source, run)
	if err != nil {
		t.Fatal(err)
	}
	id := resultID(t, queued, "delivery_id")
	writePrivate(t, token, []byte("changed-after-startup"))
	if _, err := manager.Delivery(context.Background(), DeliveryRequest{Operation: "deliver", Binding: "notify", DeliveryID: id}, "", ""); err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Delivery(context.Background(), DeliveryRequest{Operation: "enqueue", Binding: "notify"}, source, run); err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Delivery(context.Background(), DeliveryRequest{Operation: "deliver", Binding: "notify", DeliveryID: id}, "", ""); err != nil {
		t.Fatal(err)
	}
	if accepted.Load() != 1 {
		t.Fatal("durable receipt did not suppress duplicate semantic notice")
	}
	reopened, err := Load(path, true)
	if err != nil {
		t.Fatal(err)
	}
	os.RemoveAll(source)
	status, err := reopened.Delivery(context.Background(), DeliveryRequest{Operation: "status", Binding: "notify", DeliveryID: id}, "", "")
	if err != nil {
		t.Fatal(err)
	}
	statusJSON, _ := json.Marshal(status)
	if !bytes.Contains(statusJSON, []byte(`"delivered":1`)) {
		t.Fatal("restart/source expiry lost durable receipt")
	}
	if _, err := reopened.Delivery(context.Background(), DeliveryRequest{Operation: "deliver", Binding: "notify", DeliveryID: id}, "", ""); err != nil || accepted.Load() != 1 {
		t.Fatal("restart retried an already delivered semantic notice")
	}
	cfg.Webhooks[0].Endpoint = attacker.URL
	raw, _ := json.Marshal(cfg)
	writePrivate(t, path, raw)
	restarted, err := Load(path, true)
	if err != nil {
		t.Fatal(err)
	}
	_, err = restarted.Delivery(context.Background(), DeliveryRequest{Operation: "deliver", Binding: "notify", DeliveryID: id}, "", "")
	faultCode(t, err, "destination_changed")
	if foreign.Load() != 0 {
		t.Fatal("credential followed substituted destination")
	}
	offline, err := Load(path, false)
	if err != nil {
		t.Fatal(err)
	}
	_, err = offline.Delivery(context.Background(), DeliveryRequest{Operation: "deliver", Binding: "notify", DeliveryID: id}, "", "")
	faultCode(t, err, "network_policy_disabled")
	_, err = manager.Delivery(context.Background(), DeliveryRequest{Operation: "status", Binding: "missing", DeliveryID: id}, "", "")
	faultCode(t, err, "unknown_webhook_binding")
	public, _ := json.Marshal(manager.Public())
	if strings.Contains(string(public), destination.URL) || strings.Contains(string(public), "fixture-credential") || strings.Contains(string(public), token) {
		t.Fatal("credential/destination leaked through discovery")
	}
}

func TestDeliveryRejectRedirectAndRetryRemainExplicit(t *testing.T) {
	for _, status := range []int{302, 400, 503} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			var foreign atomic.Int32
			target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { foreign.Add(1) }))
			defer target.Close()
			endpoint := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Location", target.URL)
				w.WriteHeader(status)
			}))
			defer endpoint.Close()
			token := filepath.Join(t.TempDir(), "token")
			writePrivate(t, token, []byte("synthetic-credential"))
			cfg := FileConfig{Version: 1, Webhooks: []WebhookConfig{{Name: "notify", Endpoint: endpoint.URL, TokenFile: token, OutboxRoot: filepath.Join(t.TempDir(), "private"), MaxNotices: 1, MaxScopes: 1}}}
			manager, err := Load(writeConfig(t, cfg), true)
			if err != nil {
				t.Fatal(err)
			}
			source, run := capturedSource(t)
			queued, err := manager.Delivery(context.Background(), DeliveryRequest{Operation: "enqueue", Binding: "notify"}, source, run)
			if err != nil {
				t.Fatal(err)
			}
			result, err := manager.Delivery(context.Background(), DeliveryRequest{Operation: "deliver", Binding: "notify", DeliveryID: resultID(t, queued, "delivery_id")}, "", "")
			faultCode(t, err, "delivery_incomplete")
			raw, _ := json.Marshal(result)
			if status == 503 && !bytes.Contains(raw, []byte(`"pending":1`)) {
				t.Fatal("retry backlog hidden")
			}
			if status < 500 && !bytes.Contains(raw, []byte(`"rejected":1`)) {
				t.Fatal("rejection hidden")
			}
			if foreign.Load() != 0 {
				t.Fatal("redirect followed")
			}
		})
	}
}

func TestBindingsDisabledAndPrivateConfigurationValidation(t *testing.T) {
	disabled, err := Load("", false)
	if err != nil {
		t.Fatal(err)
	}
	_, err = disabled.Sensor(context.Background(), SensorRequest{Operation: "prune", Binding: "anything"}, "")
	faultCode(t, err, "unconfigured")
	_, err = disabled.Delivery(context.Background(), DeliveryRequest{Operation: "deliver", Binding: "anything"}, "", "")
	faultCode(t, err, "unconfigured")
	path := writeConfig(t, FileConfig{Version: 1})
	os.Chmod(path, 0644)
	_, err = Load(path, true)
	faultCode(t, err, "private_configuration")
	writePrivate(t, path, []byte(`{"version":1,"credential":"must-not-echo"}`))
	os.Chmod(path, 0600)
	_, err = Load(path, true)
	if err == nil || strings.Contains(err.Error(), "must-not-echo") {
		t.Fatal("invalid private config was accepted or echoed")
	}
}

func TestSensorArchiveAndNamespaceSubstitutionRejected(t *testing.T) {
	key := filepath.Join(t.TempDir(), "key")
	writePrivate(t, key, bytes.Repeat([]byte{17}, 32))
	root := filepath.Join(t.TempDir(), "namespace")
	cfg := FileConfig{Version: 1, Sensors: []SensorConfig{{Name: "bound", SensorID: "lab", KeyFile: key, Namespace: root, MaxBytes: 1024, RetentionSeconds: 10, MaxRuns: 2}}}
	manager, err := Load(writeConfig(t, cfg), false)
	if err != nil {
		t.Fatal(err)
	}
	var archive bytes.Buffer
	writer := zip.NewWriter(&archive)
	file, _ := writer.Create("../foreign")
	file.Write([]byte("not permitted"))
	writer.Close()
	_, err = manager.ImportArchive(context.Background(), "bound", archive.Bytes())
	faultCode(t, err, "archive_path")
	source, _ := capturedSource(t)
	writePrivate(t, filepath.Join(source, "oversized"), make([]byte, 2048))
	_, err = manager.Sensor(context.Background(), SensorRequest{Operation: "seal", Binding: "bound"}, source)
	faultCode(t, err, "byte_budget")
	moved := root + "-old"
	if err := os.Rename(root, moved); err != nil {
		t.Fatal(err)
	}
	foreign := filepath.Join(t.TempDir(), "foreign")
	os.Mkdir(foreign, 0700)
	if err := os.Symlink(foreign, root); err != nil {
		t.Fatal(err)
	}
	_, err = manager.Sensor(context.Background(), SensorRequest{Operation: "prune", Binding: "bound"}, "")
	faultCode(t, err, "namespace_changed")
}

func TestTrustedCaptureGenerationCheckedAfterSensorSnapshot(t *testing.T) {
	key := filepath.Join(t.TempDir(), "sensor.key")
	writePrivate(t, key, bytes.Repeat([]byte{23}, 32))
	token := filepath.Join(t.TempDir(), "token")
	writePrivate(t, token, []byte("synthetic-bound-credential"))
	namespace, outbox := filepath.Join(t.TempDir(), "sensor"), filepath.Join(t.TempDir(), "outbox")
	cfg := FileConfig{Version: 1, Sensors: []SensorConfig{{Name: "bound", SensorID: "lab", KeyFile: key, Namespace: namespace, MaxBytes: 1 << 20, RetentionSeconds: 60, MaxRuns: 4}}, Webhooks: []WebhookConfig{{Name: "bound", Endpoint: "http://127.0.0.1:1", TokenFile: token, OutboxRoot: outbox, MaxNotices: 10, MaxScopes: 4}}}
	manager, err := Load(writeConfig(t, cfg), false)
	if err != nil {
		t.Fatal(err)
	}
	_, expected := capturedSource(t)
	replacement, actual := capturedSource(t)
	request := SensorRequest{Operation: "seal", Binding: "bound"}
	_, err = manager.SensorForCapture(context.Background(), request, replacement, expected)
	faultCode(t, err, "sensor_capture_generation_changed")
	entries, err := os.ReadDir(filepath.Join(namespace, "sealed"))
	if err != nil || len(entries) != 0 {
		t.Fatal("mismatched generation published a signed bundle")
	}
	entries, err = os.ReadDir(namespace)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".seal-source-") {
			t.Fatal("rejected private snapshot leaked")
		}
	}
	_, err = manager.SensorForCapture(context.Background(), request, replacement, "")
	faultCode(t, err, "validated_capture_run_required")
	sealed, err := manager.SensorForCapture(context.Background(), request, replacement, actual)
	if err != nil {
		t.Fatal(err)
	}
	if resultID(t, sealed, "bundle_id") != actual {
		t.Fatal("matching generation changed during sealing")
	}
	_, err = manager.Delivery(context.Background(), DeliveryRequest{Operation: "enqueue", Binding: "bound"}, replacement, expected)
	faultCode(t, err, "capture_identity_unavailable_or_stale")
	entries, err = os.ReadDir(outbox)
	if err != nil || len(entries) != 0 {
		t.Fatal("stale generation admitted a durable alert scope")
	}
}
