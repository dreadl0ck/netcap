package investigate

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/dreadl0ck/netcap/internal/evidence"
)

func TestSensorCLISealsAndImportsScopedEvidence(t *testing.T) {
	dir := t.TempDir()
	input := filepath.Join(dir, "fixture.pcap")
	if err := os.WriteFile(input, []byte("fixture bytes"), 0600); err != nil {
		t.Fatal(err)
	}
	out := t.TempDir()
	capture, err := evidence.NewCapture(context.Background(), out, evidence.CaptureConfig{Kind: "file", Source: input})
	if err != nil {
		t.Fatal(err)
	}
	if err := capture.Close("done", 0, 0, nil); err != nil {
		t.Fatal(err)
	}
	key := filepath.Join(dir, "key")
	if err := os.WriteFile(key, bytes.Repeat([]byte{42}, 32), 0600); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	command := GetCommand()
	command.Writer = &output
	if err := command.Run(context.Background(), []string{"investigate", "sensor-seal", "--read", out, "--out", filepath.Join(t.TempDir(), "store"), "--sensor-id", "lab", "--key-file", key, "--retention", "1h"}); err != nil {
		t.Fatal(err)
	}
	var bundle string
	if err := json.Unmarshal(output.Bytes(), &bundle); err != nil {
		t.Fatal(err)
	}
	output.Reset()
	command = GetCommand()
	command.Writer = &output
	if err := command.Run(context.Background(), []string{"investigate", "sensor-import", "--read", bundle, "--out", filepath.Join(t.TempDir(), "store"), "--sensor-id", "lab", "--key-file", key, "--retention", "1h"}); err != nil {
		t.Fatal(err)
	}
	var imported string
	if err := json.Unmarshal(output.Bytes(), &imported); err != nil {
		t.Fatal(err)
	}
	if data, err := os.ReadFile(filepath.Join(imported, "capture-manifest.json")); err != nil || !bytes.Contains(data, []byte("inputSHA256")) {
		t.Fatalf("import lost source identity: %v", err)
	}
	output.Reset()
	command = GetCommand()
	command.Writer = &output
	if err := command.Run(context.Background(), []string{"investigate", "sensor-import", "--read", bundle, "--out", filepath.Join(t.TempDir(), "store"), "--sensor-id", "other", "--key-file", key}); err == nil {
		t.Fatal("CLI allowed cross-sensor import")
	}
}
