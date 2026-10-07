package flowexport

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestRecorderPersistsMissingEvidenceAndRefusesReplacement(t *testing.T) {
	dir := t.TempDir()
	r, err := NewRecorder(dir, DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	env := testEnvelope("192.0.2.10:50000")
	if err := r.Observe(nf9(1, set(256, words(123))), env); err != nil {
		t.Fatal(err)
	}
	if err := r.Observe([]byte{0, 9}, env); err != nil {
		t.Fatal(err)
	}
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(dir, "FlowExportsHealth.json"))
	if err != nil {
		t.Fatal(err)
	}
	var health RecorderHealth
	if err := json.Unmarshal(data, &health); err != nil {
		t.Fatal(err)
	}
	if health.Status != "partial" || health.MissingTemplates != 1 || health.Malformed != 1 || health.Issues != 2 {
		t.Fatalf("missing telemetry presented as healthy: %+v", health)
	}
	f, err := os.Open(filepath.Join(dir, "FlowExports.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	count := 0
	for scanner.Scan() {
		var event Event
		if err := json.Unmarshal(scanner.Bytes(), &event); err != nil {
			t.Fatal(err)
		}
		if event.Kind == "datagram" {
			if len(event.Datagram) == 0 || len(event.SHA256) != 64 {
				t.Fatal("wire evidence lost")
			}
			continue
		}
		if event.Kind != "issue" || event.Issue == nil {
			t.Fatal("missing evidence issue lost")
		}
		count++
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
	if count != 2 {
		t.Fatalf("issues=%d", count)
	}
	if _, err := NewRecorder(dir, DefaultConfig()); err == nil {
		t.Fatal("existing investigation overwritten")
	}
}

func FuzzFlowExportDecoder(f *testing.F) {
	f.Add(nf9(0, set(0, shorts(256, 1, 8, 4))))
	f.Add(ipfix(0, set(2, shorts(256, 1, 8, 4))))
	f.Add([]byte{0, 5})
	f.Fuzz(func(t *testing.T, data []byte) {
		e := testEngine(t)
		_, _ = e.Decode(data, testEnvelope("192.0.2.10:50000"))
	})
}
