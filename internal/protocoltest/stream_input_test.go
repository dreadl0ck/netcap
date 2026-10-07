package protocoltest

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestDirectionalInputRefusesGapAndTamperedBytes(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "client.bin")
	data := []byte{0, 1, 'x'}
	digest := sha256.Sum256(data)
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	manifest := map[string]any{"version": 1, "status": "no-reported-gap", "protocol": "TCP", "client": map[string]string{"name": "client.bin", "sha256": hex.EncodeToString(digest[:])}, "spans": []map[string]any{{"missingBytes": 0}}}
	write := func() {
		t.Helper()
		bytes, err := json.Marshal(manifest)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "manifest.json"), bytes, 0600); err != nil {
			t.Fatal(err)
		}
	}
	write()
	if _, err := ReadDirectionalInput(path); err != nil {
		t.Fatal(err)
	}
	manifest["spans"] = []map[string]any{{"missingBytes": 10}}
	write()
	if _, err := ReadDirectionalInput(path); err == nil {
		t.Fatal("gap silently joined")
	}
	manifest["spans"] = []map[string]any{}
	manifest["protocol"] = "UDP"
	write()
	if _, err := ReadDirectionalInput(path); err == nil {
		t.Fatal("datagrams silently joined")
	}
	manifest["protocol"] = "TCP"
	write()
	if err := os.WriteFile(path, []byte{0, 1, 'y'}, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadDirectionalInput(path); err == nil {
		t.Fatal("changed artifact accepted")
	}
}
