package testutil

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// Recheck168Capture returns a hash-verified, evaluator-supplied synthetic capture.
func Recheck168Capture(t testing.TB, name string) string {
	t.Helper()
	if filepath.Base(name) != name || name == "." {
		t.Fatal("invalid recheck fixture name")
	}
	_, source, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("locate recheck fixtures")
	}
	root := filepath.Join(filepath.Dir(source), "..", "..", "testdata", "recheck-v0168")
	wire, err := os.ReadFile(filepath.Join(root, "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	var manifest struct {
		ArchiveSHA256 string
		Files         map[string]struct {
			SHA256 string
			Member string
		}
	}
	if err := json.Unmarshal(wire, &manifest); err != nil {
		t.Fatal(err)
	}
	if manifest.ArchiveSHA256 != "592f9c7bb78b48aeab0bc3db5011d2f0d969e31fab9e50fcee5ddea80cad4c06" {
		t.Fatal("unexpected recheck fixture provenance")
	}
	fixture, ok := manifest.Files[name]
	if !ok {
		t.Fatalf("unknown recheck fixture %q", name)
	}
	path := filepath.Join(root, name)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(data)
	if hex.EncodeToString(digest[:]) != fixture.SHA256 {
		t.Fatalf("recheck fixture digest mismatch: %s", name)
	}
	return path
}
