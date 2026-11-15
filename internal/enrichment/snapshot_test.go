package enrichment

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestOfflineSnapshotSurvivesFreshnessExpiry(t *testing.T) {
	t.Setenv("NC_ENRICHMENT_VERSION", "")
	envelope, archive, trust, _, now := fixture(t)
	root := t.TempDir()
	if err := Install(root, envelope, archive, trust, now); err != nil {
		t.Fatal(err)
	}
	var payload Payload
	if err := json.Unmarshal(envelope.Payload, &payload); err != nil {
		t.Fatal(err)
	}
	later := time.Unix(payload.ExpiresAt+1, 0)
	before, err := Open(root, trust, now)
	if err != nil {
		t.Fatal(err)
	}
	after, err := Open(root, trust, later)
	if err != nil {
		t.Fatal("offline snapshot expired", err)
	}
	for name, want := range before {
		if !bytes.Equal(after[name], want) {
			t.Fatal("clock changed member", name)
		}
	}
	s := Inspect(root, trust, later)
	if s.State != "stale" || s.ReleaseSHA256 != Digest(envelope.Payload) || s.ExpiresAt != payload.ExpiresAt || s.ManifestSHA256 != payload.ManifestSHA256 {
		t.Fatal(s)
	}
	if _, _, err := Verify(envelope, trust, later, true); err == nil || !strings.Contains(err.Error(), "expired at ") {
		t.Fatal("freshness diagnostic", err)
	}
	if err := Install(t.TempDir(), envelope, archive, trust, later); err == nil {
		t.Fatal("expired update installed")
	}
	t.Setenv("NC_ENRICHMENT_VERSION", s.ReleaseSHA256)
	if err := os.WriteFile(filepath.Join(root, "active"), []byte(strings.Repeat("0", 64)+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(root, trust, later); err != nil {
		t.Fatal("pin followed mutable active pointer", err)
	}
	if err := os.WriteFile(filepath.Join(root, "versions", s.ReleaseSHA256, "kev.json"), []byte("tampered"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(root, trust, later); err == nil {
		t.Fatal("stale policy bypassed content authentication")
	}
}
