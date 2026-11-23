package utils

import (
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"testing"
	"time"

	"github.com/dreadl0ck/netcap/internal/decoder/core"
	"github.com/dreadl0ck/netcap/internal/reassembly"
	"github.com/gopacket/gopacket"
)

func evidenceFixture() core.FragmentSource {
	return core.SliceSource(core.DataFragments{&core.StreamData{RawData: []byte("hello"), Dir: reassembly.TCPDirClientToServer, CaptureInformation: gopacket.CaptureInfo{Timestamp: time.Unix(1, 0)}}})
}

// V1612-2: a final name already taken by published evidence is drawn again;
// it used to fail the rename and abort the capture.
func TestStreamEvidenceRetriesTakenName(t *testing.T) {
	out := t.TempDir()
	taken := filepath.Join(out, "stream-evidence", "stream-taken")
	if err := os.MkdirAll(taken, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(taken, "marker"), []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	names := []string{"stream-taken", "stream-taken", "stream-fresh"}
	next := func() (string, error) {
		name := names[0]
		names = names[1:]
		return name, nil
	}
	dir, err := saveSourceEvidence(out, "TCP", evidenceFixture(), "tuple", time.Unix(1, 0), "", next)
	if err != nil || filepath.Base(dir) != "stream-fresh" {
		t.Fatalf("published %s, %v", dir, err)
	}
	if data, err := os.ReadFile(filepath.Join(taken, "marker")); err != nil || string(data) != "keep" {
		t.Fatalf("existing evidence was disturbed: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "manifest.json")); err != nil {
		t.Fatal(err)
	}
	assertNoPending(t, out)
}

func TestStreamEvidenceNameErrorsAreNotRetried(t *testing.T) {
	out := t.TempDir()
	calls := 0
	for _, next := range []func() (string, error){
		func() (string, error) { calls++; return "", errors.New("entropy unavailable") },
		func() (string, error) { calls++; return "../escape", nil },
		func() (string, error) { calls++; return "not-a-stream", nil },
	} {
		if _, err := saveSourceEvidence(out, "TCP", evidenceFixture(), "tuple", time.Unix(1, 0), "", next); err == nil {
			t.Fatal("bad name accepted")
		}
	}
	if calls != 3 {
		t.Fatalf("errors were retried: %d calls", calls)
	}
	assertNoPending(t, out)
}

func TestStreamEvidenceNamesAre128Bit(t *testing.T) {
	pattern := regexp.MustCompile(`^stream-[0-9a-f]{32}$`)
	seen := map[string]bool{}
	for range 1000 {
		name, err := randomStreamEvidenceName()
		if err != nil || !pattern.MatchString(name) || seen[name] {
			t.Fatalf("name %q %v", name, err)
		}
		seen[name] = true
	}
}

func assertNoPending(t *testing.T, out string) {
	t.Helper()
	if matches, _ := filepath.Glob(filepath.Join(out, "stream-evidence", ".pending-*")); len(matches) != 0 {
		t.Fatalf("pending directories left behind: %v", matches)
	}
}
