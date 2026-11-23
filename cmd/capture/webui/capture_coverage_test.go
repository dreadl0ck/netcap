package webui

import (
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/gogo/protobuf/proto"

	"github.com/dreadl0ck/netcap/internal/evidence"
	"github.com/dreadl0ck/netcap/internal/rules"
	"github.com/dreadl0ck/netcap/types"
)

func writeCoverageManifest(t *testing.T, dir string, manifest evidence.CaptureManifest) {
	t.Helper()
	data, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "capture-manifest.json"), data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func exitStatus(t *testing.T, code string) error {
	t.Helper()
	err := exec.Command("sh", "-c", "exit "+code).Run()
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) {
		t.Fatalf("no exit error: %v", err)
	}
	return err
}

// Since v0.16.11 a capture with sealed but partial output exits 2. The WebUI
// treated that as a failed analysis, so try-demo captures with a few
// malformed frames (arp-dns-eth-icmp-ip-udp-goodhttp-gooddns.pcapng) failed.
func TestPartialCaptureExitIsAccepted(t *testing.T) {
	dir := t.TempDir()
	partial := evidence.CaptureManifest{RunID: "run", Status: "partial", CoverageError: "capture input partial: link-errors=3", AuditStagesGeneration: "g"}
	writeCoverageManifest(t, dir, partial)
	if note, ok := acceptPartialCapture(exitStatus(t, "2"), dir); !ok || note != partial.CoverageError {
		t.Fatalf("partial exit rejected: %q %v", note, ok)
	}
	for name, tc := range map[string]struct {
		err      error
		manifest evidence.CaptureManifest
	}{
		"exit 1":                  {exitStatus(t, "1"), partial},
		"exit 3, no input report": {exitStatus(t, "3"), partial},
		"failed manifest":         {exitStatus(t, "2"), evidence.CaptureManifest{RunID: "run", Status: "failed", CoverageError: "x", AuditStagesGeneration: "g"}},
		"unsealed":                {exitStatus(t, "2"), evidence.CaptureManifest{RunID: "run", Status: "partial", CoverageError: "x"}},
		"plain error":             {errors.New("exit status 2"), partial},
	} {
		writeCoverageManifest(t, dir, tc.manifest)
		if _, ok := acceptPartialCapture(tc.err, dir); ok {
			t.Errorf("%s accepted", name)
		}
	}
}

// merged.pcapng holds 559,270 packets of which 3 are Frame Relay: exit 3 must
// not discard the rest. A Token Ring capture with no supported packet fails.
func TestMixedLinkCaptureExitIsAccepted(t *testing.T) {
	dir := t.TempDir()
	writeCoverageManifest(t, dir, evidence.CaptureManifest{RunID: "run", Status: "partial", CoverageError: "capture input unsupported", AuditStagesGeneration: "g"})
	for report, want := range map[string]bool{
		`{"processedPackets":559270,"unsupportedPackets":3}`:  true,
		`{"processedPackets":1000,"unsupportedPackets":1000}`: false,
	} {
		if err := os.WriteFile(filepath.Join(dir, "capture-input.json"), []byte(report), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, ok := acceptPartialCapture(exitStatus(t, "3"), dir); ok != want {
			t.Errorf("%s: accepted=%v", report, ok)
		}
	}
}

func TestPartialCaptureCompletesWithCoverageNote(t *testing.T) {
	s, input, dir := reanalysisFixture(t)
	delete(s.completedFiles, input)
	s.fileBPFFilters = map[string]string{}
	s.rulesConfig = &rules.Config{}
	s.isServiceMode = true
	s.sessionManager = NewSessionManager(10, 60, 10)
	job := &AnalysisJob{InputFile: input, OutputDir: dir, SessionID: "partial"}
	s.sessionManager.AddSession(&SessionInfo{SessionID: job.SessionID, InputFile: input, OutputDir: dir, Status: StatusProcessing})
	writeTimelineAuditFile(t, dir, "HTTP", types.Type_NC_HTTP, []proto.Message{&types.HTTP{Timestamp: 1}})
	writeCoverageManifest(t, dir, evidence.CaptureManifest{RunID: "run", Status: "partial", CoverageError: "capture input partial: link-errors=3", AuditStagesGeneration: "g"})
	if err := s.completeAnalysis(job, time.Second); err != nil {
		t.Fatal(err)
	}
	session, ok := s.sessionManager.GetSession(job.SessionID)
	if !ok || session.Status != StatusCompleted || session.Coverage != "capture input partial: link-errors=3" {
		t.Fatalf("session %+v", session)
	}
}
