package webui

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/gogo/protobuf/proto"

	"github.com/dreadl0ck/netcap/internal/collector"
	"github.com/dreadl0ck/netcap/internal/evidence"
	"github.com/dreadl0ck/netcap/internal/rules"
	"github.com/dreadl0ck/netcap/types"
)

// exitStatus stands in for *exec.ExitError, which also reports ExitCode.
type exitStatus int

func (e exitStatus) Error() string { return "exit status" }
func (e exitStatus) ExitCode() int { return int(e) }

func writeCoverageJSON(t *testing.T, dir, name string, value any) {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, name), data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func partialInput() collector.CaptureInputReport {
	return collector.CaptureInputReport{Format: "pcapng", Status: "partial", ReachedEOF: true, CountedPackets: 8, ProcessedPackets: 8, LinkErrors: 3, Finalized: true,
		Issues: []collector.CaptureInputIssue{{Offset: 120, Kind: "link", Reason: "Ethernet packet too small", Recoverable: true}}}
}

// Service mode runs with capture evidence off, so no manifest exists; the
// try.netcap.io arp-dns capture kept failing with exit 2 until acceptance
// stopped requiring one.
func TestPartialCaptureAcceptedWithoutManifest(t *testing.T) {
	started := time.Now()
	dir := t.TempDir()
	writeCoverageJSON(t, dir, collector.CaptureInputFile, partialInput())
	note, ok := acceptPartialCapture(exitStatus(2), dir, started, nil)
	if !ok || note != "capture input partial: processed=8 skipped=0 read-errors=0 link-errors=3 decode-errors=0 unsupported=0 snapshot-truncated=0; link at offset 120: Ethernet packet too small" {
		t.Fatalf("rejected or wrong note: %q %v", note, ok)
	}
	// A sealed manifest names the reason when present.
	writeCoverageJSON(t, dir, "capture-manifest.json", evidence.CaptureManifest{RunID: "run", Status: "partial", CoverageError: "manifest reason", AuditStagesGeneration: "g"})
	if note, ok := acceptPartialCapture(exitStatus(2), dir, started, nil); !ok || note != "manifest reason" {
		t.Fatalf("manifest note: %q %v", note, ok)
	}
}

func TestPartialCaptureRejections(t *testing.T) {
	started := time.Now()
	mutate := func(f func(*collector.CaptureInputReport)) collector.CaptureInputReport {
		r := partialInput()
		f(&r)
		return r
	}
	for name, tc := range map[string]struct {
		err    error
		report *collector.CaptureInputReport
	}{
		"fatal exit":            {exitStatus(1), ptr(partialInput())},
		"crash before finalize": {exitStatus(2), ptr(mutate(func(r *collector.CaptureInputReport) { r.Finalized = false }))},
		"only link errors":      {exitStatus(2), ptr(mutate(func(r *collector.CaptureInputReport) { r.ProcessedPackets = 3 }))},
		"no input report":       {exitStatus(2), nil},
		"error status":          {exitStatus(2), ptr(mutate(func(r *collector.CaptureInputReport) { r.Status = "error" }))},
		"exit 3 partial status": {exitStatus(3), ptr(partialInput())},
		"all unsupported":       {exitStatus(3), ptr(mutate(func(r *collector.CaptureInputReport) { r.Status, r.LinkErrors, r.Unsupported = "unsupported", 0, 8 }))},
		"coded leaf with fatal": {errors.Join(&collector.CaptureInputError{Report: partialInput()}, errors.New("disk full")), ptr(partialInput())},
		"plain error":           {errors.New("exit status 2"), ptr(partialInput())},
	} {
		dir := t.TempDir()
		if tc.report != nil {
			writeCoverageJSON(t, dir, collector.CaptureInputFile, tc.report)
		}
		if _, ok := acceptPartialCapture(tc.err, dir, started, nil); ok {
			t.Errorf("%s accepted", name)
		}
	}
	// A report left by an earlier run is not this run's evidence.
	dir := t.TempDir()
	writeCoverageJSON(t, dir, collector.CaptureInputFile, partialInput())
	old := time.Now().Add(-time.Hour)
	if err := os.Chtimes(filepath.Join(dir, collector.CaptureInputFile), old, old); err != nil {
		t.Fatal(err)
	}
	if _, ok := acceptPartialCapture(exitStatus(2), dir, started, nil); ok {
		t.Error("stale report accepted")
	}
}

// merged.pcapng holds 559,270 packets of which 3 are Frame Relay.
func TestMixedLinkCaptureExitIsAccepted(t *testing.T) {
	dir := t.TempDir()
	r := partialInput()
	r.Status, r.ProcessedPackets, r.LinkErrors, r.Unsupported = "unsupported", 559270, 0, 3
	r.Issues = []collector.CaptureInputIssue{{Offset: 101731300, Kind: "unsupported", Reason: "unsupported capture link type 107"}}
	writeCoverageJSON(t, dir, collector.CaptureInputFile, r)
	if note, ok := acceptPartialCapture(exitStatus(3), dir, time.Now(), nil); !ok || note == "" {
		t.Fatalf("mixed-link capture rejected: %q", note)
	}
}

// An artifact or reassembly budget loss exits 2 with complete input.
func TestBudgetCoverageUsesFallbackNote(t *testing.T) {
	dir := t.TempDir()
	r := partialInput()
	r.Status, r.LinkErrors, r.Issues = "complete", 0, nil
	writeCoverageJSON(t, dir, collector.CaptureInputFile, r)
	if note, ok := acceptPartialCapture(exitStatus(2), dir, time.Now(), func() string { return "partial TCP reassembly: budget" }); !ok || note != "partial TCP reassembly: budget" {
		t.Fatalf("budget coverage: %q %v", note, ok)
	}
}

func ptr[T any](v T) *T { return &v }

func TestPartialCaptureCompletesWithCoverageNote(t *testing.T) {
	s, input, dir := reanalysisFixture(t)
	delete(s.completedFiles, input)
	s.fileBPFFilters = map[string]string{}
	s.rulesConfig = &rules.Config{}
	s.isServiceMode = true
	s.sessionManager = NewSessionManager(10, 60, 10)
	job := &AnalysisJob{InputFile: input, OutputDir: dir, SessionID: "partial", coverage: "capture input partial: link-errors=3"}
	s.sessionManager.AddSession(&SessionInfo{SessionID: job.SessionID, InputFile: input, OutputDir: dir, Status: StatusProcessing})
	writeTimelineAuditFile(t, dir, "HTTP", types.Type_NC_HTTP, []proto.Message{&types.HTTP{Timestamp: 1}})
	if err := s.completeAnalysis(job, time.Second); err != nil {
		t.Fatal(err)
	}
	session, ok := s.sessionManager.GetSession(job.SessionID)
	if !ok || session.Status != StatusCompleted || session.Coverage != job.coverage {
		t.Fatalf("session %+v", session)
	}
}
