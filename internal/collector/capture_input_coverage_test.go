package collector

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"

	"github.com/dreadl0ck/netcap/internal/evidence"
)

func TestCaptureInputDistinguishesProtocolEvidenceFromFramingLoss(t *testing.T) {
	malformed := CaptureInputReport{ReachedEOF: true, ProcessedPackets: 1, DecodeErrors: 1}
	if err := malformed.result(); err != nil || malformed.Status != "complete" || malformed.DecodeErrors != 1 {
		t.Fatalf("fully captured malformed protocol became unread input: %+v %v", malformed, err)
	}
	for _, report := range []CaptureInputReport{
		{ProcessedPackets: 1, ReadErrors: 1},
		{ReachedEOF: true, ProcessedPackets: 1, Unsupported: 1},
	} {
		if err := report.result(); err == nil || report.Status == "complete" {
			t.Fatalf("input coverage loss became success: %+v", report)
		}
	}
	frames := CaptureInputReport{ReachedEOF: true, ProcessedPackets: 3, LinkErrors: 1}
	if err := frames.result(); err != nil || frames.Status != "partial" {
		t.Fatalf("completed frame warning: %+v %v", frames, err)
	}
}

func TestCaptureSnapshotTruncationRemainsPartial(t *testing.T) {
	frame := rawPacketFixture(t, true, 64)
	input := append(inputPCAPHeader(binary.LittleEndian, false, 65535, 1), inputPCAPRecord(binary.LittleEndian, 1, 0, 64, 128, frame)...)
	path := filepath.Join(t.TempDir(), "snapshot.pcap")
	if err := os.WriteFile(path, input, 0600); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(t.TempDir(), "audits")
	result := runInputRepro(t, path, out, 1)
	var report CaptureInputReport
	readInputJSON(t, filepath.Join(out, "capture-input.json"), &report)
	var manifest evidence.CaptureManifest
	readInputJSON(t, filepath.Join(out, "capture-manifest.json"), &manifest)
	if result.Packets != 1 || result.Error != "" || result.Complete || report.Status != "partial" || report.SnapshotTruncated != 1 || manifest.Status != "partial" || manifest.TruncatedPackets != 1 {
		t.Fatalf("snapshot truncation became complete: result=%+v report=%+v manifest=%+v", result, report, manifest)
	}
}

func TestCaptureInputExitCoverageMatrix(t *testing.T) {
	for _, tc := range []struct {
		name   string
		report CaptureInputReport
		status string
		code   int
	}{
		{"decode-warning", CaptureInputReport{ReachedEOF: true, ProcessedPackets: 1, DecodeErrors: 1}, "complete", 0},
		{"frame-warning", CaptureInputReport{ReachedEOF: true, ProcessedPackets: 2, LinkErrors: 1}, "partial", 0},
		{"no-readable-input", CaptureInputReport{ReachedEOF: true, LinkErrors: 1}, "error", 1},
		{"read-loss", CaptureInputReport{ReachedEOF: true, ProcessedPackets: 2, ReadErrors: 1}, "partial", 2},
		{"unsupported", CaptureInputReport{ReachedEOF: true, ProcessedPackets: 2, Unsupported: 1}, "unsupported", 3},
		{"mixed-loss", CaptureInputReport{ReachedEOF: true, ProcessedPackets: 2, ReadErrors: 1, Unsupported: 1}, "partial", 2},
		{"snapshot", CaptureInputReport{ReachedEOF: true, ProcessedPackets: 1, SnapshotTruncated: 1}, "partial", 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			code := 0
			if err := tc.report.result(); err != nil {
				code = err.(*CaptureInputError).ExitCode()
			}
			if tc.report.Status != tc.status || code != tc.code {
				t.Fatalf("status=%s exit=%d; want %s/%d", tc.report.Status, code, tc.status, tc.code)
			}
		})
	}
}
