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
		{ReachedEOF: true, ProcessedPackets: 1, LinkErrors: 1},
		{ProcessedPackets: 1, ReadErrors: 1},
		{ReachedEOF: true, ProcessedPackets: 1, Unsupported: 1},
	} {
		if err := report.result(); err == nil || report.Status == "complete" {
			t.Fatalf("input coverage loss became success: %+v", report)
		}
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
