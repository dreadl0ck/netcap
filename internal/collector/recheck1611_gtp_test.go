package collector

import (
	"archive/zip"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/dreadl0ck/netcap/defaults"
	"github.com/dreadl0ck/netcap/internal/evidence"
	"github.com/dreadl0ck/netcap/types"
)

func TestGTPMixedAuditSealing(t *testing.T) {
	// The two-packet T-PDU/End Marker fixture from the v0.16.11 archive.
	data, err := hex.DecodeString("d4c3b2a1020004000000000000000000ffff000001000000" +
		"00f15365000000005300000053000000020000000002020000000001080045000045000100004011f6a3c0000201c00002020868086800313cba30ff0021000011114500002100010000401166b70a0900010a09000213881389000d80dc68656c6c6f" +
		"00f15365102700003200000032000000020000000002020000000001080045000024000100004011f6c4c0000201c000020208680868001028eb30fe000000001111")
	if err != nil {
		t.Fatal(err)
	}
	checkGTPAuditSealing(t, data, 2, []int32{254})
}

func TestRecheck1611GTPAuditSealing(t *testing.T) {
	path := os.Getenv("NETCAP_RECHECK_1611_ARCHIVE")
	if path == "" {
		t.Skip("set NETCAP_RECHECK_1611_ARCHIVE to the pinned synthetic archive")
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		t.Fatal(err)
	}
	h := sha256.New()
	if _, err := io.Copy(h, io.NewSectionReader(f, 0, info.Size())); err != nil {
		t.Fatal(err)
	}
	if fmt.Sprintf("%x", h.Sum(nil)) != "6d5c914a95b343096f86e454ee67a122a1da47b1172dcc82d8dc39f70312133e" {
		t.Fatal("unexpected v0.16.11 archive digest")
	}
	z, err := zip.NewReader(f, info.Size())
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name     string
		messages []int32
	}{
		{"gtpu_type_01.pcap", []int32{1}},
		{"gtpu_type_02.pcap", []int32{2}},
		{"gtpu_type_1a.pcap", []int32{26}},
		{"gtpu_type_1f.pcap", []int32{31}},
		{"gtpu_endmarker_only.pcap", []int32{254}},
		{"gtpu_tpdu_then_endmarker.pcap", []int32{254}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			wire, err := z.Open("netcap-v0.16.11-synthetic-repros/repro/v1611/gtp/" + tc.name)
			if err != nil {
				t.Fatal(err)
			}
			data, err := io.ReadAll(io.LimitReader(wire, 1<<20))
			wire.Close()
			if err != nil {
				t.Fatal(err)
			}
			wantPackets := uint64(1)
			if tc.name == "gtpu_tpdu_then_endmarker.pcap" {
				wantPackets = 2
			}
			checkGTPAuditSealing(t, data, wantPackets, tc.messages)
		})
	}
}

func checkGTPAuditSealing(t *testing.T, data []byte, wantPackets uint64, wantMessages []int32) {
	t.Helper()
	input := filepath.Join(t.TempDir(), "gtp.pcap")
	if err := os.WriteFile(input, data, 0600); err != nil {
		t.Fatal(err)
	}
	out := t.TempDir()
	cfg := ultimateCaptureConfig(out, 1, 0)
	cfg.CaptureEvidence = true
	cfg.DecoderConfig.Compression = true
	cfg.DecoderConfig.CompressionBlockSize = defaults.CompressionBlockSize
	cfg.DecoderConfig.CompressionLevel = defaults.CompressionLevel
	if err := New(cfg).CollectPcap(input); err != nil {
		t.Fatal(err)
	}
	manifest := bookJSON[evidence.CaptureManifest](t, filepath.Join(out, "capture-manifest.json"))
	if manifest.Status != "done" || manifest.AdmittedPackets != wantPackets {
		t.Fatalf("capture status %s, admitted %d, want %d", manifest.Status, manifest.AdmittedPackets, wantPackets)
	}
	stage, _, err := evidence.ReadAuditStage(out, manifest.RunID, "GTP", manifest.AuditStagesGeneration)
	if err != nil || stage.State != "sealed" || stage.Coverage != "complete" || stage.Records != int64(len(wantMessages)) || len(stage.Files) != 1 || stage.Files[0].Name != "GTP.ncap.gz" {
		t.Fatalf("unexpected GTP stage: %+v, %v", stage, err)
	}
	var messages []int32
	for _, row := range bookRecords(t, out, "GTP", func() *types.GTP { return new(types.GTP) }) {
		messages = append(messages, row.MessageType)
	}
	slices.Sort(messages)
	if !slices.Equal(messages, wantMessages) {
		t.Fatalf("GTP messages: %v, want %v", messages, wantMessages)
	}
}
