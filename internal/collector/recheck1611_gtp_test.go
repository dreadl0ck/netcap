package collector

import (
	"archive/zip"
	"crypto/sha256"
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
			input := filepath.Join(t.TempDir(), tc.name)
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
			wantPackets := uint64(1)
			if tc.name == "gtpu_tpdu_then_endmarker.pcap" {
				wantPackets = 2
			}
			if manifest.Status != "done" || manifest.AdmittedPackets != wantPackets {
				t.Fatalf("capture status %s, admitted %d, want %d", manifest.Status, manifest.AdmittedPackets, wantPackets)
			}
			stage, _, err := evidence.ReadAuditStage(out, manifest.RunID, "GTP", manifest.AuditStagesGeneration)
			if err != nil || stage.State != "sealed" || stage.Coverage != "complete" || stage.Records != int64(len(tc.messages)) || len(stage.Files) != 1 || stage.Files[0].Name != "GTP.ncap.gz" {
				t.Fatalf("unexpected GTP stage: %+v, %v", stage, err)
			}
			var messages []int32
			for _, row := range bookRecords(t, out, "GTP", func() *types.GTP { return new(types.GTP) }) {
				messages = append(messages, row.MessageType)
			}
			slices.Sort(messages)
			if !slices.Equal(messages, tc.messages) {
				t.Fatalf("GTP messages: %v, want %v", messages, tc.messages)
			}
		})
	}
}
