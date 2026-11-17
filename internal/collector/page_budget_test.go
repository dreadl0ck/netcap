package collector

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	streamutils "github.com/dreadl0ck/netcap/internal/decoder/stream/utils"
	"github.com/dreadl0ck/netcap/internal/evidence"
	"github.com/dreadl0ck/netcap/internal/reassembly"
	"github.com/dreadl0ck/netcap/types"
	"github.com/gopacket/gopacket/layers"
)

func TestLocalReassemblyPageLossPreservesIndependentOutput(t *testing.T) {
	wire, input := newBookCapture(t)
	for index := range 4 {
		src, port := fmt.Sprintf("192.0.2.%d", index+1), uint16(45000+index)
		wire.openTCP(src, "198.51.100.1", port, 65000, false)
		wire.packet(src, "198.51.100.1", &layers.TCP{SrcPort: layers.TCPPort(port), DstPort: 65000, Seq: 1011, Ack: 5001, ACK: true, PSH: true, Window: 65535}, strings.Repeat("x", 64), false)
	}
	out := t.TempDir()
	cfg := ultimateCaptureConfig(out, 1, 0)
	cfg.CaptureEvidence = true
	cfg.DecoderConfig.IncludeDecoders = "TCP,Connection"
	cfg.DecoderConfig.SaveConns = true
	cfg.DecoderConfig.MaxRetainedReassemblyBytes = 2 * reassembly.PageAllocationBytes
	cfg.DecoderConfig.LocalReassemblyPageLoss = true
	err := New(cfg).CollectPcap(input)
	var partial *localReassemblyCoverageError
	if !errors.As(err, &partial) || partial.ExitCode() != 2 || !errors.Is(err, reassembly.ErrPageBudget) {
		t.Fatal(err)
	}
	manifest := bookJSON[evidence.CaptureManifest](t, filepath.Join(out, "capture-manifest.json"))
	if manifest.Status != "partial" || manifest.Error != "" || manifest.CoverageError == "" || !manifest.Config.LocalReassemblyPageLoss || manifest.AdmittedPackets != 16 {
		t.Fatalf("unexpected manifest: %+v", manifest)
	}
	if _, err := os.Stat(filepath.Join(out, evidence.AuditReadyFile)); !os.IsNotExist(err) {
		t.Fatal("full readiness published", err)
	}
	health := bookJSON[reassembly.PageBudgetHealth](t, filepath.Join(out, "TCPReassemblyPageBudget.json"))
	if !health.Exceeded || health.PeakBytes > health.LimitBytes || health.RetainedBytes != 0 {
		t.Fatal(health)
	}
	for typ, want := range map[string]string{"TCP": "complete", "Connection": "partial"} {
		stage, _, err := evidence.ReadAuditStage(out, manifest.RunID, typ, manifest.AuditStagesGeneration)
		if err != nil || stage.Coverage != want || stage.Records == 0 {
			t.Fatal(typ, stage, err)
		}
	}
	ports := map[string]bool{}
	for _, record := range bookRecords(t, out, "Connection", func() *types.Connection { return new(types.Connection) }) {
		if record.DstPort == "65000" {
			ports[record.SrcPort] = true
		}
	}
	for port := 45000; port < 45004; port++ {
		if !ports[fmt.Sprint(port)] {
			t.Fatal("lost independent connection", port, ports)
		}
	}
}

func TestLocalReassemblyPageLossOmitsOnlyAffectedHTTPFlow(t *testing.T) {
	wire, input := newBookCapture(t)
	// This flow holds the one available queued page until capture finalization.
	wire.openTCP("192.0.2.1", "198.51.100.1", 45000, 65000, false)
	wire.packet("192.0.2.1", "198.51.100.1", &layers.TCP{SrcPort: 45000, DstPort: 65000, Seq: 1011, Ack: 5001, ACK: true, Window: 65535}, "queue", false)
	affected := wire.openTCP("192.0.2.2", "198.51.100.1", 45001, 80, false)
	wire.packet("192.0.2.2", "198.51.100.1", &layers.TCP{SrcPort: 45001, DstPort: 80, Seq: 1101, Ack: 5001, ACK: true, Window: 65535}, "refused", false)
	affected(false, false, false, "GET /affected HTTP/1.1\r\nHost: fixture.test\r\n\r\n")
	wire.conversation("192.0.2.3", "198.51.100.1", 45002, 80, false,
		bookMessage{text: "GET /healthy HTTP/1.1\r\nHost: fixture.test\r\n\r\n"},
		bookMessage{server: true, text: "HTTP/1.1 204 No Content\r\n\r\n"})
	out := t.TempDir()
	cfg := ultimateCaptureConfig(out, 1, 0)
	cfg.CaptureEvidence = true
	cfg.DecoderConfig.IncludeDecoders = "TCP,Connection,HTTP"
	cfg.DecoderConfig.SaveConns = true
	cfg.DecoderConfig.MaxRetainedReassemblyBytes = reassembly.PageAllocationBytes
	cfg.DecoderConfig.LocalReassemblyPageLoss = true
	if err := New(cfg).CollectPcap(input); !errors.Is(err, reassembly.ErrPageBudget) {
		t.Fatal(err)
	}
	if records := bookRecords(t, out, "HTTP", func() *types.HTTP { return new(types.HTTP) }); len(records) != 1 || records[0].URL != "/healthy" || records[0].StatusCode != 204 {
		t.Fatalf("unexpected application audits: %v", records)
	}
	manifest := bookJSON[evidence.CaptureManifest](t, filepath.Join(out, "capture-manifest.json"))
	stage, _, err := evidence.ReadAuditStage(out, manifest.RunID, "HTTP", manifest.AuditStagesGeneration)
	if err != nil || stage.Coverage != "partial" || stage.Records != 1 {
		t.Fatal(stage, err)
	}
}

func TestReassemblyPageBudgetCaptureReadinessAndLocalLoss(t *testing.T) {
	for _, workers := range []int{1, 2, 4, 8} {
		for _, pages := range []int64{2, 8} {
			t.Run(fmt.Sprintf("workers=%d/pages=%d", workers, pages), func(t *testing.T) {
				wire, input := newBookCapture(t)
				for index := range 4 {
					src, port := fmt.Sprintf("192.0.2.%d", index+1), uint16(45000+index)
					wire.openTCP(src, "198.51.100.1", port, 65000, false)
					wire.packet(src, "198.51.100.1", &layers.TCP{SrcPort: layers.TCPPort(port), DstPort: 65000, Seq: 1011, Ack: 5001, ACK: true, PSH: true, Window: 65535}, strings.Repeat("x", 64), false)
				}
				out := t.TempDir()
				configuration := ultimateCaptureConfig(out, workers, 0)
				configuration.CaptureEvidence = true
				configuration.DecoderConfig.IncludeDecoders = "TCP,Connection"
				configuration.DecoderConfig.SaveConns = true
				configuration.DecoderConfig.MaxRetainedReassemblyBytes = pages * reassembly.PageAllocationBytes
				c := New(configuration)
				err := c.CollectPcap(input)
				health := bookJSON[reassembly.PageBudgetHealth](t, filepath.Join(out, "TCPReassemblyPageBudget.json"))
				manifest := bookJSON[evidence.CaptureManifest](t, filepath.Join(out, "capture-manifest.json"))
				if health.PeakBytes > health.LimitBytes || health.RetainedBytes != 0 || health.LimitBytes != configuration.DecoderConfig.MaxRetainedReassemblyBytes || manifest.Config.MaxRetainedReassemblyBytes != health.LimitBytes {
					t.Fatal("global page accounting/configuration mismatch", health, manifest.Config)
				}
				_, readyErr := os.Stat(filepath.Join(out, evidence.AuditReadyFile))
				if pages == 2 {
					if !errors.Is(err, reassembly.ErrPageBudget) || manifest.Status != "error" || !os.IsNotExist(readyErr) || !health.Exceeded {
						t.Fatal("page exhaustion became successful capture", err, manifest.Status, readyErr, health)
					}
					streams, _ := filepath.Glob(filepath.Join(out, "stream-evidence", "stream-*", "manifest.json"))
					var discarded int64
					for _, path := range streams {
						stream := bookJSON[streamutils.StreamEvidenceManifest](t, path)
						for _, span := range stream.Spans {
							if span.DiscardReason == "tcp-reassembly-page-budget" {
								if stream.Status != "locally-truncated" || span.MissingBytes != 0 {
									t.Fatal("local page loss lost qualification", stream)
								}
								discarded += span.DiscardedBytes
							}
						}
					}
					if discarded == 0 {
						t.Fatal("page budget omitted local discard witnesses")
					}
				} else if err != nil || manifest.Status != "done" || readyErr != nil || health.Exceeded || health.PeakBytes != 4*reassembly.PageAllocationBytes {
					t.Fatal("under-budget control failed", err, manifest.Status, readyErr, health)
				}
			})
		}
	}
}
