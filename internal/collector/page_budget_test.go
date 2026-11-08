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
	"github.com/gopacket/gopacket/layers"
)

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
