package collector

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dreadl0ck/netcap/internal/decoder/stream/tcp"
	streamutils "github.com/dreadl0ck/netcap/internal/decoder/stream/utils"
	"github.com/dreadl0ck/netcap/internal/evidence"
)

func TestTCPRetainedPayloadBudgetQualifiesFailureAndReadiness(t *testing.T) {
	for _, workers := range []int{1, 2, 4, 8} {
		for _, limit := range []int64{96, 256} {
			t.Run(fmt.Sprintf("workers=%d/limit=%d", workers, limit), func(t *testing.T) {
				wire, input := newBookCapture(t)
				for index := range 4 {
					send := wire.openTCP(fmt.Sprintf("192.0.2.%d", index+1), "198.51.100.1", uint16(45000+index), 65000, false)
					send(false, false, false, string(bytes.Repeat([]byte{0xff}, 64)))
				}
				out := t.TempDir()
				configuration := ultimateCaptureConfig(out, workers, 0)
				configuration.CaptureEvidence = true
				configuration.DecoderConfig.IncludeDecoders = "TCP,Connection"
				configuration.DecoderConfig.MaxRetainedTCPBytes = limit
				configuration.DecoderConfig.SaveConns = true
				collector := New(configuration)
				err := collector.CollectPcap(input)
				health := bookJSON[tcp.ReassemblyHealth](t, filepath.Join(out, "TCPReassemblyHealth.json"))
				if health.RetainedPayload == nil || health.RetainedPayload.LimitBytes != limit || health.RetainedPayload.PeakBytes > limit || health.RetainedPayload.RetainedBytes != 0 {
					t.Fatalf("invalid shared budget health: %+v", health.RetainedPayload)
				}
				manifest := bookJSON[evidence.CaptureManifest](t, filepath.Join(out, "capture-manifest.json"))
				streams, globErr := filepath.Glob(filepath.Join(out, "stream-evidence", "stream-*", "manifest.json"))
				if globErr != nil {
					t.Fatal(globErr)
				}
				var discarded int64
				for _, path := range streams {
					stream := bookJSON[streamutils.StreamEvidenceManifest](t, path)
					for _, span := range stream.Spans {
						if span.DiscardedBytes > 0 {
							if stream.Status != "locally-truncated" || span.MissingBytes != 0 || span.DiscardReason != "tcp-retained-payload-budget" {
								t.Fatalf("local omission became a network gap or clean stream: %+v", stream)
							}
							discarded += span.DiscardedBytes
						}
					}
				}
				if discarded != health.RetainedPayload.RejectedBytes {
					t.Fatalf("per-stream discard evidence lost: spans=%d health=%d", discarded, health.RetainedPayload.RejectedBytes)
				}
				if manifest.Config.MaxRetainedTCPBytes != limit {
					t.Fatal("effective retention budget missing from capture configuration")
				}
				_, readyErr := os.Stat(filepath.Join(out, evidence.AuditReadyFile))
				if limit == 96 {
					if !errors.Is(err, tcp.ErrRetainedPayloadLimit) || manifest.Status != "error" || !strings.Contains(manifest.Error, "retained payload budget exceeded") || !os.IsNotExist(readyErr) || !health.RetainedPayload.Exceeded || health.RetainedPayload.RejectedBytes == 0 {
						t.Fatalf("overflow became successful output: err=%v manifest=%+v health=%+v ready=%v", err, manifest, health.RetainedPayload, readyErr)
					}
				} else {
					if err != nil || manifest.Status != "done" || readyErr != nil || health.RetainedPayload.Exceeded || health.RetainedPayload.PeakBytes < 64 || manifest.AdmittedPackets != uint64(wire.n) {
						t.Fatalf("under-budget capture failed: err=%v manifest=%+v health=%+v ready=%v", err, manifest, health.RetainedPayload, readyErr)
					}
				}
			})
		}
	}
}

func TestNegativeTCPRetentionBudgetRefusesInitialization(t *testing.T) {
	configuration := ultimateCaptureConfig(t.TempDir(), 1, 0)
	configuration.DecoderConfig.MaxRetainedTCPBytes = -1
	collector := New(configuration)
	defer collector.Stop()
	if err := collector.Init(); err == nil || !strings.Contains(err.Error(), "cannot be negative") {
		t.Fatalf("negative budget accepted: %v", err)
	}
	if collector.initialized || len(collector.workers) != 0 {
		t.Fatal("invalid budget started workers")
	}
}
