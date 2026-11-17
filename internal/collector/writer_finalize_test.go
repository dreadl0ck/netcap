package collector

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/dreadl0ck/netcap/internal/evidence"
	"github.com/dreadl0ck/netcap/internal/netio"
	"github.com/dreadl0ck/netcap/types"
)

func TestArtifactCoverageDoesNotUnsealPacketAudits(t *testing.T) {
	out := t.TempDir()
	capture, err := evidence.NewCapture(context.Background(), out, evidence.CaptureConfig{Kind: "live"})
	if err != nil {
		t.Fatal(err)
	}
	c := &Collector{captureEvidence: capture, captureComplete: true, artifactAnalysisError: errors.New("artifact analysis incomplete")}
	c.auditStages = []evidence.AuditStage{
		{Type: "UDP", Stage: "packet", State: "sealed", Coverage: "complete"},
		{Type: "File", Stage: "application", State: "sealed", Coverage: "complete"},
	}
	c.finalizeCaptureEvidence()
	if err := c.sealAuditStages(); err != nil {
		t.Fatal(err)
	}
	manifest := bookJSON[evidence.CaptureManifest](t, filepath.Join(out, "capture-manifest.json"))
	if manifest.Status != "partial" || manifest.CoverageError != "artifact analysis incomplete" || manifest.Error != "" {
		t.Fatal(manifest)
	}
	if err := capture.MarkAuditOutputReady(); err == nil {
		t.Fatal("artifact loss allowed full readiness")
	}
	stage, _, err := evidence.ReadAuditStage(out, manifest.RunID, "UDP", manifest.AuditStagesGeneration)
	if err != nil || stage.Coverage != "complete" {
		t.Fatal(stage, err)
	}
	if _, _, err := evidence.ReadAuditStage(out, manifest.RunID, "File", manifest.AuditStagesGeneration); err == nil {
		t.Fatal("unavailable artifact stage was readable")
	}
}

type captureCloseFailureWriter struct {
	netio.AuditRecordWriter
	closed  atomic.Bool
	failure error
}

func (w *captureCloseFailureWriter) Close(n int64) (string, int64) {
	name, size := w.AuditRecordWriter.Close(n)
	w.closed.Store(true)
	return name, size
}
func (w *captureCloseFailureWriter) Error() error {
	if w.closed.Load() {
		return w.failure
	}
	return nil
}

func TestWriterFinalizationFailurePreventsReadiness(t *testing.T) {
	_, input := newBookCapture(t)
	out := t.TempDir()
	cfg := ultimateCaptureConfig(out, 1, 0)
	cfg.CaptureEvidence = true
	cfg.DecoderConfig.IncludeDecoders = "UDP"
	c := New(cfg)
	c.captureKind, c.captureSource = "file", input
	if err := c.Init(); err != nil {
		t.Fatal(err)
	}
	failure := errors.New("audit finalization negative control")
	installed := false
	for _, group := range c.goPacketDecoders {
		for _, decoder := range group {
			if decoder.GetType() == types.Type_NC_UDP {
				decoder.SetWriter(&captureCloseFailureWriter{AuditRecordWriter: decoder.GetWriter(), failure: failure})
				installed = true
			}
		}
	}
	if !installed {
		c.Stop()
		t.Fatal("writer control was not installed")
	}
	err := c.CollectPcap(input)
	if !errors.Is(err, failure) {
		t.Fatal("collector discarded writer finalization failure", err)
	}
	manifest := bookJSON[evidence.CaptureManifest](t, filepath.Join(out, "capture-manifest.json"))
	if manifest.Status != "error" || manifest.Error == "" {
		t.Fatal("failed writer became a successful capture", manifest.Status, manifest.Error)
	}
	if _, err := os.Stat(filepath.Join(out, evidence.AuditReadyFile)); !os.IsNotExist(err) {
		t.Fatal("failed writer published readiness", err)
	}
}
