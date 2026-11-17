package collector

import (
	"errors"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/dreadl0ck/netcap/internal/evidence"
	"github.com/dreadl0ck/netcap/internal/netio"
	"github.com/dreadl0ck/netcap/types"
)

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
