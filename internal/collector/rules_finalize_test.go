package collector

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dreadl0ck/netcap/internal/delivery"
	"github.com/dreadl0ck/netcap/internal/evidence"
	"github.com/dreadl0ck/netcap/internal/rules"
	"github.com/dreadl0ck/netcap/types"
)

type captureRuleWriter struct {
	count int
	fail  bool
}

func (w *captureRuleWriter) WriteAlert(*types.Alert) error {
	if w.fail {
		return errors.New("rules persistence negative control")
	}
	w.count++
	return nil
}
func (w *captureRuleWriter) Close() error { return nil }

func TestRulesFinalizeBeforeReadinessAndOutbox(t *testing.T) {
	for _, failure := range []string{"", "audit", "outbox"} {
		t.Run("failure="+failure, func(t *testing.T) {
			wire, input := newBookCapture(t)
			wire.conversation("192.0.2.1", "198.51.100.1", 40000, 80, false,
				bookMessage{text: "GET / HTTP/1.1\r\nHost: fixture.test\r\n\r\n"},
				bookMessage{server: true, text: "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"})
			out := t.TempDir()
			cfg := ultimateCaptureConfig(out, 2, 0)
			cfg.CaptureEvidence = true
			cfg.DecoderConfig.IncludeDecoders = "TCP,Connection,HTTP"
			c := New(cfg)
			audit := &captureRuleWriter{fail: failure == "audit"}
			box, err := delivery.Open(t.TempDir(), "http://127.0.0.1:1")
			if err != nil {
				t.Fatal(err)
			}
			defer box.Close()
			if failure == "outbox" {
				if err := box.Close(); err != nil {
					t.Fatal(err)
				}
			}
			engine, err := rules.NewEngineFromConfig(&rules.Config{
				CaptureTime: &rules.CaptureTimeConfig{Scope: "declared-source", LatenessSeconds: 600},
				Rules:       []*rules.Rule{{Name: "final-response", Type: "HTTP", Expression: "StatusCode == 200", Enabled: true}},
			}, &delivery.Writer{Audit: audit, Outbox: box, Scope: "fixture"})
			if err != nil {
				t.Fatal(err)
			}
			c.SetRulesEngine(engine)
			err = c.CollectPcap(input)
			manifest := bookJSON[evidence.CaptureManifest](t, filepath.Join(out, "capture-manifest.json"))
			_, ready := os.Stat(filepath.Join(out, evidence.AuditReadyFile))
			if failure != "" {
				if err == nil || manifest.Status != "error" || !os.IsNotExist(ready) || !strings.Contains(manifest.Error, "finalize rules") {
					t.Fatalf("failed rules became ready: %v %+v %v", err, manifest, ready)
				}
			} else {
				status, statusErr := box.Status()
				if err != nil || manifest.Status != "done" || ready != nil || c.GetAlertCount() != 1 || audit.count != 1 || statusErr != nil || status.Pending != 1 {
					t.Fatalf("final alert missing: %v %s ready=%v count=%d audit=%d outbox=%+v/%v", err, manifest.Status, ready, c.GetAlertCount(), audit.count, status, statusErr)
				}
			}
			if n, _ := engine.Finalize(); n != 0 {
				t.Fatal("finalization duplicated alerts", n)
			}
		})
	}
}

func TestObservedRulesKeepMixedScopesSeparate(t *testing.T) {
	writer := &captureRuleWriter{}
	e, err := rules.NewEngineFromConfig(&rules.Config{CaptureTime: &rules.CaptureTimeConfig{Scope: "declared", LatenessSeconds: 600}, Rules: []*rules.Rule{{Name: "two", Type: "TCP", Expression: "SYN", Enabled: true, Threshold: 2, GroupBy: []string{"SrcIP"}}}}, writer)
	if err != nil {
		t.Fatal(err)
	}
	c := New(ultimateCaptureConfig(t.TempDir(), 2, 0))
	c.SetRulesEngine(e)
	for _, scope := range []string{"source-a/interface-1/vlan-7", "source-b/interface-1/vlan-7", "source-a/interface-2/vlan-7", "source-a/interface-1/vlan-8"} {
		c.evaluateRulesWithScope(&types.TCP{Timestamp: 1700000000000000000, SrcIP: "192.0.2.1", SYN: true}, scope)
	}
	if n, err := e.Finalize(); n != 0 || err != nil || writer.count != 0 {
		t.Fatal("scopes combined", n, err, writer.count)
	}
	if c.rulesError != nil {
		t.Fatal(c.rulesError)
	}
}

func TestPacketPipelineScopedRules(t *testing.T) {
	input := filepath.Join(t.TempDir(), "mixed.pcap")
	pipelinePCAP(t, input)
	for _, workers := range []int{1, 2} {
		cfg := ultimateCaptureConfig(t.TempDir(), workers, 0)
		cfg.CaptureEvidence = true
		cfg.DecoderConfig.IncludeDecoders = "TCP,Connection"
		writer := &captureRuleWriter{}
		engine, err := rules.NewEngineFromConfig(&rules.Config{CaptureTime: &rules.CaptureTimeConfig{Scope: "single-file-mixed-networks", LatenessSeconds: 600}, Rules: []*rules.Rule{{Name: "no-cross-network-count", Type: "TCP", Expression: "SYN && !ACK", Enabled: true, Threshold: 6, ThresholdWindow: 600, GroupBy: []string{"SrcIP"}}}}, writer)
		if err != nil {
			t.Fatal(err)
		}
		c := New(cfg)
		c.SetRulesEngine(engine)
		if err := c.CollectPcap(input); err != nil {
			t.Fatal(err)
		}
		if writer.count != 0 || c.GetAlertCount() != 0 {
			t.Fatal("mixed interface/VLAN/tunnel observations combined", writer.count, c.GetAlertCount())
		}
	}
}
