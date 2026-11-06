package collector

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime/pprof"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/google/pprof/profile"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"
)

// A worker may invalidate every packet method immediately after handoff.
type accountingPacket struct {
	gopacket.Packet
	transferred atomic.Bool
}

func (p *accountingPacket) Data() []byte {
	if p.transferred.Load() {
		panic("packet accessed after ownership transfer")
	}
	return p.Packet.Data()
}

func TestCapturedByteAdmissionOwnership(t *testing.T) {
	c := &Collector{acceptingPackets: true, numWorkers: 1, workers: []chan gopacket.Packet{make(chan gopacket.Packet)}}
	base := gopacket.NewPacket(make([]byte, 60), layers.LayerTypeEthernet, gopacket.Default)
	base.Metadata().CaptureInfo = gopacket.CaptureInfo{CaptureLength: 60, Length: 1500}
	p := &accountingPacket{Packet: base}
	done := make(chan struct{})
	go func() {
		received := <-c.workers[0]
		received.(*accountingPacket).transferred.Store(true)
		c.wg.Done()
		close(done)
	}()
	if !c.submitPacket(p, false) {
		t.Fatal("packet rejected")
	}
	<-done
	if c.admittedPackets != 1 || c.admittedBytes != 60 {
		t.Fatalf("admitted = %d packets, %d bytes", c.admittedPackets, c.admittedBytes)
	}
	c.acceptingPackets = false
	if c.submitPacket(base, false) {
		t.Fatal("accepted stopped packet")
	}
	if c.admittedPackets != 1 || c.admittedBytes != 60 {
		t.Fatal("rejected packet affected totals")
	}
}

func TestCapturedByteReportTruncation(t *testing.T) {
	c := lifecycleInitCollector(t)
	input := filepath.Join(t.TempDir(), "truncated.pcap")
	f, err := os.Create(input)
	if err != nil {
		t.Fatal(err)
	}
	w := pcapgo.NewWriter(f)
	if err := w.WriteFileHeader(64, layers.LinkTypeEthernet); err != nil {
		t.Fatal(err)
	}
	data := make([]byte, 60)
	if err := w.WritePacket(gopacket.CaptureInfo{Timestamp: time.Unix(1700000000, 0), CaptureLength: len(data), Length: 1500}, data); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	if err := c.CollectPcap(input); err != nil {
		t.Fatal(err)
	}
	if c.perfTracker.TotalPackets != 1 || c.perfTracker.TotalBytes != 60 {
		t.Fatalf("performance input = %d packets, %d bytes", c.perfTracker.TotalPackets, c.perfTracker.TotalBytes)
	}
	if c.GetTotalBytesWritten() != 0 {
		t.Fatal("null output unexpectedly wrote audit bytes")
	}
	report, err := os.ReadFile(filepath.Join(c.config.DecoderConfig.Out, "performance.log"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(report), "(60 bytes)") {
		t.Fatalf("report uses wire/file/output bytes:\n%s", report)
	}
}

func TestCapturedByteAdmissionTimeout(t *testing.T) {
	c := rawPacketCollector(1, 0, gopacket.Default)
	p := &lifecyclePacket{Packet: lifecyclePayload()}
	c.handlePacketTimeout(p)
	c.wg.Wait()
	if c.admittedBytes != 0 || c.admittedPackets != 0 || c.GetNumPackets() != 0 || p.disposed.Load() != 1 {
		t.Fatalf("timed out packet affected accounting: bytes=%d packets=%d current=%d disposed=%d", c.admittedBytes, c.admittedPackets, c.GetNumPackets(), p.disposed.Load())
	}
}

func TestSignalFinalizationAfterCleanup(t *testing.T) {
	for _, fail := range []bool{false, true} {
		c := lifecycleInitCollector(t)
		if err := c.Init(); err != nil {
			t.Fatal(err)
		}
		called := false
		c.SetSignalExitHook(func() error {
			called = true
			if !c.logFilesClosed.Load() || c.workers != nil || c.netcapLogFile != nil {
				t.Error("hook ran before collector teardown")
			}
			if fail {
				return errors.New("profile finalization failure")
			}
			return nil
		})
		c.Stop()
		if called {
			t.Fatal("normal per-input cleanup finalized command profile")
		}
		code := c.finishSignalShutdown()
		if !called || (code != 0) != fail {
			t.Fatalf("called=%v exit=%d fail=%v", called, code, fail)
		}
	}
}

func TestProfileSignalProcess(t *testing.T) {
	if os.Getenv("NETCAP_ACCOUNTING_SIGNAL_HELPER") != "1" {
		return
	}
	c := lifecycleInitCollector(t)
	c.config.NoSignalHandling = false
	f, err := os.Create("signal.profile")
	if err != nil {
		t.Fatal(err)
	}
	if err := pprof.StartCPUProfile(f); err != nil {
		t.Fatal(err)
	}
	c.SetSignalExitHook(func() error {
		if !c.logFilesClosed.Load() || c.workers != nil {
			return errors.New("signal hook preceded cleanup")
		}
		pprof.StopCPUProfile()
		return errors.Join(f.Close(), os.WriteFile("finalized", []byte("after cleanup"), 0600))
	})
	if err := c.Init(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile("ready", nil, 0600); err != nil {
		t.Fatal(err)
	}
	select {}
}

func TestProfileHandledSignals(t *testing.T) {
	for _, sig := range []os.Signal{syscall.SIGINT, syscall.SIGTERM} {
		t.Run(sig.String(), func(t *testing.T) {
			dir := t.TempDir()
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestProfileSignalProcess$")
			cmd.Dir = dir
			cmd.Env = append(os.Environ(), "NETCAP_ACCOUNTING_SIGNAL_HELPER=1")
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			defer cmd.Process.Kill()
			deadline := time.Now().Add(15 * time.Second)
			for {
				if _, err := os.Stat(filepath.Join(dir, "ready")); err == nil {
					break
				}
				if time.Now().After(deadline) {
					t.Fatal("signal helper did not initialize")
				}
				time.Sleep(10 * time.Millisecond)
			}
			if err := cmd.Process.Signal(sig); err != nil {
				t.Fatal(err)
			}
			if err := cmd.Wait(); err != nil {
				t.Fatalf("handled signal: %v", err)
			}
			if b, err := os.ReadFile(filepath.Join(dir, "finalized")); err != nil || string(b) != "after cleanup" {
				t.Fatalf("finalization marker: %q, %v", b, err)
			}
			f, err := os.Open(filepath.Join(dir, "signal.profile"))
			if err != nil {
				t.Fatal(err)
			}
			defer f.Close()
			p, err := profile.Parse(f)
			if err != nil {
				t.Fatal(err)
			}
			if err := p.CheckValid(); err != nil {
				t.Fatal(err)
			}
		})
	}
}
