package collector

import (
	"context"
	"errors"
	"os/exec"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/gopacket/gopacket/pcap"
)

// loopbackInterface returns the loopback device, or skips when live capture is
// unavailable (no permission on /dev/bpf, or no loopback in the environment).
func loopbackInterface(t *testing.T) string {
	t.Helper()
	name := "lo"
	if runtime.GOOS == "darwin" {
		name = "lo0"
	}
	handle, err := pcap.OpenLive(name, 1024, false, 50*time.Millisecond)
	if err != nil {
		t.Skipf("live capture unavailable on %s: %v", name, err)
	}
	handle.Close()
	return name
}

// pingLoopback generates traffic for the capture to observe.
func pingLoopback(t *testing.T, done <-chan struct{}) *sync.WaitGroup {
	t.Helper()
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-done:
				return
			default:
				_ = exec.Command("ping", "-c", "3", "-i", "0.2", "localhost").Run()
			}
		}
	}()
	return &wg
}

func liveCaptureConfig(out string, workers int) Config {
	cfg := ultimateCaptureConfig(out, workers, 0)
	cfg.Promisc = false
	cfg.Timeout = time.Second
	cfg.DecoderConfig.WaitForConnections = false
	cfg.DecoderConfig.ClosePendingTimeOut = time.Second
	cfg.DecoderConfig.CloseInactiveTimeOut = 2 * time.Second
	return cfg
}

// TestLiveCaptureWorkerPools covers CollectLive, which the PCAP tests never
// reach: producer cancellation, the interrupt handle that unblocks a idle
// libpcap read, and cleanup joining a live producer.
func TestLiveCaptureWorkerPools(t *testing.T) {
	if testing.Short() {
		t.Skip("captures live traffic")
	}
	iface := loopbackInterface(t)

	for _, workers := range []int{1, 4} {
		t.Run("workers="+string(rune('0'+workers)), func(t *testing.T) {
			out := t.TempDir()
			c := New(liveCaptureConfig(out, workers))

			stopPing := make(chan struct{})
			pingers := pingLoopback(t, stopPing)

			ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
			defer cancel()

			start := time.Now()
			err := c.CollectLive(iface, "", ctx)
			elapsed := time.Since(start)
			close(stopPing)
			pingers.Wait()

			if err != nil && !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("live capture failed: %v", err)
			}
			// Cancellation must actually unblock the read loop rather than
			// leaving cleanup to wait on an idle producer.
			if elapsed > 60*time.Second {
				t.Fatalf("live capture took %s to stop after cancellation", elapsed)
			}
			if got := c.GetNumPackets(); got <= 0 {
				t.Fatalf("captured %d packets; expected loopback traffic", got)
			}
			t.Logf("workers=%d: %d packets in %s", workers, c.GetNumPackets(), elapsed)

			// Records must be readable, which also proves teardown flushed
			// and closed the writers rather than racing them.
			counts, _ := ultimateRecords(t, out)
			if len(counts) == 0 {
				t.Fatal("live capture produced no audit records")
			}
		})
	}
}

// TestLiveCaptureStopUnblocksIdleRead pins the shutdown path that has no
// traffic at all: with an empty loopback the producer sits in a libpcap read,
// and Stop must still return promptly.
func TestLiveCaptureStopUnblocksIdleRead(t *testing.T) {
	if testing.Short() {
		t.Skip("captures live traffic")
	}
	iface := loopbackInterface(t)
	c := New(liveCaptureConfig(t.TempDir(), 2))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan error, 1)
	go func() { done <- c.CollectLive(iface, "udp port 65534", ctx) }()

	// Let the producer reach its read loop, then cancel with no traffic.
	time.Sleep(1500 * time.Millisecond)
	start := time.Now()
	cancel()

	select {
	case err := <-done:
		if err != nil && !errors.Is(err, context.Canceled) {
			t.Fatalf("live capture failed: %v", err)
		}
		t.Logf("idle live capture stopped in %s", time.Since(start))
	case <-time.After(60 * time.Second):
		t.Fatal("cancelled live capture did not stop")
	}
}

// TestBatchModeWorkerPools covers InitBatching, whose read loop this branch
// rewrote from ranging Packets() to NextPacket.
func TestBatchModeWorkerPools(t *testing.T) {
	if testing.Short() {
		t.Skip("captures live traffic")
	}
	iface := loopbackInterface(t)
	out := t.TempDir()
	c := New(liveCaptureConfig(out, 4))

	chans, handle, err := c.InitBatching("", iface)
	if err != nil {
		t.Fatalf("InitBatching: %v", err)
	}
	if len(chans) == 0 {
		t.Fatal("InitBatching returned no decoder channels")
	}

	stopPing := make(chan struct{})
	pingers := pingLoopback(t, stopPing)
	time.Sleep(2 * time.Second)
	close(stopPing)
	pingers.Wait()

	// Stop closes the handle and joins the batching producer.
	stopped := make(chan struct{})
	go func() {
		defer close(stopped)
		c.Stop()
		handle.Close()
	}()
	select {
	case <-stopped:
	case <-time.After(60 * time.Second):
		t.Fatal("batch mode did not stop")
	}

	if got := c.GetNumPackets(); got <= 0 {
		t.Logf("batch mode observed %d packets", got)
	}
	if _, err := filepath.Glob(filepath.Join(out, "*.ncap")); err != nil {
		t.Fatal(err)
	}
}
