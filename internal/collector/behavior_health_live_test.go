//go:build linux

package collector

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/dreadl0ck/netcap/internal/behavior"
	"github.com/dreadl0ck/netcap/internal/rules"
)

func TestBehaviorHealthLinuxLoopbackCounters(t *testing.T) {
	if os.Getenv("NETCAP_BEHAVIOR_LIVE") != "1" {
		t.Skip("requires isolated Linux loopback capture and NETCAP_BEHAVIOR_LIVE=1")
	}
	dir := t.TempDir()
	sink, err := rules.NewFileAlertWriter(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer sink.Close()
	engine, err := behavior.Open(behavior.Config{Path: filepath.Join(dir, "Behavior.json")}, sink)
	if err != nil {
		t.Fatal(err)
	}
	defer engine.Close()
	cfg := liveCaptureConfig(dir, 4)
	cfg.DecoderConfig.IncludeDecoders = "Ethernet,IPv4,UDP"
	cfg.DecoderConfig.ExcludeDecoders = ""
	c := New(cfg)
	c.SetBehaviorEngine(engine, behavior.Scope{Sensor: "isolated-health", Interface: "lo"})
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- c.CollectLive("lo", "udp", ctx) }()
	conn, err := net.Dial("udp", "127.0.0.1:43219")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		_, _ = conn.Write([]byte("synthetic-health"))
		time.Sleep(10 * time.Millisecond)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	health := c.GetBehaviorHealth(dir)
	if health.Capture == nil || health.Capture.Packets == 0 || health.Capture.KernelReceived == nil || *health.Capture.KernelReceived == 0 || health.Capture.KernelDrops == nil || health.Capture.QueueDrops == nil || *health.Capture.QueueDrops != 0 || health.Capture.Scope.Interface != "lo" {
		t.Fatalf("missing actual live counters: %+v", health.Capture)
	}
	t.Logf("Linux loopback: packets=%d kernelReceived=%d kernelDrops=%d queueDrops=%d statsAt=%d", health.Capture.Packets, *health.Capture.KernelReceived, *health.Capture.KernelDrops, *health.Capture.QueueDrops, health.Capture.StatsAt)
}
