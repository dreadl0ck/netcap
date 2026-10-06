package collector

import (
	"errors"
	"path/filepath"
	"testing"

	"github.com/dreadl0ck/netcap/internal/behavior"
	"github.com/dreadl0ck/netcap/internal/rules"
	"github.com/gopacket/gopacket"
)

func TestBehaviorHealthCumulativeKernelDeltasAndAdmission(t *testing.T) {
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
	c := &Collector{workers: []chan gopacket.Packet{make(chan gopacket.Packet, 8)}}
	c.SetBehaviorEngine(engine, behavior.Scope{Sensor: "test", Interface: "eth0"})
	c.behaviorPackets, c.behaviorQueueDrops = 20, 2
	c.recordBehaviorCaptureStats(12, 3, true, nil)
	c.recordBehaviorCaptureStats(8, 2, true, nil)
	c.recordBehaviorCaptureStats(0, 0, true, errors.New("counter unavailable"))
	c.SetBehaviorDeliveryHealth(func() *behavior.DeliveryHealth { return &behavior.DeliveryHealth{Acked: 4, Pending: 1} })
	health := c.GetBehaviorHealth(dir)
	if health.Capture.Packets != 20 || *health.Capture.KernelReceived != 20 || *health.Capture.KernelDrops != 5 || *health.Capture.QueueDrops != 2 || health.Capture.QueueCapacity != 8 || health.Capture.StatsError == "" || health.Delivery.Pending != 1 {
		t.Fatalf("health = %+v", health)
	}
	c.recordBehaviorCaptureStats(30, 6, false, nil)
	if capture := c.GetBehaviorHealth(dir).Capture; *capture.KernelReceived != 30 || *capture.KernelDrops != 6 || capture.StatsError != "" {
		t.Fatal("cumulative source was double-counted")
	}
	c.SetBehaviorEngine(engine, behavior.Scope{Sensor: "test", Interface: "eth0"})
	if capture := c.GetBehaviorHealth(dir).Capture; capture.KernelDrops != nil || capture.Packets != 0 || *capture.QueueDrops != 0 {
		t.Fatal("new capture retained previous counters")
	}
}
