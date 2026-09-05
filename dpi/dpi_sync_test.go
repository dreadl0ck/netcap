//go:build (!windows && ignore) || !nodpi

package dpi

import (
	"net"
	"sync"
	"testing"
	"time"

	dpitypes "github.com/dreadl0ck/go-dpi/types"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

func TestDPILifecycleIdempotent(t *testing.T) {
	Destroy()
	t.Cleanup(Destroy)
	Init("go")
	tracker := dpitypes.FlowTrackerInstance
	if !IsEnabled() || tracker == nil {
		t.Fatal("Init did not enable DPI and initialize flow tracking")
	}

	var wg sync.WaitGroup
	for range 16 {
		wg.Go(func() { Init("go") })
	}
	wg.Wait()
	if dpitypes.FlowTrackerInstance != tracker {
		t.Fatal("repeated Init replaced the active flow tracker")
	}
	for range 16 {
		wg.Go(Destroy)
	}
	wg.Wait()
	if IsEnabled() || dpitypes.FlowTrackerInstance != nil {
		t.Fatal("Destroy did not disable DPI and release flow tracking")
	}

	Init("go")
	if !IsEnabled() || dpitypes.FlowTrackerInstance == nil {
		t.Fatal("Init after Destroy did not enable DPI")
	}
	Reset("go")
	Reset("go")
	if IsEnabled() || dpitypes.FlowTrackerInstance != nil {
		t.Fatal("Reset must remain teardown-only")
	}
}

func TestDPIClassifyConcurrentDestroy(t *testing.T) {
	Destroy()
	t.Cleanup(Destroy)
	ip := &layers.IPv4{
		Version: 4, TTL: 64, Protocol: layers.IPProtocolTCP,
		SrcIP: net.IPv4(192, 0, 2, 1), DstIP: net.IPv4(192, 0, 2, 2),
	}
	tcp := &layers.TCP{SrcPort: 12345, DstPort: 80, ACK: true}
	if err := tcp.SetNetworkLayerForChecksum(ip); err != nil {
		t.Fatal(err)
	}
	buf := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true},
		ip, tcp, gopacket.Payload("GET / HTTP/1.1\r\nHost: example.test\r\n\r\n")); err != nil {
		t.Fatal(err)
	}
	// Eager decoding and owned bytes keep the shared packet immutable.
	packet := gopacket.NewPacket(buf.Bytes(), layers.LayerTypeIPv4, gopacket.Default)
	if err := packet.ErrorLayer(); err != nil {
		t.Fatal(err)
	}

	for range 10 {
		Init("go")
		var ready, workers sync.WaitGroup
		resume := make(chan struct{})
		for range 8 {
			ready.Add(1)
			workers.Go(func() {
				if _, ok := GetProtocols(packet)["HTTP"]; !ok {
					t.Error("enabled Go classifier did not identify HTTP")
				}
				ready.Done()
				<-resume
				for range 32 {
					results := GetProtocols(packet)
					if results != nil {
						if _, ok := results["HTTP"]; !ok {
							t.Error("classification lost HTTP before teardown")
						}
					}
				}
			})
		}
		ready.Wait()
		workers.Go(func() {
			<-resume
			Destroy()
		})
		close(resume)
		workers.Wait()
		if IsEnabled() || GetProtocols(packet) != nil {
			t.Fatal("classification remained enabled after Destroy")
		}
	}
}

func TestDPIDisabledFastPath(t *testing.T) {
	Destroy()
	t.Cleanup(Destroy)
	dpiMu.Lock()
	defer dpiMu.Unlock()
	done := make(chan bool, 1)
	go func() { done <- GetProtocols(nil) == nil }()
	select {
	case ok := <-done:
		if !ok {
			t.Fatal("disabled DPI returned a non-nil result")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("disabled classification waited for the DPI mutex")
	}
}
