package collector

import (
	"io"
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"

	"github.com/dreadl0ck/netcap/internal/behavior"
	"github.com/dreadl0ck/netcap/internal/netio"
	"github.com/dreadl0ck/netcap/internal/rules"
	"github.com/dreadl0ck/netcap/types"
)

func TestBehaviorDetectsBeforeWorkerAdmission(t *testing.T) {
	dir := t.TempDir()
	sink, err := rules.NewFileAlertWriter(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer sink.Close()
	engine, err := behavior.Open(behavior.Config{Path: filepath.Join(dir, "Behavior.json"), MinLearning: time.Second, MinSamples: 2}, sink)
	if err != nil {
		t.Fatal(err)
	}
	defer engine.Close()
	scope := behavior.Scope{Sensor: "fixture", Interface: "pcap"}
	fact := behavior.Fact{Scope: scope, Kind: "service", SrcIP: "192.0.2.1", DstIP: "192.0.2.2", Protocol: "tcp", Port: 443}
	start := time.Unix(1700000000, 0)
	if err := engine.Observe(start, fact); err != nil {
		t.Fatal(err)
	}
	if err := engine.Observe(start.Add(time.Second), fact); err != nil {
		t.Fatal(err)
	}
	if err := engine.Change("approve", nil, "approved fixture"); err != nil {
		t.Fatal(err)
	}
	ip := &layers.IPv4{Version: 4, TTL: 64, SrcIP: net.ParseIP(fact.SrcIP), DstIP: net.ParseIP(fact.DstIP), Protocol: layers.IPProtocolTCP}
	tcp := &layers.TCP{SrcPort: 55000, DstPort: 22, SYN: true}
	_ = tcp.SetNetworkLayerForChecksum(ip)
	buffer := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buffer, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, ip, tcp); err != nil {
		t.Fatal(err)
	}
	packet := gopacket.NewPacket(buffer.Bytes(), layers.LayerTypeIPv4, gopacket.Default)
	packet.Metadata().CaptureInfo.Timestamp = start.Add(2 * time.Second)
	c := &Collector{acceptingPackets: true, numWorkers: 1, workers: []chan gopacket.Packet{make(chan gopacket.Packet, 1)}}
	c.SetBehaviorEngine(engine, scope)
	if !c.handlePacket(packet) || c.GetBehaviorError() != nil {
		t.Fatalf("admission failed: %v", c.GetBehaviorError())
	}
	// No worker has consumed the SYN and the connection has never closed.
	reader, err := netio.Open(filepath.Join(dir, "Alert.ncap.gz"), 4096)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	if _, err := reader.ReadHeader(); err != nil {
		t.Fatal(err)
	}
	count := 0
	for {
		var alert types.Alert
		if err := reader.Next(&alert); err == io.EOF {
			break
		} else if err != nil {
			t.Fatal(err)
		}
		count++
	}
	if count != 2 {
		t.Fatalf("expected immediate edge and service alerts, got %d", count)
	}
	<-c.workers[0]
	c.wg.Done()
}
