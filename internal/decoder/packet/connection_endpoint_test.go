package packet

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"testing"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"
)

func TestConnectionTruncatedUDPEndpoint(t *testing.T) {
	connectionConcurrencySetup(t)
	// Packet 1149 of bf63bf6245d691d0ea9c96fc97e9b6454704dca74545b37f1e99875ed2cdeabe.
	data, err := hex.DecodeString("ffffffffffff01010101010108004500003cc59e4000ff11d7e0d01502b80a0101630b3cd2c1fd7ea1")
	if err != nil {
		t.Fatal(err)
	}
	for i := range 3 {
		wire := append([]byte(nil), data...)
		if i == 2 {
			copy(wire[:6], data[6:12])
			copy(wire[6:12], data[:6])
			copy(wire[26:30], data[30:34])
			copy(wire[30:34], data[26:30])
		}
		p := gopacket.NewPacket(wire, layers.LayerTypeEthernet, gopacket.Default)
		p.Metadata().CaptureInfo = gopacket.CaptureInfo{Timestamp: time.Unix(1700000000-int64(i), 0), CaptureLength: len(wire), Length: len(wire)}
		if p.TransportLayer() == nil || p.ErrorLayer() == nil || len(p.TransportLayer().TransportFlow().Src().Raw()) != 0 {
			t.Fatal("fixture no longer exercises the incomplete UDP endpoint")
		}
		handlePacket(p)
	}
	w := &connectionTestWriter{}
	connectionDecoder.FlushState(&Decoder{Writer: w})
	if len(w.records) != 1 {
		t.Fatalf("retained %d connections, want 1", len(w.records))
	}
	c := w.records[0]
	if c.SrcPort != "" || c.DstPort != "" || c.TransportProto != "UDP" || c.NumPackets64 != 3 || c.TotalSize64 != 3*int64(len(data)) || c.PacketsClientToServer != 1 || c.PacketsServerToClient != 2 {
		t.Fatalf("truncated flow lost accounting or direction: %v", c)
	}
	if path := os.Getenv("NETCAP_ENDPOINT_REGRESSION_PCAP"); path != "" {
		t.Run("full-capture", func(t *testing.T) { qualifyConnectionEndpointCapture(t, path) })
	}
}

func TestConnectionPortWidths(t *testing.T) {
	for _, endpointType := range []gopacket.EndpointType{layers.EndpointTCPPort, layers.EndpointUDPPort, layers.EndpointSCTPPort, layers.EndpointUDPLitePort} {
		for _, raw := range [][]byte{nil, {1}, {1, 2, 3}} {
			if got := connectionPort(gopacket.NewEndpoint(endpointType, raw)); got != "" {
				t.Fatalf("malformed endpoint %d/%x became %q", endpointType, raw, got)
			}
		}
		if got := connectionPort(gopacket.NewEndpoint(endpointType, []byte{0, 0})); got != "0" {
			t.Fatalf("valid zero port became %q", got)
		}
	}
	if got := connectionPort(layers.NewRUDPPortEndpoint(7)); got != "7" {
		t.Fatalf("RUDP port became %q", got)
	}
}

func TestConnectionUnsupportedIPProtocolsRetained(t *testing.T) {
	connectionConcurrencySetup(t)
	for _, protocol := range []layers.IPProtocol{253, 254} {
		for i := range 2 {
			base := connectionBenchmarkPackets(t, 1)[0]
			ip := base.NetworkLayer().(*layers.IPv4)
			ip.Protocol = protocol
			if i == 1 {
				ip.SrcIP, ip.DstIP = ip.DstIP, ip.SrcIP
			}
			buf := gopacket.NewSerializeBuffer()
			if err := gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, base.LinkLayer().(*layers.Ethernet), ip, gopacket.Payload("unsupported transport")); err != nil {
				t.Fatal(err)
			}
			p := gopacket.NewPacket(buf.Bytes(), layers.LayerTypeEthernet, gopacket.Default)
			p.Metadata().CaptureInfo = gopacket.CaptureInfo{Timestamp: time.Unix(1700000000+int64(i), 0), Length: len(buf.Bytes()), CaptureLength: len(buf.Bytes())}
			if p.TransportLayer() != nil {
				t.Fatal("fixture unexpectedly decoded transport")
			}
			handlePacket(p)
		}
	}
	if len(conns.Items) != 2 {
		t.Fatalf("unsupported protocols merged or dropped: %d", len(conns.Items))
	}
	for _, c := range conns.Items {
		if c.NumPackets64 != 2 || c.packetsClientToServer != 1 || c.packetsServerToClient != 1 {
			t.Fatalf("unsupported transport lost accounting: %v", c.Connection)
		}
	}
}

func qualifyConnectionEndpointCapture(t *testing.T, path string) {
	connectionConcurrencySetup(t)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := sha256.Sum256(data); hex.EncodeToString(got[:]) != "bf63bf6245d691d0ea9c96fc97e9b6454704dca74545b37f1e99875ed2cdeabe" {
		t.Fatal("unexpected regression capture checksum")
	}
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	reader, err := pcapgo.NewNgReader(file, pcapgo.DefaultNgReaderOptions)
	if err != nil {
		t.Fatal(err)
	}
	var count int
	for {
		data, ci, err := reader.ReadPacketData()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		p := gopacket.NewPacket(data, reader.LinkType(), gopacket.Default)
		p.Metadata().CaptureInfo = ci
		func() {
			defer func() {
				if failure := recover(); failure != nil {
					t.Fatalf("packet %d: %v; bytes=%x; layers=%v", count, failure, data, p.Layers())
				}
			}()
			handlePacket(p)
		}()
		count++
	}
	var retained int64
	for _, conn := range conns.Items {
		retained += conn.NumPackets64
	}
	if retained != int64(count) {
		t.Fatalf("retained %d packets, read %d", retained, count)
	}
	t.Logf("retained all %d packets across %d connections", count, len(conns.Items))
}
