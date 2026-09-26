package udp

import (
	"net"
	"testing"

	"github.com/gogo/protobuf/proto"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"

	decoderconfig "github.com/dreadl0ck/netcap/internal/decoder/config"
	"github.com/dreadl0ck/netcap/internal/decoder/stream/bacnetip"
	"github.com/dreadl0ck/netcap/internal/netio"
	"github.com/dreadl0ck/netcap/types"
)

type bacnetCaptureWriter struct {
	netio.AuditRecordWriter
	records []*types.BACnetIP
}

func (w *bacnetCaptureWriter) Write(msg proto.Message) error {
	w.records = append(w.records, proto.Clone(msg).(*types.BACnetIP))
	return nil
}

func TestUDPStreamSelectsLaterCompleteDatagram(t *testing.T) {
	previousConfig, previousWriter := decoderconfig.Instance, bacnetip.Decoder.Writer
	t.Cleanup(func() {
		decoderconfig.Instance, bacnetip.Decoder.Writer = previousConfig, previousWriter
	})
	decoderconfig.Instance = decoderconfig.DefaultConfig.Clone()
	w := &bacnetCaptureWriter{}
	bacnetip.Decoder.Writer = w
	pool := newUDPStreamPool()
	for _, data := range [][]byte{
		{0},
		{0x81, 0x0a, 0, 12, 1, 0, 0, 0, 0, 0, 0, 0},
	} {
		packet := serializedIPv4UDPPayload(t, "192.0.2.10", "198.51.100.20", 53000, 47808, data)
		pool.HandleUDP(packet, packet.Layer(layers.LayerTypeUDP))
	}
	if len(pool.streams) != 1 {
		t.Fatalf("%d UDP conversations, want one", len(pool.streams))
	}
	for _, u := range pool.streams {
		u.decode()
	}
	if len(w.records) != 1 || w.records[0].SrcIP != "192.0.2.10" {
		t.Fatalf("later BACnet datagram did not produce a correctly attributed record: %+v", w.records)
	}
}

func TestUDPConversationKey(t *testing.T) {
	forward := serializedIPv4UDPPacket(t, "192.0.2.10", "198.51.100.20", 53000, 53)
	reverse := serializedIPv4UDPPacket(t, "198.51.100.20", "192.0.2.10", 53, 53000)
	otherHosts := serializedIPv4UDPPacket(t, "192.0.2.11", "198.51.100.20", 53000, 53)

	if got, want := udpConversationKey(reverse), udpConversationKey(forward); got != want {
		t.Fatalf("reverse direction key = %d, want %d", got, want)
	}
	if got, other := udpConversationKey(forward), udpConversationKey(otherHosts); got == other {
		t.Fatalf("different host pairs with the same ports produced key %d", got)
	}
}

func serializedIPv4UDPPacket(t *testing.T, srcIP, dstIP string, srcPort, dstPort layers.UDPPort) gopacket.Packet {
	return serializedIPv4UDPPayload(t, srcIP, dstIP, srcPort, dstPort, []byte("payload"))
}

func serializedIPv4UDPPayload(t *testing.T, srcIP, dstIP string, srcPort, dstPort layers.UDPPort, payload []byte) gopacket.Packet {
	t.Helper()

	ip := &layers.IPv4{
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolUDP,
		SrcIP:    net.ParseIP(srcIP),
		DstIP:    net.ParseIP(dstIP),
	}
	udp := &layers.UDP{SrcPort: srcPort, DstPort: dstPort}
	if err := udp.SetNetworkLayerForChecksum(ip); err != nil {
		t.Fatalf("set UDP checksum network layer: %v", err)
	}

	buf := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, ip, udp, gopacket.Payload(payload)); err != nil {
		t.Fatalf("serialize IPv4/UDP packet: %v", err)
	}

	return gopacket.NewPacket(buf.Bytes(), layers.LayerTypeIPv4, gopacket.Default)
}
