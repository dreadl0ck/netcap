package udp

import (
	"testing"

	"github.com/dreadl0ck/netcap/internal/decoder/core"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

func rolePacket(t *testing.T, reverse bool, payload []byte) gopacket.Packet {
	t.Helper()
	src, dst := []byte{192, 0, 2, 1}, []byte{198, 51, 100, 1}
	sp, dp := layers.UDPPort(53000), layers.UDPPort(137)
	if reverse {
		src, dst = dst, src
		sp, dp = dp, sp
	}
	b := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(b, gopacket.SerializeOptions{FixLengths: true}, &layers.IPv4{Version: 4, TTL: 64, SrcIP: src, DstIP: dst, Protocol: layers.IPProtocolUDP}, &layers.UDP{SrcPort: sp, DstPort: dp}, gopacket.Payload(payload)); err != nil {
		t.Fatal(err)
	}
	return gopacket.NewPacket(b.Bytes(), layers.LayerTypeIPv4, gopacket.Default)
}

func TestReplyFirstUDPHasServerOnWellKnownPort(t *testing.T) {
	p := rolePacket(t, true, []byte{0, 1, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0})
	network, transport := clientFlows(core.DataFragments{&core.StreamData{RawData: p.TransportLayer().LayerPayload(), Net: p.NetworkLayer().NetworkFlow(), Trans: p.TransportLayer().TransportFlow()}})
	if network.Dst().String() != "198.51.100.1" || transport.Dst().String() != "137" {
		t.Fatal("ephemeral client port became service", network, transport)
	}
}

func TestICMPRefusalMarksOnlyObservedUDPAttempt(t *testing.T) {
	pool := newUDPStreamPool()
	probe := rolePacket(t, false, []byte("probe"))
	pool.HandleUDP(probe, probe.TransportLayer())
	quote := append([]byte(nil), probe.Data()[:28]...)
	b := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(b, gopacket.SerializeOptions{FixLengths: true}, &layers.IPv4{Version: 4, TTL: 64, SrcIP: []byte{198, 51, 100, 1}, DstIP: []byte{192, 0, 2, 1}, Protocol: layers.IPProtocolICMPv4}, &layers.ICMPv4{TypeCode: layers.CreateICMPv4TypeCode(3, 3)}, gopacket.Payload(quote)); err != nil {
		t.Fatal(err)
	}
	pool.ObserveICMPRefusal(gopacket.NewPacket(b.Bytes(), layers.LayerTypeIPv4, gopacket.Default))
	if len(pool.streams) != 1 || !pool.streams[udpConversationKey(probe)].refused {
		t.Fatal("UDP refusal not attributed")
	}
	empty := newUDPStreamPool()
	empty.ObserveICMPRefusal(gopacket.NewPacket(b.Bytes(), layers.LayerTypeIPv4, gopacket.Default))
	if len(empty.streams) != 0 {
		t.Fatal("ICMP quote created service state")
	}
	empty.HandleUDP(probe, probe.TransportLayer())
	if len(empty.streams) != 1 || !empty.streams[udpConversationKey(probe)].refused {
		t.Fatal("worker scheduling before UDP observation lost refusal")
	}
}
