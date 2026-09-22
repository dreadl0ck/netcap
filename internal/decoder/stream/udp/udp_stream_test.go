package udp

import (
	"net"
	"testing"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

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
	if err := gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, ip, udp, gopacket.Payload("payload")); err != nil {
		t.Fatalf("serialize IPv4/UDP packet: %v", err)
	}

	return gopacket.NewPacket(buf.Bytes(), layers.LayerTypeIPv4, gopacket.Default)
}
