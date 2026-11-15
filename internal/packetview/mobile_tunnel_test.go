package packetview

import (
	"bytes"
	"encoding/binary"
	"net"
	"testing"

	"github.com/dreadl0ck/netcap/internal/packetview/testutil"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

func TestMobileTunnelsUseInnerEndpoints(t *testing.T) {
	for _, kind := range []string{"gtpu", "gtpu-extensions", "teredo", "teredo-headers", "l2tpv2", "l2tpv2-options"} {
		t.Run(kind, func(t *testing.T) {
			v6 := kind == "teredo" || kind == "teredo-headers"
			inner := testutil.TCP(v6, false, 1, 1, "AP", "GET / HTTP/1.1\r\nHost: fixture.test\r\n\r\n")
			port := layers.UDPPort(2152)
			var payload []byte
			switch kind {
			case "gtpu", "gtpu-extensions":
				payload = []byte{0x30, 0xff, 0, 0, 0, 0, 0, 7}
				if kind == "gtpu-extensions" {
					payload[0] = 0x37
					payload = append(payload, 0, 1, 0, 0x85, 1, 0, 0, 0)
				}
				payload = append(payload, inner...)
				binary.BigEndian.PutUint16(payload[2:], uint16(len(payload)-8))
			case "teredo", "teredo-headers":
				port = 3544
				if kind == "teredo-headers" {
					payload = append(payload, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1)
					payload = append(payload, 0, 0, 0, 0, 0, 0, 0, 0)
				}
				payload = append(payload, inner...)
			case "l2tpv2", "l2tpv2-options":
				port = 1701
				payload = []byte{0, 2, 0, 1, 0, 7}
				if kind == "l2tpv2-options" {
					payload = []byte{0x4a, 2, 0, 0, 0, 1, 0, 7, 0, 1, 0, 2, 0, 2, 0, 0}
				}
				payload = append(payload, 0xff, 3, 0, 0x21)
				payload = append(payload, inner...)
				if kind == "l2tpv2-options" {
					binary.BigEndian.PutUint16(payload[2:], uint16(len(payload)))
				}
			}
			for _, reversePorts := range []bool{false, true} {
				src, dst := layers.UDPPort(53000), port
				if reversePorts {
					src, dst = dst, src
				}
				outer := testutil.Serialize(&layers.IPv4{Version: 4, TTL: 64, Protocol: layers.IPProtocolUDP, SrcIP: net.IPv4(192, 0, 2, 1), DstIP: net.IPv4(192, 0, 2, 2)}, &layers.UDP{SrcPort: src, DstPort: dst}, gopacket.Payload(payload))
				original := testutil.Packet(testutil.Ethernet(outer), 0, 1)
				result := New(DefaultLimits()).Process(original, 1)
				if result.Packet == nil {
					t.Fatalf("not decapsulated: %+v", result)
				}
				want := "10.0.0.1"
				if v6 {
					want = "2001:db8::1"
				}
				if result.Packet.NetworkLayer().NetworkFlow().Src().String() != want || result.Packet.TransportLayer().TransportFlow().Dst().String() != "80" {
					t.Fatal("outer and inner layers mixed", result.Packet)
				}
				if !bytes.Equal(result.Packet.TransportLayer().LayerPayload(), inner[len(inner)-len(result.Packet.TransportLayer().LayerPayload()):]) {
					t.Fatal("inner payload changed")
				}
				c := FromCapture(result.Packet.Metadata().CaptureInfo)
				if c == nil || len(c.Tunnels) != 1 || c.Tunnels[0].SrcIP != "192.0.2.1" {
					t.Fatal("outer provenance lost", c)
				}
			}
			for n := 0; n < len(payload); n++ {
				truncated := payload[:n]
				switch port {
				case 2152:
					_, _, _ = gtpuPayload(truncated)
				case 3544:
					_, _ = teredoPayload(truncated)
				case 1701:
					_, _, _, _ = l2tpPayload(truncated)
				}
			}
		})
	}
}
