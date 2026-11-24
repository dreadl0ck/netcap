package collector

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

// The four Token Ring (DLT 6) captures in the try set failed as unsupported
// link type 6. This frame is wireshark-tftp.pcap: 802.5, LLC/SNAP, IPv4/UDP.
func TestTokenRingDecodesLLCSNAPToIP(t *testing.T) {
	frame, _ := hex.DecodeString("1040002035012b5900062917" + "93f8aaaa030000000800" +
		"45000037f93900004011a6dbc0a82c7bc0a82cd5f93900450023")
	frame = append(frame, make([]byte, 0x23-8)...)
	packet := gopacket.NewPacket(frame, linkTypeToLayerType(6), gopacket.Default)
	if packet.ErrorLayer() != nil {
		t.Fatal(packet.ErrorLayer().Error())
	}
	udp, _ := packet.Layer(layers.LayerTypeUDP).(*layers.UDP)
	if udp == nil || udp.DstPort != 69 || packet.LinkLayer() == nil {
		t.Fatalf("layers: %v", packet.Layers())
	}
	if src, dst := packet.LinkLayer().LinkFlow().Endpoints(); !bytes.Equal(src.Raw(), []byte{0x00, 0x06, 0x29, 0x17, 0x93, 0xf8}) || !bytes.Equal(dst.Raw(), []byte{0x00, 0x20, 0x35, 0x01, 0x2b, 0x59}) {
		t.Fatalf("link flow %v", packet.LinkLayer().LinkFlow())
	}

	// A source-routed frame carries a routing field before LLC; the routing
	// bit is not part of the station address.
	routed := append(append(bytes.Clone(frame[:14]), 0x06, 0x30, 0x01, 0x10, 0x02, 0x20), frame[14:]...)
	routed[8] |= 0x80
	packet = gopacket.NewPacket(routed, layerTokenRing, gopacket.Default)
	ring := packet.Layer(layerTokenRing).(*tokenRingLayer)
	if packet.ErrorLayer() != nil || packet.Layer(layers.LayerTypeUDP) == nil || len(ring.RouteInformation) != 6 || ring.SrcMAC[0] != 0 {
		t.Fatalf("routed: %v %v", packet.ErrorLayer(), packet.Layers())
	}

	// MAC management frames and unknown SAPs are payload, not errors.
	mac := bytes.Clone(frame)
	mac[1] = 0x01
	ipx := append(bytes.Clone(frame[:14]), 0xe0, 0xe0, 0x03, 0xff, 0xff)
	for name, data := range map[string][]byte{"mac": mac, "ipx": ipx} {
		if p := gopacket.NewPacket(data, layerTokenRing, gopacket.Default); p.ErrorLayer() != nil || p.ApplicationLayer() == nil {
			t.Fatalf("%s: %v %v", name, p.ErrorLayer(), p.Layers())
		}
	}

	badRoute := bytes.Clone(routed)
	badRoute[14] = 0x05
	if p := gopacket.NewPacket(badRoute, layerTokenRing, gopacket.Default); p.ErrorLayer() == nil {
		t.Fatal("odd routing field length accepted")
	}
	if p := gopacket.NewPacket(frame[:10], layerTokenRing, gopacket.Default); p.ErrorLayer() == nil {
		t.Fatal("short header accepted")
	}
}
