// Package testutil builds deterministic, fictional packet-pipeline fixtures.
package testutil

import (
	"encoding/binary"
	"net"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

func Serialize(parts ...gopacket.SerializableLayer) []byte {
	b := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(b, gopacket.SerializeOptions{FixLengths: true}, parts...); err != nil {
		panic(err)
	}
	return b.Bytes()
}

func IP(v6, reverse bool, protocol layers.IPProtocol, payload []byte) []byte {
	a, b := net.ParseIP("10.0.0.1"), net.ParseIP("10.0.0.2")
	if v6 {
		a, b = net.ParseIP("2001:db8::1"), net.ParseIP("2001:db8::2")
	}
	if reverse {
		a, b = b, a
	}
	if v6 {
		return Serialize(&layers.IPv6{Version: 6, HopLimit: 64, SrcIP: a, DstIP: b, NextHeader: protocol}, gopacket.Payload(payload))
	}
	return Serialize(&layers.IPv4{Version: 4, TTL: 64, SrcIP: a, DstIP: b, Protocol: protocol}, gopacket.Payload(payload))
}

func TCP(v6, reverse bool, seq, ack uint32, flags string, payload string) []byte {
	a, b := layers.TCPPort(40000), layers.TCPPort(80)
	if reverse {
		a, b = b, a
	}
	t := &layers.TCP{SrcPort: a, DstPort: b, Seq: seq, Ack: ack, Window: 65535}
	for _, f := range flags {
		switch f {
		case 'S':
			t.SYN = true
		case 'A':
			t.ACK = true
		case 'F':
			t.FIN = true
		case 'R':
			t.RST = true
		case 'P':
			t.PSH = true
		}
	}
	return IP(v6, reverse, layers.IPProtocolTCP, Serialize(t, gopacket.Payload(payload)))
}

func Ethernet(ip []byte) []byte {
	kind := layers.EthernetTypeIPv4
	if ip[0]>>4 == 6 {
		kind = layers.EthernetTypeIPv6
	}
	return Serialize(&layers.Ethernet{SrcMAC: net.HardwareAddr{2, 0, 0, 0, 0, 1}, DstMAC: net.HardwareAddr{2, 0, 0, 0, 0, 2}, EthernetType: kind}, gopacket.Payload(ip))
}

// Tunnel always uses the same outer direction, as mirrored ERSPAN/VXLAN do.
func Tunnel(kind string, id uint32, inner []byte) []byte {
	var payload []byte
	proto := layers.IPProtocolGRE
	iptype := uint16(0x0800)
	if inner[0]>>4 == 6 {
		iptype = 0x86dd
	}
	switch kind {
	case "gre":
		payload = Serialize(&layers.GRE{KeyPresent: true, Key: id, Protocol: layers.EthernetType(iptype)}, gopacket.Payload(inner))
	case "gre-ethernet":
		payload = Serialize(&layers.GRE{Protocol: 0x6558}, gopacket.Payload(Ethernet(inner)))
	case "erspan-i":
		payload = Serialize(&layers.GRE{Protocol: 0x88be}, gopacket.Payload(Ethernet(inner)))
	case "erspan-ii":
		payload = Serialize(&layers.GRE{Protocol: 0x88be, SeqPresent: true}, &layers.ERSPANII{Version: 1, SessionID: uint16(id)}, gopacket.Payload(Ethernet(inner)))
	case "erspan-iii":
		e := []byte{0x20, 0, byte(id >> 8), byte(id), 0, 0, 0, 1, 0, 0, 0, 1, 1, 2, 3, 4, 5, 6, 7, 8}
		payload = Serialize(&layers.GRE{Protocol: 0x22eb, SeqPresent: true}, gopacket.Payload(append(e, Ethernet(inner)...)))
	case "vxlan", "geneve", "geneve-gre":
		proto = layers.IPProtocolUDP
		port := layers.UDPPort(4789)
		header := []byte{8, 0, 0, 0, byte(id >> 16), byte(id >> 8), byte(id), 0}
		body := Ethernet(inner)
		if kind != "vxlan" {
			port = 6081
			header[0], header[2], header[3] = 0, 0x65, 0x58
			if kind == "geneve-gre" {
				header[2], header[3] = 0x08, 0x00
				body = Tunnel("gre", 23, inner)
			}
		}
		payload = Serialize(&layers.UDP{SrcPort: 53000, DstPort: port}, gopacket.Payload(append(header, body...)))
	default:
		panic(kind)
	}
	return Serialize(&layers.IPv4{Version: 4, TTL: 64, Protocol: proto, SrcIP: net.IPv4(192, 0, 2, 1), DstIP: net.IPv4(192, 0, 2, 2)}, gopacket.Payload(payload))
}

// Fragment returns an IP fragment from an unfragmented datagram. start/end are
// offsets in the IP payload, so tests can deliberately create overlaps and holes.
func Fragment(ip []byte, id uint32, start, end int, more bool) []byte {
	h := int(ip[0]&15) * 4
	v6 := ip[0]>>4 == 6
	if v6 {
		h = 40
	}
	out := append([]byte(nil), ip[:h]...)
	if v6 {
		f := []byte{ip[6], 0, 0, 0, 0, 0, 0, 0}
		binary.BigEndian.PutUint16(f[2:4], uint16(start))
		if more {
			f[3] |= 1
		}
		binary.BigEndian.PutUint32(f[4:], id)
		out[6] = 44
		out = append(out, f...)
	} else {
		binary.BigEndian.PutUint16(out[4:6], uint16(id))
		binary.BigEndian.PutUint16(out[6:8], uint16(start/8))
		if more {
			out[6] |= 0x20
		}
	}
	out = append(out, ip[h+start:h+end]...)
	if v6 {
		binary.BigEndian.PutUint16(out[4:6], uint16(len(out)-40))
	} else {
		binary.BigEndian.PutUint16(out[2:4], uint16(len(out)))
		out[10], out[11] = 0, 0
		binary.BigEndian.PutUint16(out[10:12], gopacket.FoldChecksum(gopacket.ComputeChecksum(out[:h], 0)))
	}
	return out
}

func Packet(raw []byte, index int, ordinal uint64) gopacket.Packet {
	p := gopacket.NewPacket(raw, layers.LayerTypeEthernet, gopacket.Default)
	p.Metadata().CaptureInfo = gopacket.CaptureInfo{Timestamp: time.Unix(1700000000, int64(ordinal)*1000000), CaptureLength: len(raw), Length: len(raw), InterfaceIndex: index}
	return p
}
