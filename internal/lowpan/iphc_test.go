package lowpan

import (
	"encoding/binary"
	"net/netip"
	"testing"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

func TestIPHCUDPPortModesAndChecksums(t *testing.T) {
	src := netip.MustParseAddr("fe80::ff:fe00:2").As16()
	dst := netip.MustParseAddr("fe80::ff:fe00:1").As16()
	for mode, ports := range [][]byte{{0x9c, 0x40, 0, 80}, {0x9c, 0x40, 0x12}, {0x34, 0, 80}, {0x12}} {
		wantSrc := []uint16{40000, 40000, 0xf034, 0xf0b1}[mode]
		wantDst := []uint16{80, 0xf012, 80, 0xf0b2}[mode]
		udp := []byte{0, 0, 0, 0, 0, 11, 0, 0, 'a', 'b', 'c'}
		binary.BigEndian.PutUint16(udp, wantSrc)
		binary.BigEndian.PutUint16(udp[2:], wantDst)
		checksum := Checksum(src, dst, 17, udp)
		wire := append([]byte{0x7e, 0x33, 0xf0 | byte(mode)}, ports...)
		wire = binary.BigEndian.AppendUint16(wire, checksum)
		wire = append(wire, 'a', 'b', 'c')
		result, err := Decode(wire, Options{Source: 2, Destination: 1})
		if err != nil || len(result.Packet) != 51 || binary.BigEndian.Uint16(result.Packet[40:]) != wantSrc || binary.BigEndian.Uint16(result.Packet[42:]) != wantDst || Checksum(src, dst, 17, result.Packet[40:]) != 0 {
			t.Fatal(mode, result, err)
		}
		packet := gopacket.NewPacket(result.Packet, layers.LayerTypeIPv6, gopacket.Default)
		if packet.ErrorLayer() != nil || packet.Layer(layers.LayerTypeUDP) == nil {
			t.Fatal(packet)
		}
	}
	if _, err := Decode([]byte{0x7e, 0x33, 0xf7, 0x12, 'a'}, Options{Source: 2, Destination: 1}); err == nil {
		t.Fatal("elided checksum trusted without additional integrity")
	}
	result, err := Decode([]byte{0x7e, 0x33, 0xf7, 0x12, 'a'}, Options{Source: 2, Destination: 1, IntegrityVerified: true})
	if err != nil || Checksum(src, dst, 17, result.Packet[40:]) != 0 {
		t.Fatal(result, err)
	}
}

func TestIPHCContextsMulticastAndExtensions(t *testing.T) {
	if _, err := Decode([]byte{0x7a, 0x77, 59}, Options{Source: 2, Destination: 1}); err == nil {
		t.Fatal("missing context guessed")
	}
	result, err := Decode([]byte{0x7a, 0x77, 59}, Options{Source: 2, Destination: 1, Contexts: map[uint8]netip.Prefix{0: netip.MustParsePrefix("aaaa::/64")}})
	if err != nil || netip.AddrFrom16([16]byte(result.Packet[8:24])).String() != "aaaa::ff:fe00:2" {
		t.Fatal(result, err)
	}
	result, err = Decode([]byte{0x7a, 0x3b, 59, 1}, Options{Source: 2, Destination: 255})
	if err != nil || netip.AddrFrom16([16]byte(result.Packet[24:40])).String() != "ff02::1" {
		t.Fatal(result, err)
	}
	result, err = Decode([]byte{0x7e, 0x33, 0xe0, 59, 0}, Options{Source: 2, Destination: 1})
	if err != nil || len(result.Packet) != 48 || result.Packet[6] != 0 || result.Packet[40] != 59 || result.Packet[41] != 0 || result.Packet[42] != 1 || result.Packet[43] != 4 {
		t.Fatal(result, err)
	}
	for n := 0; n < 3; n++ {
		if _, err := Decode([]byte{0x7e, 0x33, 0xf0}[:n], Options{}); err == nil {
			t.Fatal("short IPHC accepted")
		}
	}
}

func FuzzIPHCFieldBounds(f *testing.F) {
	f.Add([]byte{0x7a, 0x33, 59})
	f.Add([]byte{0x7e, 0x33, 0xe0, 59, 0})
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 65536 {
			t.Skip()
		}
		result, err := Decode(data, Options{Source: 2, Destination: 1})
		if err == nil && (len(result.Packet) < 40 || len(result.Packet) > 65575 || int(binary.BigEndian.Uint16(result.Packet[4:])) != len(result.Packet)-40) {
			t.Fatal("expanded IPHC length escaped IPv6")
		}
	})
}
