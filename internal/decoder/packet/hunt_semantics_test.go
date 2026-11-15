package packet

import (
	"encoding/binary"
	"net"
	"testing"

	"github.com/dreadl0ck/netcap/types"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

func TestPortlessCommunityIDVectors(t *testing.T) {
	// Independent ipaddress/struct/hashlib vectors; RSVP also matches the report's tshark oracle.
	for _, tc := range []struct {
		src, dst string
		protocol byte
		want     string
	}{
		{"10.1.12.1", "10.1.12.2", 46, "1:KHlLkgoJW7ifUTyTSgyVfkFHzKw="},
		{"192.0.2.1", "192.0.2.2", 99, "1:qo9ZnHKd7rxCPSh5JqG7GenNLoI="},
		{"2001:db8::1", "2001:db8::2", 99, "1:nggMJC+W+o0+x2T01T+dM3p2Q0I="},
	} {
		for _, reverse := range []bool{false, true} {
			src, dst := net.ParseIP(tc.src), net.ParseIP(tc.dst)
			if reverse {
				src, dst = dst, src
			}
			wire := make([]byte, 32)
			decoder := layers.LayerTypeIPv4
			if src.To4() != nil {
				wire[0], wire[8], wire[9] = 0x45, 64, tc.protocol
				binary.BigEndian.PutUint16(wire[2:], uint16(len(wire)))
				copy(wire[12:], src.To4())
				copy(wire[16:], dst.To4())
			} else {
				wire = make([]byte, 52)
				wire[0], wire[6], wire[7] = 0x60, tc.protocol, 64
				binary.BigEndian.PutUint16(wire[4:], 12)
				copy(wire[8:], src.To16())
				copy(wire[24:], dst.To16())
				decoder = layers.LayerTypeIPv6
			}
			if got := CalcCommunityID(gopacket.NewPacket(wire, decoder, gopacket.Default)); got != tc.want {
				t.Fatalf("proto=%d reverse=%t got=%s want=%s", tc.protocol, reverse, got, tc.want)
			}
		}
	}
}

func TestIGMPEveryWireVersion(t *testing.T) {
	for _, tc := range []struct {
		kind, response byte
		version        int32
	}{{0x11, 0, 1}, {0x12, 0, 1}, {0x11, 10, 2}, {0x16, 0, 2}, {0x17, 0, 2}} {
		wire := []byte{tc.kind, tc.response, 0, 0, 224, 0, 0, 1}
		p := gopacket.NewPacket(wire, layers.LayerTypeIGMP, gopacket.Default)
		if err := p.ErrorLayer(); err != nil {
			t.Fatal(err)
		}
		message := igmpDecoder.Handler(p.Layer(layers.LayerTypeIGMP), 123)
		r, ok := message.(*types.IGMP)
		if !ok || r.Version != tc.version || r.Type != int32(tc.kind) || r.Timestamp != 123 || r.GroupAddress != "224.0.0.1" {
			t.Fatalf("%x: %v", tc.kind, message)
		}
	}
}
