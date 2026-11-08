package packet

import (
	"encoding/binary"
	"net"
	"testing"

	streamutils "github.com/dreadl0ck/netcap/internal/decoder/stream/utils"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

// Fixed expected IDs are from corelight/community-id-spec baseline_deflt.json.
func TestCommunityIDSpecificationVectors(t *testing.T) {
	cases := []struct {
		src, dst string
		sp, dp   uint16
		protocol byte
		want     string
	}{
		{"128.232.110.120", "66.35.250.204", 34855, 80, 6, "1:LQU9qZlK+B5F3KDmev6m5PMibrg="},
		{"192.168.1.52", "8.8.8.8", 54585, 53, 17, "1:d/FP5EW3wiY1vCndhwleRRKHowQ="},
		{"192.168.170.8", "192.168.170.56", 7, 7, 132, "1:MP2EtRCAUIZvTw6MxJHLV7N7JDs="},
		{"2001:470:e5bf:dead:4957:2174:e82c:4887", "2607:f8b0:400c:c03::1a", 63943, 25, 6, "1:/qFaeAR+gFe1KYjMzVDsMv+wgU4="},
		// Independently encoded SHA-1 tuple using Python's ipaddress/struct/hashlib.
		{"2001:db8::1", "2001:db8::2", 1234, 53, 17, "1:kG/geD1kQbAyqHMRDAboT+XscMg="},
	}
	for _, c := range cases {
		for _, reverse := range []bool{false, true} {
			src, dst, sp, dp := c.src, c.dst, c.sp, c.dp
			if reverse {
				src, dst, sp, dp = dst, src, dp, sp
			}
			transport := make([]byte, 20)
			binary.BigEndian.PutUint16(transport, sp)
			binary.BigEndian.PutUint16(transport[2:], dp)
			switch c.protocol {
			case 6:
				transport[12] = 5 << 4
			case 17:
				transport = transport[:8]
				binary.BigEndian.PutUint16(transport[4:], 8)
			case 132:
				transport = transport[:12]
			}
			ip := net.ParseIP(src)
			if ip.To4() != nil {
				raw := make([]byte, 20+len(transport))
				raw[0] = 0x45
				raw[8] = 64
				raw[9] = c.protocol
				binary.BigEndian.PutUint16(raw[2:], uint16(len(raw)))
				copy(raw[12:], ip.To4())
				copy(raw[16:], net.ParseIP(dst).To4())
				copy(raw[20:], transport)
				p := gopacket.NewPacket(raw, layers.LayerTypeIPv4, gopacket.Default)
				if got := CalcCommunityID(p); got != c.want {
					t.Fatalf("IPv4 %d %v: %s != %s", c.protocol, reverse, got, c.want)
				}
			} else {
				for _, extensions := range []int{0, 1, 2} {
					raw := make([]byte, 40+8*extensions+len(transport))
					raw[0] = 0x60
					raw[7] = 64
					copy(raw[8:], ip.To16())
					copy(raw[24:], net.ParseIP(dst).To16())
					binary.BigEndian.PutUint16(raw[4:], uint16(len(raw)-40))
					raw[6] = c.protocol
					if extensions > 0 {
						raw[6] = 0
						raw[40] = c.protocol
						if extensions == 2 {
							raw[40] = 60
							raw[48] = c.protocol
						}
					}
					copy(raw[40+8*extensions:], transport)
					p := gopacket.NewPacket(raw, layers.LayerTypeIPv6, gopacket.Default)
					if got := CalcCommunityID(p); got != c.want {
						t.Fatalf("IPv6 ext=%d reverse=%v: %s != %s", extensions, reverse, got, c.want)
					}
					streamID := streamutils.CalcCommunityIDTCP(src, dst, sp, dp)
					if c.protocol == 17 {
						streamID = streamutils.CalcCommunityIDUDP(src, dst, sp, dp)
					}
					if streamID != c.want {
						t.Fatal("stream and packet tuple disagree")
					}
				}
			}
		}
	}
}

func TestCommunityIDICMPSpecificationPairs(t *testing.T) {
	for _, reverse := range []bool{false, true} {
		src, dst, typ := "192.168.0.89", "192.168.0.1", byte(8)
		if reverse {
			src, dst, typ = dst, src, 0
		}
		raw := make([]byte, 28)
		raw[0] = 0x45
		raw[9] = 1
		binary.BigEndian.PutUint16(raw[2:], 28)
		copy(raw[12:], net.ParseIP(src).To4())
		copy(raw[16:], net.ParseIP(dst).To4())
		raw[20] = typ
		if got := CalcCommunityID(gopacket.NewPacket(raw, layers.LayerTypeIPv4, gopacket.Default)); got != "1:X0snYXpgwiv9TZtqg64sgzUn6Dk=" {
			t.Fatal("ICMPv4 pair changed", got)
		}
		a, b, kind := "3ffe:507:0:1:200:86ff:fe05:80da", "3ffe:501:0:1001::2", byte(128)
		if reverse {
			a, b, kind = b, a, 129
		}
		wire := make([]byte, 48)
		wire[0] = 0x60
		wire[6] = 58
		wire[40] = kind
		binary.BigEndian.PutUint16(wire[4:], 8)
		copy(wire[8:], net.ParseIP(a).To16())
		copy(wire[24:], net.ParseIP(b).To16())
		if got := CalcCommunityID(gopacket.NewPacket(wire, layers.LayerTypeIPv6, gopacket.Default)); got != "1:+TW+HtLHvV1xnGhV1lv7XoJrqQg=" {
			t.Fatal("ICMPv6 pair changed", got)
		}
	}
}

func TestCommunityIDUnobservedTransport(t *testing.T) {
	for _, proto := range []byte{6, 17, 132, 0, 44, 60} {
		raw := make([]byte, 40)
		raw[0] = 0x60
		raw[6] = proto
		copy(raw[8:], net.ParseIP("2001:db8::1").To16())
		copy(raw[24:], net.ParseIP("2001:db8::2").To16())
		p := gopacket.NewPacket(raw, layers.LayerTypeIPv6, gopacket.Default)
		if got := CalcCommunityID(p); got != "" {
			t.Fatalf("unseen ports invented: protocol %d = %s", proto, got)
		}
	}
	fragment := make([]byte, 28)
	fragment[0] = 0x45
	fragment[9] = 1
	fragment[6] = 0x20
	binary.BigEndian.PutUint16(fragment[2:], 28)
	copy(fragment[12:], net.ParseIP("192.0.2.1").To4())
	copy(fragment[16:], net.ParseIP("192.0.2.2").To4())
	if got := CalcCommunityID(gopacket.NewPacket(fragment, layers.LayerTypeIPv4, gopacket.Default)); got != "" {
		t.Fatal("fragmented ICMP assigned an invented generic tuple", got)
	}
	tunnel := make([]byte, 80)
	tunnel[0] = 0x45
	tunnel[9] = 41
	binary.BigEndian.PutUint16(tunnel[2:], 80)
	copy(tunnel[12:], net.ParseIP("192.0.2.1").To4())
	copy(tunnel[16:], net.ParseIP("192.0.2.2").To4())
	tunnel[20] = 0x60
	tunnel[26] = 6
	binary.BigEndian.PutUint16(tunnel[24:], 20)
	copy(tunnel[28:], net.ParseIP("2001:db8::1").To16())
	copy(tunnel[44:], net.ParseIP("2001:db8::2").To16())
	binary.BigEndian.PutUint16(tunnel[60:], 1234)
	binary.BigEndian.PutUint16(tunnel[62:], 80)
	tunnel[72] = 5 << 4
	if got := CalcCommunityID(gopacket.NewPacket(tunnel, layers.LayerTypeIPv4, gopacket.Default)); got != "" {
		t.Fatal("outer IP and inner ports combined", got)
	}
}
