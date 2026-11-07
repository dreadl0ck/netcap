package packetview_test

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"testing"
	"time"

	"github.com/gogo/protobuf/jsonpb"
	"github.com/gogo/protobuf/proto"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"

	"github.com/dreadl0ck/netcap/internal/packetview"
	"github.com/dreadl0ck/netcap/internal/packetview/testutil"
	"github.com/dreadl0ck/netcap/types"
)

func process(p *packetview.Processor, raw []byte, ordinal uint64) packetview.Result {
	return p.Process(testutil.Packet(testutil.Ethernet(raw), 0, ordinal), ordinal)
}

func TestTunnelViews(t *testing.T) {
	for _, kind := range []string{"gre", "gre-ethernet", "erspan-i", "erspan-ii", "erspan-iii", "vxlan", "geneve", "geneve-gre"} {
		for _, v6 := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/v6=%v", kind, v6), func(t *testing.T) {
				p := packetview.New(packetview.Limits{})
				var scope string
				for _, reverse := range []bool{false, true} {
					raw := testutil.Ethernet(testutil.Tunnel(kind, 7, testutil.TCP(v6, reverse, 10, 0, "S", "hello")))
					original := testutil.Packet(raw, 3, 1)
					// The legacy gopacket view still points to the outer sensor.
					if original.NetworkLayer().NetworkFlow().Src().String() != "192.0.2.1" {
						t.Fatal("invalid outer fixture")
					}
					r := p.Process(original, 1)
					if r.Packet == nil || r.Status != "complete" {
						t.Fatalf("normalization: %+v", r)
					}
					n := r.Packet.NetworkLayer().NetworkFlow()
					want := "10.0.0.1"
					if reverse {
						want = "10.0.0.2"
					}
					if v6 {
						want = "2001:db8::1"
						if reverse {
							want = "2001:db8::2"
						}
					}
					if n.Src().String() != want {
						t.Fatalf("inner src %s, want %s", n.Src(), want)
					}
					if tcp, ok := r.Packet.TransportLayer().(*layers.TCP); !ok || string(tcp.Payload) != "hello" {
						t.Fatalf("transport = %v", r.Packet)
					}
					if scope != "" && packetview.Scope(r.Packet) != scope {
						t.Fatal("mirrored reverse flow changed scope")
					}
					scope = packetview.Scope(r.Packet)
					c := packetview.FromCapture(r.Packet.Metadata().CaptureInfo)
					if len(c.Tunnels) == 0 || c.Tunnels[0].SrcIP != "192.0.2.1" || c.Packets[0].Ordinal != 1 || !bytes.Equal(original.Data(), raw) {
						t.Fatal("lost outer/provenance evidence")
					}
					if len(r.Evidence) == 0 || r.Evidence[0].NetworkLayer().NetworkFlow().Src().String() != "192.0.2.1" {
						t.Fatal("lost outer header audit view")
					}
				}
			})
		}
	}
}

func TestTunnelScopeIsolation(t *testing.T) {
	p := packetview.New(packetview.Limits{})
	seen := map[string]bool{}
	for _, kind := range []string{"vxlan", "geneve", "gre", "erspan-ii", "erspan-iii", "geneve-gre"} {
		for _, id := range []uint32{1, 2} {
			for _, iface := range []int{0, 1} {
				r := p.Process(testutil.Packet(testutil.Ethernet(testutil.Tunnel(kind, id, testutil.TCP(false, false, 1, 0, "S", ""))), iface, 1), 1)
				if r.Packet == nil {
					t.Fatal(r.Status)
				}
				s := packetview.Scope(r.Packet)
				if seen[s] {
					t.Fatal("merged tunnel scope", s)
				}
				seen[s] = true
			}
		}
	}
}

func TestIPv6OuterAndVLANScope(t *testing.T) {
	for _, kind := range []string{"gre", "vxlan", "geneve", "geneve-gre"} {
		outer := testutil.Tunnel(kind, 9, testutil.TCP(false, false, 1, 0, "S", "outer IPv6"))
		outer = testutil.IP(true, false, layers.IPProtocol(outer[9]), outer[20:])
		p := packetview.New(packetview.Limits{})
		var previous string
		for _, vlan := range []uint16{11, 12} {
			raw := testutil.Serialize(&layers.Ethernet{SrcMAC: []byte{2, 0, 0, 0, 0, 1}, DstMAC: []byte{2, 0, 0, 0, 0, 2}, EthernetType: layers.EthernetTypeDot1Q}, &layers.Dot1Q{VLANIdentifier: vlan, Type: layers.EthernetTypeIPv6}, gopacket.Payload(outer))
			r := p.Process(testutil.Packet(raw, 0, 1), 1)
			if r.Packet == nil || r.Packet.NetworkLayer().NetworkFlow().Src().String() != "10.0.0.1" || string(r.Packet.TransportLayer().LayerPayload()) != "outer IPv6" {
				t.Fatalf("%s IPv6 outer attribution: %+v", kind, r)
			}
			c := packetview.FromCapture(r.Packet.Metadata().CaptureInfo)
			if c.Tunnels[0].SrcIP != "2001:db8::1" || c.Scope == previous {
				t.Fatal("lost outer IPv6/VLAN context")
			}
			previous = c.Scope
		}
	}
}

func TestFragmentTransportExactlyOnce(t *testing.T) {
	for _, v6 := range []bool{false, true} {
		for _, protocol := range []layers.IPProtocol{6, 17, 1, 58} {
			if v6 && protocol == 1 || !v6 && protocol == 58 {
				continue
			}
			t.Run(fmt.Sprintf("v6=%v/proto=%d", v6, protocol), func(t *testing.T) {
				var payload []byte
				switch protocol {
				case 6:
					payload = testutil.Serialize(&layers.TCP{SrcPort: 40000, DstPort: 80, SYN: true, Seq: 99}, gopacket.Payload("fragment payload"))
				case 17:
					payload = testutil.Serialize(&layers.UDP{SrcPort: 40000, DstPort: 40001}, gopacket.Payload("fragment payload"))
				case 1:
					payload = testutil.Serialize(&layers.ICMPv4{TypeCode: layers.CreateICMPv4TypeCode(8, 0), Id: 13, Seq: 7}, gopacket.Payload("fragment payload"))
				case 58:
					payload = append([]byte{128, 0, 0, 0, 0, 13, 0, 7}, []byte("fragment payload")...)
				}
				ip := testutil.IP(v6, false, protocol, payload)
				p := packetview.New(packetview.Limits{})
				parts := [][]byte{testutil.Fragment(ip, 19, 0, 8, true), testutil.Fragment(ip, 19, 8, 16, true), testutil.Fragment(ip, 19, 16, len(payload), false)}
				for i, part := range []int{2, 0, 0, 1, 2, 0, 1} {
					r := process(p, parts[part], uint64(i+1))
					if r.Packet != nil {
						if i != 3 {
							t.Fatalf("early/duplicate transport at %d", i)
						}
						c := packetview.FromCapture(r.Packet.Metadata().CaptureInfo)
						if !c.Reassembled || len(c.Packets) != 4 || c.Packets[0].Ordinal != 1 {
							t.Fatalf("provenance %+v", c)
						}
						if r.Packet.ErrorLayer() != nil {
							t.Fatal(r.Packet.ErrorLayer().Error())
						}
						var got []byte
						if tl := r.Packet.TransportLayer(); tl != nil {
							got = append(append([]byte(nil), tl.LayerContents()...), tl.LayerPayload()...)
						} else {
							lt := layers.LayerTypeICMPv4
							if v6 {
								lt = layers.LayerTypeICMPv6
							}
							l := r.Packet.Layer(lt)
							if l == nil {
								t.Fatal("ICMP missing")
							}
							got = append(append([]byte(nil), l.LayerContents()...), l.LayerPayload()...)
						}
						if !bytes.Equal(got, payload) {
							t.Fatalf("transport differs: %x != %x", got, payload)
						}
						if !v6 {
							ip := r.Packet.NetworkLayer().(*layers.IPv4)
							if gopacket.FoldChecksum(gopacket.ComputeChecksum(ip.Contents, 0)) != 0 {
								t.Fatal("reconstructed checksum invalid")
							}
						}
					} else if i == 3 {
						t.Fatal("missing reconstruction", r.Status)
					}
				}
				if p.Stats().Completed != 1 || p.Stats().BufferedBytes != 0 {
					t.Fatalf("stats %+v", p.Stats())
				}
			})
		}
	}
}

func TestFragmentRejectsOverlapAndBounds(t *testing.T) {
	for _, v6 := range []bool{false, true} {
		ip := testutil.TCP(v6, false, 1, 0, "S", "012345678901234567890123456789")
		h := 20
		if v6 {
			h = 40
		}
		size := len(ip) - h
		for _, mode := range []string{"overlap", "conflict", "hole", "fragment-limit", "bytes-limit", "timeout", "reset"} {
			t.Run(fmt.Sprintf("v6=%v/%s", v6, mode), func(t *testing.T) {
				limits := packetview.DefaultLimits()
				if mode == "fragment-limit" {
					limits.MaxFragments = 1
				}
				if mode == "bytes-limit" {
					limits.MaxBytes = 1
				}
				p := packetview.New(limits)
				first := testutil.Fragment(ip, 4, 0, 16, true)
				if process(p, first, 1).Packet != nil {
					t.Fatal("partial dispatched")
				}
				next := testutil.Fragment(ip, 4, 16, size, false)
				switch mode {
				case "overlap":
					next = testutil.Fragment(ip, 4, 8, size, false)
				case "conflict":
					next = append([]byte(nil), first...)
					next[len(next)-1] ^= 1
				case "hole":
					next = testutil.Fragment(ip, 4, 24, size, false)
				case "timeout":
					p.ExpireIdle(time.Now().Add(time.Minute))
				case "reset":
					p.Reset()
				}
				if process(p, next, 2).Packet != nil {
					t.Fatal("unsafe reconstruction", mode)
				}
				if mode == "overlap" || mode == "conflict" {
					if process(p, testutil.Fragment(ip, 4, 16, size, false), 3).Packet != nil || p.Stats().Rejected != 1 {
						t.Fatal("rejected ID not quarantined")
					}
				}
				p.Reset()
				if p.Stats().BufferedBytes != 0 || p.Stats().Datagrams != 0 {
					t.Fatal("retained state after reset")
				}
			})
		}
		p := packetview.New(packetview.Limits{MaxDatagrams: 1})
		process(p, testutil.Fragment(ip, 1, 0, 16, true), 1)
		process(p, testutil.Fragment(ip, 2, 0, 16, true), 2)
		if p.Stats().Datagrams != 1 || p.Stats().Limited != 1 {
			t.Fatal(p.Stats())
		}
	}
}

func TestFragmentScopeAndNestedTunnels(t *testing.T) {
	ip := testutil.TCP(false, false, 1, 0, "S", "01234567890123456789")
	p := packetview.New(packetview.Limits{})
	first, last := testutil.Fragment(ip, 6, 0, 16, true), testutil.Fragment(ip, 6, 16, len(ip)-20, false)
	if process(p, testutil.Tunnel("vxlan", 1, first), 1).Packet != nil || process(p, testutil.Tunnel("vxlan", 2, last), 2).Packet != nil {
		t.Fatal("cross-VNI fragments merged")
	}
	if process(p, testutil.Tunnel("vxlan", 1, last), 3).Packet == nil || process(p, testutil.Tunnel("vxlan", 2, first), 4).Packet == nil {
		t.Fatal("scoped fragments failed")
	}
	outer := testutil.Tunnel("geneve-gre", 7, ip)
	p = packetview.New(packetview.Limits{})
	process(p, testutil.Fragment(outer, 8, 0, 32, true), 1)
	r := process(p, testutil.Fragment(outer, 8, 32, len(outer)-20, false), 2)
	if r.Packet == nil || r.Packet.TransportLayer() == nil || len(packetview.FromCapture(r.Packet.Metadata().CaptureInfo).Tunnels) != 2 {
		t.Fatalf("fragmented nested tunnel: %+v", r)
	}
}

func TestIPv6ExtensionsAndAtomicFragment(t *testing.T) {
	ip := testutil.TCP(true, false, 1, 0, "S", "extensions")
	first, last := testutil.Fragment(ip, 99, 0, 16, true), testutil.Fragment(ip, 99, 16, len(ip)-40, false)
	withHBH := func(raw []byte) []byte {
		out := append([]byte(nil), raw[:40]...)
		out[6] = 0
		out = append(out, []byte{44, 0, 1, 4, 0, 0, 0, 0}...)
		out = append(out, raw[40:]...)
		binary.BigEndian.PutUint16(out[4:6], uint16(len(out)-40))
		return out
	}
	p := packetview.New(packetview.Limits{})
	process(p, withHBH(last), 1)
	r := process(p, withHBH(first), 2)
	if r.Packet == nil || r.Packet.Layer(layers.LayerTypeIPv6HopByHop) == nil || r.Packet.Layer(layers.LayerTypeIPv6Fragment) != nil || r.Packet.TransportLayer() == nil {
		t.Fatalf("extension repair: %+v", r)
	}
	// RFC 6946: atomic fragments do not consume or collide with the pending ID.
	p = packetview.New(packetview.Limits{})
	process(p, first, 1)
	r = process(p, testutil.Fragment(ip, 99, 0, len(ip)-40, false), 2)
	if r.Packet == nil || r.Packet.TransportLayer() == nil {
		t.Fatal("atomic fragment failed")
	}
	if process(p, last, 3).Packet == nil {
		t.Fatal("atomic fragment destroyed pending set")
	}
}

func TestMalformedAndDepthBound(t *testing.T) {
	ip := testutil.TCP(false, false, 1, 0, "S", "")
	raw := testutil.Tunnel("geneve", 1, ip)
	raw[28] = 63 // options exceed UDP payload
	p := packetview.New(packetview.Limits{})
	if r := process(p, raw, 1); r.Packet != nil || r.Status != "malformed" {
		t.Fatalf("malformed Geneve: %+v", r)
	}
	raw = ip
	for range 5 {
		raw = testutil.Tunnel("gre", 1, raw)
	}
	p = packetview.New(packetview.Limits{MaxDepth: 2})
	if r := process(p, raw, 1); r.Packet != nil || r.Status != "depth-limit" || len(r.Evidence) != 3 {
		t.Fatalf("depth bound: %+v", r)
	}
	frag := testutil.Fragment(ip, 1, 0, 16, true)
	frag = frag[:len(frag)-1]
	frame := testutil.Ethernet(frag)[:14+len(frag)] // exclude Ethernet serializer padding
	if r := p.Process(testutil.Packet(frame, 0, 2), 2); r.Packet != nil || r.Status != "malformed" {
		t.Fatal("truncated fragment dispatched")
	}
}

func TestTunnelEndpointSymmetryAndGREKey(t *testing.T) {
	for _, kind := range []string{"gre", "vxlan", "geneve"} {
		p := packetview.New(packetview.Limits{})
		a := testutil.Tunnel(kind, 13, testutil.TCP(false, false, 1, 0, "S", ""))
		b := testutil.Tunnel(kind, 13, testutil.TCP(false, true, 1, 0, "SA", ""))
		copy(b[12:16], a[16:20])
		copy(b[16:20], a[12:16])
		if kind != "gre" {
			binary.BigEndian.PutUint16(b[20:22], 54000) // VTEP entropy must not split a conversation.
		}
		left, right := process(p, a, 1), process(p, b, 2)
		if left.Packet == nil || right.Packet == nil || packetview.Scope(left.Packet) != packetview.Scope(right.Packet) {
			t.Fatalf("%s reverse tunnel scope mismatch", kind)
		}
	}
	var previous string
	for _, key := range []uint32{7, 8} {
		inner := testutil.TCP(false, false, 1, 0, "S", "")
		gre := testutil.Serialize(&layers.GRE{Protocol: 0x88be, KeyPresent: true, Key: key, SeqPresent: true}, &layers.ERSPANII{Version: 1, SessionID: 3}, gopacket.Payload(testutil.Ethernet(inner)))
		r := process(packetview.New(packetview.Limits{}), testutil.IP(false, false, layers.IPProtocolGRE, gre), 1)
		if r.Packet == nil {
			t.Fatal(r.Status)
		}
		c := packetview.FromCapture(r.Packet.Metadata().CaptureInfo)
		if c.Tunnels[0].GREKey != key || c.Tunnels[0].Identifier != 3 || packetview.Scope(r.Packet) == previous {
			t.Fatal("ERSPAN lost GRE key/session identity")
		}
		previous = packetview.Scope(r.Packet)
	}
}

func TestMalformedTunnelControls(t *testing.T) {
	ip := testutil.TCP(false, false, 1, 0, "S", "")
	for _, mode := range []string{"short-udp", "bad-udp-length", "vxlan-flags", "geneve-critical", "geneve-option", "gre-version", "gre-protocol"} {
		t.Run(mode, func(t *testing.T) {
			kind := "vxlan"
			if mode == "geneve-critical" || mode == "geneve-option" {
				kind = "geneve"
			}
			if mode == "gre-version" || mode == "gre-protocol" {
				kind = "gre"
			}
			raw := testutil.Tunnel(kind, 1, ip)
			switch mode {
			case "short-udp":
				raw = raw[:24]
				binary.BigEndian.PutUint16(raw[2:4], uint16(len(raw)))
			case "bad-udp-length":
				binary.BigEndian.PutUint16(raw[24:26], 65535)
			case "vxlan-flags":
				raw[28] = 0
			case "geneve-critical":
				raw[29] = 0x40
			case "geneve-option":
				raw[28] = 1 // Four option bytes; length claims another four.
				raw[39] = 1
			case "gre-version":
				raw[21] |= 1
			case "gre-protocol":
				binary.BigEndian.PutUint16(raw[22:24], 0x1234)
			}
			r := process(packetview.New(packetview.Limits{}), raw, 1)
			if r.Packet != nil || r.Status != "malformed" || len(r.Evidence) == 0 {
				t.Fatalf("unsafe tunnel dispatch: %+v", r)
			}
		})
	}
	// A payload signature on another UDP port is ordinary application data.
	raw := testutil.Tunnel("vxlan", 1, ip)
	binary.BigEndian.PutUint16(raw[22:24], 9999)
	r := process(packetview.New(packetview.Limits{}), raw, 1)
	if r.Packet == nil || r.Packet.NetworkLayer().NetworkFlow().Src().String() != "192.0.2.1" || len(r.Evidence) != 0 {
		t.Fatal("ordinary UDP payload was decapsulated")
	}
}

func TestFragmentCaptureExpiryAndContextExport(t *testing.T) {
	p := packetview.New(packetview.Limits{Timeout: time.Second})
	ip := testutil.TCP(false, false, 1, 0, "S", "fragment evidence")
	first := testutil.Packet(testutil.Ethernet(testutil.Fragment(ip, 1, 0, 16, true)), 2, 1)
	first.Metadata().Timestamp = time.Unix(0, 0)
	p.Process(first, 1)
	last := testutil.Packet(testutil.Ethernet(testutil.Fragment(ip, 1, 16, len(ip)-20, false)), 2, 2)
	last.Metadata().Timestamp = time.Unix(2, 0)
	if p.Process(last, 2).Packet != nil || p.Stats().Expired != 1 {
		t.Fatal("capture-time expiry reconstructed across timeout", p.Stats())
	}
	p.Reset()
	p.Process(first, 1)
	last.Metadata().Timestamp = time.Unix(0, 500)
	r := p.Process(last, 2)
	if r.Packet == nil || !r.Packet.Metadata().Timestamp.Equal(time.Unix(0, 0)) {
		t.Fatal("lost epoch-zero fragment timestamp")
	}
	c := packetview.FromCapture(r.Packet.Metadata().CaptureInfo)
	if !c.CompletedAt.Equal(time.Unix(0, 500)) || len(c.Packets) != 2 || c.Packets[0].Timestamp != 0 || c.Packets[1].Timestamp != 500 {
		t.Fatalf("completion time or original evidence lost: %+v", c)
	}
	ctx := &types.PacketContext{}
	packetview.FillContext(ctx, r.Packet)
	encoded, err := proto.Marshal(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var decoded types.PacketContext
	if err = proto.Unmarshal(encoded, &decoded); err != nil || !proto.Equal(ctx, &decoded) {
		t.Fatalf("protobuf evidence roundtrip: %v", err)
	}
	var json bytes.Buffer
	if err = (&jsonpb.Marshaler{}).Marshal(&json, ctx); err != nil {
		t.Fatal(err)
	}
	var fromJSON types.PacketContext
	if err = jsonpb.Unmarshal(&json, &fromJSON); err != nil || !proto.Equal(ctx, &fromJSON) {
		t.Fatalf("JSON evidence roundtrip: %v", err)
	}
}

func FuzzPacketPipeline(f *testing.F) {
	f.Add(testutil.Ethernet(testutil.Tunnel("geneve-gre", 3, testutil.TCP(false, false, 1, 0, "S", ""))))
	f.Add(testutil.Ethernet(testutil.Fragment(testutil.TCP(true, false, 1, 0, "S", ""), 3, 0, 16, true)))
	f.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) > 65535 {
			return
		}
		p := packetview.New(packetview.Limits{MaxBytes: 65536, MaxDatagrams: 4, MaxDepth: 4})
		r := p.Process(testutil.Packet(raw, 0, 1), 1)
		if r.Packet != nil {
			r.Packet.Layers()
		}
		if p.Stats().BufferedBytes > 65536 || p.Stats().Datagrams > 4 {
			t.Fatal("limits exceeded")
		}
		p.Reset()
	})
}
