package bgp

import (
	"bytes"
	"encoding/binary"
	"reflect"
	"testing"
	"time"

	"github.com/dreadl0ck/netcap/internal/decoder/core"
	"github.com/dreadl0ck/netcap/internal/reassembly"
	"github.com/dreadl0ck/netcap/types"
	"github.com/gopacket/gopacket"
)

func frame(kind byte, payload ...byte) []byte {
	b := append(bytes.Repeat([]byte{255}, 16), 0, 0, kind)
	b = append(b, payload...)
	binary.BigEndian.PutUint16(b[16:18], uint16(len(b)))
	return b
}

func fragment(data []byte, server bool, ns int64) *core.StreamData {
	d := &core.StreamData{RawData: data, CaptureInformation: gopacket.CaptureInfo{Timestamp: time.Unix(0, ns)}}
	if server {
		d.Dir = reassembly.TCPDirServerToClient
	}
	return d
}

func decode(data core.DataFragments) []*types.BGP {
	b := &bgpReader{conversation: &core.ConversationInfo{Data: data, ClientIP: "192.0.2.1", ServerIP: "192.0.2.2", ClientPort: 40000, ServerPort: 179, CommunityID: "known"}}
	var messages []*types.BGP
	b.decodeMessages(func(m *types.BGP) { messages = append(messages, m) })
	return messages
}

func TestDirectionalTerminalKeepalive(t *testing.T) {
	keep := frame(BGPMsgKeepalive)
	for split := 1; split < len(keep); split++ {
		t.Run(string(rune('A'+split)), func(t *testing.T) {
			got := decode(core.DataFragments{fragment(keep[:split], false, 11), fragment(keep, true, 12), fragment(keep[split:], false, 13)})
			if len(got) != 2 {
				t.Fatalf("split %d: %+v", split, got)
			}
			if got[0].SrcIP != "192.0.2.2" || got[0].SrcPort != 179 || got[0].Timestamp != 12 || got[1].Timestamp != 11 || got[1].SrcIP != "192.0.2.1" || got[1].CommunityID != "known" {
				t.Fatalf("wrong attribution: %+v", got)
			}
		})
	}
	if got := decode(core.DataFragments{fragment(append(keep, keep...), false, 22)}); len(got) != 2 {
		t.Fatalf("coalesced terminal messages: %d", len(got))
	}
}

func TestGapCannotCompleteBGPFrame(t *testing.T) {
	keep := frame(BGPMsgKeepalive)
	for _, local := range []bool{false, true} {
		last := fragment(append(keep[10:], keep...), false, 33)
		if local {
			last.DiscardedBytes = 1
		} else {
			last.SkippedBytes = 1
		}
		got := decode(core.DataFragments{fragment(keep[:10], false, 11), last})
		if len(got) != 1 || got[0].Timestamp != 33 {
			t.Fatalf("gap synthesized a frame: %+v", got)
		}
	}
}

func TestASWidthAndReconstruction(t *testing.T) {
	for _, tc := range []struct {
		name  string
		width int
		data  []byte
		want  []uint32
	}{
		{"multiple-two-byte-segments", 2, []byte{2, 1, 0, 100, 2, 1, 0, 200}, []uint32{100, 200}},
		{"four-byte", 4, []byte{2, 2, 0, 1, 0, 0, 0, 2, 0, 0}, []uint32{65536, 131072}},
		{"midstream-two-byte", 0, []byte{2, 1, 0, 100, 2, 1, 0, 200}, []uint32{100, 200}},
		{"invalid-tail", 2, []byte{2, 1, 0, 100, 2}, nil},
		{"truncated", 4, []byte{2, 2, 0, 1, 0, 0}, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b := &bgpReader{asWidth: tc.width}
			if got := b.parseASPath(tc.data); !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("got %v want %v", got, tc.want)
			}
		})
	}
	legacy := []byte{0x40, 2, 8, 2, 3, 0, 100, 0x5b, 0xa0, 0x5b, 0xa0}
	as4 := []byte{0xc0, 17, 10, 2, 2, 0, 1, 0, 0, 0, 2, 0, 0}
	b := &bgpReader{asWidth: 2}
	m := &types.BGP{}
	b.parsePathAttributes(m, append(legacy, as4...))
	if !reflect.DeepEqual(m.ASPath, []uint32{100, 65536, 131072}) {
		t.Fatalf("lost legacy prefix: %v", m.ASPath)
	}
	m = &types.BGP{}
	b.parsePathAttributes(m, append(append([]byte(nil), as4...), legacy...))
	if !reflect.DeepEqual(m.ASPath, []uint32{100, 65536, 131072}) {
		t.Fatalf("attribute order changed path: %v", m.ASPath)
	}
}

func TestNegotiatedASWidth(t *testing.T) {
	open := func(four bool) []byte {
		payload := []byte{4, 0, 100, 0, 90, 192, 0, 2, 1, 0}
		if four {
			payload[9] = 8
			payload = append(payload, 2, 6, 65, 4, 0, 1, 0, 0)
		}
		return frame(BGPMsgOpen, payload...)
	}
	update := func(path []byte) []byte {
		attrs := append([]byte{0x40, 2, byte(len(path))}, path...)
		return frame(BGPMsgUpdate, append([]byte{0, 0, 0, byte(len(attrs))}, attrs...)...)
	}
	for _, four := range []bool{false, true} {
		path := []byte{2, 1, 0, 100}
		want := uint32(100)
		if four {
			path = []byte{2, 1, 0, 1, 0, 0}
			want = 65536
		}
		got := decode(core.DataFragments{fragment(open(four), false, 1), fragment(open(four), true, 2), fragment(update(path), false, 3)})
		if len(got) != 3 || !reflect.DeepEqual(got[2].ASPath, []uint32{want}) {
			t.Fatalf("four=%v: %+v", four, got)
		}
	}
}

func TestPrependLoopAndIPv6Analysis(t *testing.T) {
	for _, tc := range []struct {
		path []uint32
		loop bool
	}{{[]uint32{100, 100, 200, 200}, false}, {[]uint32{100, 100, 200, 100}, true}} {
		m := &types.BGP{ASPath: tc.path}
		analyzeBGPSecurity(m)
		if m.HasASPathLoop != tc.loop {
			t.Fatalf("path %v loop=%v", tc.path, m.HasASPathLoop)
		}
	}
	m := &types.BGP{IPv6NLRI: []string{"2001:4860::/32", "fc00::/7"}, IPv6Withdrawn: []string{"2001:4860::/48"}}
	analyzeBGPSecurity(m)
	if m.PrefixCount != 2 || m.WithdrawnCount != 1 || m.SmallestPrefixLen != 7 || m.LargestPrefixLen != 32 || !m.HasBogonPrefix {
		t.Fatalf("IPv6 ignored: %+v", m)
	}
	b := &bgpReader{}
	if got := b.parsePrefixes([]byte{33, 1, 2, 3, 4, 5}); len(got) != 0 {
		t.Fatalf("invalid IPv4 %v", got)
	}
	if got := b.parseIPv6Prefixes(append([]byte{129}, make([]byte, 17)...)); len(got) != 0 {
		t.Fatalf("invalid IPv6 %v", got)
	}
	if got := b.parsePrefixes([]byte{25, 192, 0, 2, 255}); !reflect.DeepEqual(got, []string{"192.0.2.128/25"}) {
		t.Fatalf("unmasked prefix %v", got)
	}
}

func FuzzBGPFraming(f *testing.F) {
	f.Add(frame(BGPMsgKeepalive), uint8(10))
	f.Add(frame(BGPMsgUpdate, 0, 0, 0, 0), uint8(20))
	f.Fuzz(func(t *testing.T, data []byte, split uint8) {
		if len(data) > 16384 {
			t.Skip()
		}
		n := int(split)
		if n > len(data) {
			n = len(data)
		}
		decode(core.DataFragments{fragment(data[:n], false, 1), fragment(data[n:], false, 2)})
	})
}

func TestCapabilityDirectionAndForwarding(t *testing.T) {
	b := &bgpReader{}
	for _, tc := range []struct {
		value         byte
		send, receive bool
	}{{1, false, true}, {2, true, false}, {3, true, true}} {
		m := &types.BGP{}
		b.parseCapabilities(m, []byte{69, 4, 0, 1, 1, tc.value})
		if len(m.Capabilities) != 1 || m.Capabilities[0].AddPathSend != tc.send || m.Capabilities[0].AddPathReceive != tc.receive {
			t.Fatalf("ADD-PATH %d: %+v", tc.value, m.Capabilities)
		}
	}
	for _, tc := range []struct {
		data    []byte
		forward bool
	}{{[]byte{64, 2, 0x80, 90}, false}, {[]byte{64, 6, 0, 90, 0, 1, 1, 0x80}, true}} {
		m := &types.BGP{}
		b.parseCapabilities(m, tc.data)
		if len(m.Capabilities) != 1 || m.Capabilities[0].GracefulRestartForwarding != tc.forward {
			t.Fatalf("GR %+v", m.Capabilities)
		}
	}
	if isBogonAS(23456) {
		t.Fatal("AS_TRANS is transition evidence, not a bogon")
	}
}

func TestNegotiatedAddPathPrefixes(t *testing.T) {
	open := func(mode byte) []byte {
		return frame(BGPMsgOpen, 4, 0, 100, 0, 90, 192, 0, 2, 1, 8, 2, 6, 69, 4, 0, 1, 1, mode)
	}
	// Path ID 0x01020304 precedes 192.0.2.0/24.
	update := frame(BGPMsgUpdate, 0, 0, 0, 0, 1, 2, 3, 4, 24, 192, 0, 2)
	got := decode(core.DataFragments{fragment(open(2), false, 1), fragment(open(1), true, 2), fragment(update, false, 3)})
	if len(got) != 3 || !reflect.DeepEqual(got[2].NLRI, []string{"192.0.2.0/24"}) || got[2].HasDefaultRoute {
		t.Fatalf("ADD-PATH framing: %+v", got)
	}
}

func TestMalformedBGPLengthsProduceNoConclusions(t *testing.T) {
	for _, wire := range [][]byte{
		frame(BGPMsgKeepalive, 0), frame(BGPMsgUpdate, 0, 5, 0, 0),
		frame(BGPMsgUpdate, 0, 0, 0, 5), frame(BGPMsgOpen, 4, 0, 100, 0, 90, 192, 0, 2, 1, 8),
	} {
		if got := decode(core.DataFragments{fragment(wire, false, 1)}); len(got) != 0 {
			t.Fatalf("malformed frame emitted: %+v", got)
		}
	}
}
