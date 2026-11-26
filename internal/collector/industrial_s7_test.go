package collector

import (
	"encoding/binary"
	"testing"

	"github.com/dreadl0ck/netcap/types"
)

func TestIndustrialS7Transfers(t *testing.T) {
	b, path := newBookCapture(t)
	tpkt := func(p []byte) bookMessage {
		wire := append([]byte{3, 0, 0, 0, 2, 0xf0, 0x80}, p...)
		binary.BigEndian.PutUint16(wire[2:], uint16(len(wire)))
		return bookMessage{server: true, text: string(wire)}
	}
	unit := func(seq, ref, more byte, data []byte) bookMessage {
		// CPU Read SZL response, extended userdata parameter and octet-string value.
		p := industrialHex(t, "320700000001000c0000000112081284010000000000ff090000")
		p[17], p[18], p[19] = seq, ref, more
		binary.BigEndian.PutUint16(p[8:], uint16(len(data)+4))
		binary.BigEndian.PutUint16(p[24:], uint16(len(data)))
		return tpkt(append(p, data...))
	}
	value := append(industrialHex(t, "00110002001c00010001"), make([]byte, 26)...)
	const src, dst = "192.0.2.1", "192.0.2.2"
	times := b.conversation(src, dst, 41010, 102, false,
		unit(1, 3, 1, value[:4]), unit(2, 4, 1, value[:3]),
		unit(1, 3, 0, value[4:]), unit(2, 5, 1, value[:5]), unit(2, 5, 0, value[5:]),
		unit(3, 3, 1, value[:4]))
	plus := b.conversation(src, dst, 41011, 102, false,
		tpkt(industrialHex(t, "7202000b3200000542000000023400")),
		tpkt(industrialHex(t, "72fe001000000000000001f40000000000000000")),
		tpkt(industrialHex(t, "72020002ccdd72020000")))
	out := runVoIP(t, path, "S7Comm", 2)
	rows := bookRecords(t, out, "S7Comm", func() *types.S7Comm { return new(types.S7Comm) })
	seen := map[int64]string{}
	for _, r := range rows {
		a := r.Assembly
		if a == nil || a.FirstTimestamp != r.Timestamp || r.SrcIP != dst || r.DstIP != src || r.SrcPort != 102 {
			t.Fatalf("lost transfer provenance: %v", r)
		}
		if a.Status == "pending" {
			continue
		}
		if _, exists := seen[r.Timestamp]; exists {
			t.Fatalf("duplicate terminal record at %d: %v", r.Timestamp, r)
		}
		switch r.Timestamp {
		case times[0], times[3]:
			if a.Status != "complete" || a.Pieces != 2 || r.SZLID != 0x11 || r.SZLIndex != 2 || r.SZLRecords != 1 {
				t.Fatalf("joined SZL: %v", r)
			}
		case times[1], times[5]:
			if a.Status != "incomplete" || r.SZLRecords != 0 || r.Timestamp == times[1] && a.Reason != "userdata transfer replaced" || r.Timestamp == times[5] && a.Reason != "EOF" {
				t.Fatalf("abandoned transfer: %v", r)
			}
		case plus[0]:
			if a.Status != "complete" || a.Pieces != 2 || r.S7PlusFunction != 0x542 || r.DataLength != 3 {
				t.Fatalf("joined S7-plus: %v", r)
			}
		case plus[1]:
			if a.Status != "complete" || r.MessageType != 0xfe || r.S7PlusFunction != 0 {
				t.Fatalf("system event: %v", r)
			}
		default:
			t.Fatalf("unexpected transfer: %v", r)
		}
		seen[r.Timestamp] = a.Status
	}
	if len(seen) != 6 {
		t.Fatalf("terminal records: %v", seen)
	}
}
