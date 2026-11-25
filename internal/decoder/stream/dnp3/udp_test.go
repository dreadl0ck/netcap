package dnp3

import (
	"encoding/binary"
	"testing"

	"github.com/dreadl0ck/netcap/internal/decoder/core"
	"github.com/dreadl0ck/netcap/types"
)

func udpWire(user ...byte) []byte {
	header := []byte{5, 100, byte(5 + len(user)), 0xc4, 3, 0, 4, 0}
	appendCRC := func(b []byte) []byte { crc := crc16DNP(b); return binary.LittleEndian.AppendUint16(b, crc) }
	frame := appendCRC(header)
	for len(user) > 0 {
		n := min(16, len(user))
		frame = append(frame, appendCRC(append([]byte(nil), user[:n]...))...)
		user = user[n:]
	}
	return frame
}

func udpReader(data ...[]byte) *dnp3Reader {
	r := reader(nil, nil, false)
	r.conversation.Transport = core.UDP
	for i, b := range data {
		r.conversation.Data = append(r.conversation.Data, fragment(b, int64(i+1), false, 0))
	}
	return r
}

func TestUDPBoundariesCRCAndTransportSequence(t *testing.T) {
	full := mustHex(t, frameRead)
	if got := valid(records(udpReader(full[:12], full[12:]))); len(got) != 0 {
		t.Fatal("joined unrelated datagram bytes")
	}
	if got := valid(records(udpReader(append(append([]byte{}, full...), full...)))); len(got) != 2 {
		t.Fatal("coalesced link frames")
	}
	bad := append([]byte{}, full...)
	bad[len(bad)-1] ^= 1
	if got := records(udpReader(bad)); len(got) != 1 || got[0].ParseStatus != statusMalformed || got[0].FunctionCode != 0 {
		t.Fatal("bad block CRC decoded")
	}
	first, last := udpWire(0x7f, 0xc1, 1), udpWire(0x80, 60, 2, 6)
	got := records(udpReader(first, first, last))
	if len(got) != 2 || got[1].FunctionCode != 1 || got[1].Timestamp != 1 || !got[1].BlockCRCValid {
		t.Fatalf("sequence wrap/retransmit: %v", got)
	}
	for _, tail := range [][]byte{udpWire(0x81, 60, 2, 6), udpWire(0x80, 60)} {
		got := records(udpReader(first, tail))
		if len(got) != 2 {
			t.Fatal("missing qualification")
		}
		if tail[10] == 0x81 && got[1].ParseStatus != statusLost {
			t.Fatal("sequence gap parsed")
		}
	}
	if got := records(udpReader(last)); got[0].ParseStatus != statusLost || got[0].FunctionCode != 0 {
		t.Fatal("orphan continuation parsed")
	}
}

func TestDatagramTransferRelease(t *testing.T) {
	var d Datagrams
	var rows []*types.DNP3
	emit := func(r *types.DNP3) { rows = append(rows, r) }
	ctx := &types.PacketContext{SrcIP: "192.0.2.1", DstIP: "192.0.2.2", DstPort: 20000, CommunityID: "flow"}
	feed := func(at int64, data []byte) { d.Decode(data, ctx, at, emit) }
	first, last := udpWire(0x7f, 0xc1, 1), udpWire(0x80, 60, 2, 6)
	feed(1, first)
	// A link acknowledgement is not a transport or application boundary.
	feed(2, udpWire())
	feed(3, last)
	if len(rows) != 3 || rows[2].Assembly.GetStatus() != "complete" || rows[2].Timestamp != 1 || d.Pending() {
		t.Fatal(rows)
	}
	feed(4, first)
	d.Flush(5, false, "idle expiry", emit)
	feed(6, last)
	if len(rows) != 6 || rows[4].Assembly.GetReason() != "idle expiry" || rows[4].Timestamp != 4 || rows[4].SrcIP != ctx.SrcIP || rows[5].ParseStatus != statusLost || d.Pending() {
		t.Fatal(rows)
	}
	// A completed transport fragment can leave an application message open.
	feed(7, udpWire(0xc0, 0x81, 0x81, 0, 0))
	d.Flush(0, true, "EOF", emit)
	if len(rows) != 8 || rows[6].Assembly.GetStatus() != "pending" || rows[7].Assembly.GetReason() != "EOF" || rows[7].Timestamp != 7 || d.Pending() {
		t.Fatal(rows)
	}
}

func FuzzDNP3Datagram(f *testing.F) {
	f.Add(udpWire(0xc0, 0xc0, 1))
	f.Add([]byte{5, 100})
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 65535 {
			return
		}
		records(udpReader(data))
	})
}
