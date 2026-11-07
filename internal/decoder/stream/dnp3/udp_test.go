package dnp3

import (
	"encoding/binary"
	"testing"

	"github.com/dreadl0ck/netcap/internal/decoder/core"
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
