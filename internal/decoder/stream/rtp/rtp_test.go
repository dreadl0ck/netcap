package rtp

import (
	"encoding/binary"
	"testing"
)

func TestRTPBounds(t *testing.T) {
	valid := []byte{0x80, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 3, 1}
	if r, p := parse(valid); r == nil || len(p) != 1 || r.Sequence != 1 || r.SSRC != 3 {
		t.Fatal("valid RTP rejected")
	}
	for _, data := range [][]byte{
		valid[:11], {0x8f, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 3, 1},
		{0xa0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 3, 0},
		{0xa0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 3, 2},
		{0x90, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 3, 0, 0, 0xff, 0xff},
		{0x80, 200, 0, 1, 0, 0, 0, 2, 0, 0, 0, 3, 1},
	} {
		if r, _ := parse(data); r != nil {
			t.Fatalf("malformed RTP accepted: %x", data)
		}
	}
	withExtras := []byte{0xb1, 0x80, 0, 1, 0, 0, 0, 2, 0, 0, 0, 3, 0, 0, 0, 4, 0xbe, 0xde, 0, 1, 0, 0, 0, 0, 9, 0, 0, 3}
	r, p := parse(withExtras)
	if r == nil || len(p) != 1 || p[0] != 9 || r.CSRC[0] != 4 || r.ExtensionProfile != 0xbede || r.ExtensionLength != 4 || r.PaddingLength != 3 || !r.Marker {
		t.Fatal("CSRC/extension/padding offset")
	}
}

func FuzzRTP(f *testing.F) {
	f.Add([]byte{0x80, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 3, 1})
	f.Add([]byte{0x90, 110, 0, 1, 0, 0, 0, 2, 0, 0, 0, 3, 0, 0, 0, 0, 5, 138, 0, 160})
	f.Fuzz(func(t *testing.T, data []byte) {
		r, p := parse(data)
		if r != nil && (int(r.PayloadLength) != len(p) || len(r.CSRC) > 15 || r.MediaTimestamp != binary.BigEndian.Uint32(data[4:8])) {
			t.Fatal("RTP bounds")
		}
	})
}
