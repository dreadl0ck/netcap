package iec62351

import "testing"

func TestGenericTLSAndMarkersAreNotIEC(t *testing.T) {
	for _, b := range [][]byte{
		append([]byte{22, 3, 3, 0, 40, 1}, make([]byte, 40)...),
		[]byte("random binary 621 security marker"),
		append([]byte{0x68, 40, 1, 0, 0, 0}, make([]byte, 40)...),
		{0x68, 10, 0, 0, 0, 0, 1, 1, 3, 0, 1, 0, 0, 0, 0, 0, 0, 0, 3, 4},
	} {
		if Decoder.CanDecode(b, nil) {
			t.Fatalf("false match %x", b)
		}
	}
}
