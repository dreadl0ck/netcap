package bacnetip

import "testing"

func TestBVLCRejectsDNSAndWrongFunctionLengths(t *testing.T) {
	for _, b := range [][]byte{{0x81, 5, 0x81, 0x80, 0, 1, 0, 0, 0, 0, 0, 0}, {0x81, 5, 0, 4}, {0x81, 0x0a, 0, 8, 0, 0, 0x10, 8}} {
		if canDecodeBACnetIP(b) {
			t.Fatalf("claimed %x", b)
		}
	}
	if !canDecodeBACnetIP([]byte{0x81, 5, 0, 6, 0, 60}) {
		t.Fatal("valid registration rejected")
	}
}
