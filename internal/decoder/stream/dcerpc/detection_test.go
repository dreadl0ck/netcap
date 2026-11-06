package dcerpc

import (
	"encoding/binary"
	"testing"
)

func TestRPCHeaderDoesNotClaimSOCKSConnect(t *testing.T) {
	socks := append([]byte{5, 1, 0, 3, 19}, []byte("mail.protonmail.com")...)
	socks = append(socks, 1, 187)
	if isDCERPC(socks) {
		t.Fatal("SOCKS tunnel claimed as DCE/RPC")
	}
	header := make([]byte, 24)
	header[0], header[3], header[4] = 5, 3, 0x10
	binary.LittleEndian.PutUint16(header[8:], 24)
	if !isDCERPC(header) {
		t.Fatal("valid RPC common header rejected")
	}
	for cut := 0; cut < 16; cut++ {
		if isDCERPC(header[:cut]) {
			t.Fatal("incomplete common header accepted")
		}
	}
	header[6] = 1
	if isDCERPC(header) {
		t.Fatal("invalid representation accepted")
	}
}
