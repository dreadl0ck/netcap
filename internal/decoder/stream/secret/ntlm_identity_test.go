package secret

import (
	"encoding/binary"
	"testing"
	"time"
	"unicode/utf16"
)

func TestNTLMIdentityWithoutChallenge(t *testing.T) {
	b := make([]byte, 64)
	copy(b, ntlmsspSignature)
	binary.LittleEndian.PutUint32(b[8:], 3)
	binary.LittleEndian.PutUint32(b[60:], 1)
	for i, s := range []string{"EXAMPLE", "bdiaz", "VICTIM"} {
		u := utf16.Encode([]rune(s))
		offset := 28 + i*8
		binary.LittleEndian.PutUint16(b[offset:], uint16(len(u)*2))
		binary.LittleEndian.PutUint16(b[offset+2:], uint16(len(u)*2))
		binary.LittleEndian.PutUint32(b[offset+4:], uint32(len(b)))
		for _, v := range u {
			b = binary.LittleEndian.AppendUint16(b, v)
		}
	}
	r := ntlmsspHarvesterFunc(b, "flow", time.Unix(1, 0))
	if r == nil || r.User != "bdiaz" || r.Realm != "EXAMPLE" || r.Password != "" {
		t.Fatal(r)
	}
	binary.LittleEndian.PutUint32(b[40:], 0xffffffff)
	if r := ntlmsspHarvesterFunc(b, "flow", time.Unix(1, 0)); r != nil {
		t.Fatal("out-of-bounds username accepted", r)
	}
}
