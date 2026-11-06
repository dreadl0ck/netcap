package dcerpc

import (
	"encoding/binary"
	"testing"
	"unicode/utf16"
)

func samrNameReply(level uint16, account, full string) []byte {
	fixed, desc := 16, 0
	names := []string{account, full}
	if level == 7 {
		fixed = 8
		names = []string{account}
	}
	if level == 8 {
		fixed = 8
		names = []string{full}
	}
	if level == 21 {
		fixed = 196
		desc = 48
	}
	b := make([]byte, 8+fixed)
	binary.LittleEndian.PutUint32(b, 0x20000)
	binary.LittleEndian.PutUint16(b[4:], level)
	if level == 21 {
		binary.LittleEndian.PutUint32(b[8+172:], 3)
	}
	for i, name := range names {
		u := utf16.Encode([]rune(name))
		d := b[8+desc+i*8:]
		binary.LittleEndian.PutUint16(d, uint16(len(u)*2))
		binary.LittleEndian.PutUint16(d[2:], uint16(len(u)*2))
		binary.LittleEndian.PutUint32(d[4:], uint32(0x20004+i*4))
	}
	for _, name := range names {
		for len(b)%4 != 0 {
			b = append(b, 0)
		}
		u := utf16.Encode([]rune(name))
		b = binary.LittleEndian.AppendUint32(b, uint32(len(u)))
		b = binary.LittleEndian.AppendUint32(b, 0)
		b = binary.LittleEndian.AppendUint32(b, uint32(len(u)))
		for _, v := range u {
			b = binary.LittleEndian.AppendUint16(b, v)
		}
	}
	for len(b)%4 != 0 {
		b = append(b, 0)
	}
	return append(b, 0, 0, 0, 0)
}

func TestSAMRIdentityUnion(t *testing.T) {
	for _, level := range []uint16{6, 7, 8, 21} {
		b := samrNameReply(level, "bdiaz", "Test Analyst")
		i, status := samrUserIdentity(b, level, binary.LittleEndian)
		if i == nil || status != "decoded_ndr32" || level != 8 && i.AccountName != "bdiaz" || level != 7 && i.FullName != "Test Analyst" {
			t.Fatalf("class %d: %v %s", level, i, status)
		}
		for cut := 0; cut < len(b)-4; cut++ {
			if i, _ := samrUserIdentity(b[:cut], level, binary.LittleEndian); i != nil {
				t.Fatalf("truncated class %d at %d accepted", level, cut)
			}
		}
		if i, _ := samrUserIdentity(b, level+1, binary.LittleEndian); i != nil {
			t.Fatal("union discriminator ignored")
		}
		b[len(b)-1] = 1
		if i, _ := samrUserIdentity(b, level, binary.LittleEndian); i != nil {
			t.Fatal("failed RPC produced identity")
		}
	}
}

func TestSAMRNDR64UserAllInformation(t *testing.T) {
	b := make([]byte, 336)
	binary.LittleEndian.PutUint64(b, 0x20000)
	binary.LittleEndian.PutUint16(b[8:], 21)
	binary.LittleEndian.PutUint32(b[300:], 3)
	for i, name := range []string{"analyst", "Test Analyst"} {
		u := utf16.Encode([]rune(name))
		desc := b[64+i*16:]
		binary.LittleEndian.PutUint16(desc, uint16(len(u)*2))
		binary.LittleEndian.PutUint16(desc[2:], uint16(len(u)*2))
		binary.LittleEndian.PutUint64(desc[8:], uint64(0x20008+i*8))
	}
	for _, name := range []string{"analyst", "Test Analyst"} {
		for len(b)%8 != 0 {
			b = append(b, 0)
		}
		u := utf16.Encode([]rune(name))
		b = binary.LittleEndian.AppendUint64(b, uint64(len(u)))
		b = binary.LittleEndian.AppendUint64(b, 0)
		b = binary.LittleEndian.AppendUint64(b, uint64(len(u)))
		for _, v := range u {
			b = binary.LittleEndian.AppendUint16(b, v)
		}
	}
	b = append(b, 0, 0, 0, 0)
	i, status := samrUserIdentity64(b, 21, binary.LittleEndian)
	if i == nil || status != "decoded_ndr64" || i.AccountName != "analyst" || i.FullName != "Test Analyst" {
		t.Fatalf("%v %s", i, status)
	}
	for cut := 0; cut < len(b)-4; cut++ {
		if i, _ := samrUserIdentity64(b[:cut], 21, binary.LittleEndian); i != nil {
			t.Fatalf("truncation accepted at %d", cut)
		}
	}
	binary.LittleEndian.PutUint64(b[336:], 1<<40)
	if i, _ := samrUserIdentity64(b, 21, binary.LittleEndian); i != nil {
		t.Fatal("unbounded NDR64 array accepted")
	}
}
