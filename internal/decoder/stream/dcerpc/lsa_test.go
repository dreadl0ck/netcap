package dcerpc

import (
	"encoding/binary"
	"github.com/dreadl0ck/netcap/types"
	"testing"
	"unicode/utf16"
)

type ndrFixture struct {
	b []byte
	p int
}

func (w *ndrFixture) align(n int) {
	for len(w.b)%n != 0 {
		w.b = append(w.b, 0)
	}
}
func (w *ndrFixture) u16(v uint16) { w.align(2); w.b = binary.LittleEndian.AppendUint16(w.b, v) }
func (w *ndrFixture) u32(v uint32) { w.align(4); w.b = binary.LittleEndian.AppendUint32(w.b, v) }
func (w *ndrFixture) ptr(v uint64) {
	w.align(w.p)
	if w.p == 8 {
		w.b = binary.LittleEndian.AppendUint64(w.b, v)
	} else {
		w.u32(uint32(v))
	}
}
func (w *ndrFixture) header(s string) {
	w.align(w.p)
	n := uint16(len(utf16.Encode([]rune(s))) * 2)
	w.u16(n)
	w.u16(n)
	w.ptr(1)
}
func (w *ndrFixture) text(s string) {
	u := utf16.Encode([]rune(s))
	w.ptr(uint64(len(u)))
	w.ptr(0)
	w.ptr(uint64(len(u)))
	for _, v := range u {
		w.u16(v)
	}
}

func TestLSATranslationsNDR32And64(t *testing.T) {
	for _, p := range []int{4, 8} {
		w := &ndrFixture{p: p}
		w.ptr(1)
		w.align(p)
		w.u32(1)
		w.ptr(1)
		w.u32(1)
		w.align(p)
		w.ptr(1)
		w.header("EXAMPLE")
		w.ptr(1)
		w.align(p)
		w.text("EXAMPLE")
		w.ptr(2)
		w.b = append(w.b, 1, 2, 0, 0, 0, 0, 0, 5)
		w.u32(21)
		w.u32(10)
		w.align(p)
		w.u32(1)
		w.ptr(1)
		w.align(p)
		w.ptr(1)
		w.align(p)
		w.u16(1)
		w.u32(1001)
		w.u32(0)
		w.align(p)
		w.u32(1)
		w.u32(0)
		input := []*types.WindowsIdentity{{AccountName: "Analyst"}}
		got, status := lsaResults(w.b, 14, p == 8, binary.LittleEndian, input)
		if status != "decoded_ndr_lookup" || len(got) != 1 || got[0].AccountName != "Analyst" || got[0].Domain != "EXAMPLE" || got[0].SID != "S-1-5-21-10-1001" {
			t.Fatalf("NDR%d: %v %s", p*8, got, status)
		}
		for cut := 0; cut < len(w.b); cut++ {
			if got, _ := lsaResults(w.b[:cut], 14, p == 8, binary.LittleEndian, input); got != nil {
				t.Fatalf("truncation %d accepted", cut)
			}
		}
		w = &ndrFixture{p: p}
		w.ptr(0)
		w.align(p)
		w.u32(1)
		w.ptr(1)
		w.align(p)
		w.ptr(1)
		w.align(p)
		w.u16(1)
		w.header("Analyst")
		w.u32(0xffffffff)
		w.align(p)
		w.text("Analyst")
		w.u32(1)
		w.u32(0)
		got, status = lsaResults(w.b, 15, p == 8, binary.LittleEndian, []*types.WindowsIdentity{{SID: "S-1-5-21-10-1001"}})
		if status != "decoded_ndr_lookup" || len(got) != 1 || got[0].AccountName != "Analyst" || got[0].SID != "S-1-5-21-10-1001" {
			t.Fatalf("NDR%d: %v %s", p*8, got, status)
		}
		w.b[len(w.b)-1] = 0xc0
		if got, _ := lsaResults(w.b, 15, p == 8, binary.LittleEndian, nil); got != nil {
			t.Fatal("RPC failure emitted identity")
		}
	}
}
