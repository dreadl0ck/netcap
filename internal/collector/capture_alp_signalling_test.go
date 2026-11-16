package collector

import (
	"bytes"
	"compress/flate"
	"encoding/json"
	"strings"
	"testing"
)

func TestALPSignallingTablesAndBounds(t *testing.T) {
	body := []byte{3, 7, 1, 192, 0, 2, 1, 239, 1, 2, 3, 0x9c, 0x40, 0x1f, 0x40, 0xff, 9, 10}
	wire := append([]byte{0x80, byte(len(body)), 1, 0xff, 0xff, 4, 15}, body...)
	p, f := alpPacket(t, wire, 1, 100)
	r := &linkReconstructor{}
	r.process(p, f, 1)
	var tables [][]alpPLP
	if err := json.Unmarshal([]byte(f.Fields["signalling_tables"]), &tables); err != nil {
		t.Fatal(err, f)
	}
	if len(tables) != 1 || len(tables[0]) != 1 || tables[0][0].ID != 1 || tables[0][0].Multicasts[0].Destination != "239.1.2.3" || *tables[0][0].Multicasts[0].SID != 9 || *tables[0][0].Multicasts[0].ContextID != 10 {
		t.Fatal(tables)
	}
	for n := 0; n < len(body); n++ {
		if _, err := parseALPLMT(body[:n]); err == nil {
			t.Fatal("truncated LMT accepted", n)
		}
	}
	var compressed bytes.Buffer
	w, _ := flate.NewWriter(&compressed, flate.DefaultCompression)
	_, _ = w.Write([]byte(`{"table":"fixture"}`))
	_ = w.Close()
	wire = append([]byte{0x80, byte(compressed.Len()), 0xf0, 0, 0, 1, 0x9f}, compressed.Bytes()...)
	p, f = alpPacket(t, wire, 1, 100)
	r.process(p, f, 2)
	if f.Fields["signalling_tables"] != `[{"decoded_length":19,"format":"json"}]` || string(f.Decoded) != `{"table":"fixture"}` {
		t.Fatal(f.Fields, f.Qualifications)
	}
	compressed.Reset()
	w, _ = flate.NewWriter(&compressed, flate.DefaultCompression)
	_, _ = w.Write(bytes.Repeat([]byte{'x'}, (1<<20)+1))
	_ = w.Close()
	n := compressed.Len()
	wire = append([]byte{0x80 | byte(n>>8&7), byte(n), 0xf0, 0, 0, 1, 0x9f}, compressed.Bytes()...)
	p, f = alpPacket(t, wire, 1, 100)
	r.process(p, f, 3)
	if !strings.Contains(strings.Join(f.Qualifications, ","), "deflate-invalid-or-limit") {
		t.Fatal(f.Fields, f.Qualifications)
	}
	for _, body := range []string{"not-xml", strings.Repeat("<x>", 65) + strings.Repeat("</x>", 65)} {
		n := len(body)
		wire = append([]byte{0x80 | byte(n>>8&7), byte(n), 0xf0, 0, 0, 1, 0x4f}, []byte(body)...)
		p, f = alpPacket(t, wire, 1, 100)
		r.process(p, f, 4)
		if _, found := f.Fields["signalling_tables"]; found || len(f.Decoded) != 0 {
			t.Fatal("invalid or over-depth XML was published", f)
		}
	}
}
