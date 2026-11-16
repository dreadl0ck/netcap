package collector

import (
	"bytes"
	"github.com/dreadl0ck/netcap/internal/rohc"
	"testing"
)

func rohcALP(data []byte, kind byte) []byte {
	n := len(data)
	return append([]byte{kind<<5 | 8 | byte(n>>8&7), byte(n), 5, 0xf1, 0, 4}, data...)
}

func TestALPRDTAndROHCUDPDispatch(t *testing.T) {
	r := &linkReconstructor{}
	rdt := []byte{2, 0xff, 0xff, 1, 15, 4, 4, 0x3f, 1, 0, 2}
	// Signalling information precedes the optional header (A/330 section 5.2).
	wire := []byte{0x88, 6, 5}
	wire = append(wire, rdt[:5]...)
	wire = append(wire, 0xf1, 0, 4)
	wire = append(wire, rdt[5:]...)
	p, f := alpPacket(t, wire, 1, 100)
	r.process(p, f, 1)
	if len(r.rohcChannels) != 1 || f.Fields["signalling_type"] != "2" {
		t.Fatal(f)
	}
	static := []byte{0x40, 17, 192, 0, 2, 1, 239, 1, 2, 3, 0x9c, 0x40, 0x27, 0x0f}
	dynamic := []byte{0, 64, 0, 0, 0xa0, 0, 0, 0, 0x10, 0}
	ir := append([]byte{0xfd, 2, 0}, static...)
	ir = append(ir, dynamic...)
	ir[2] = rohc.CRC(ir, 8)
	ir = append(ir, []byte("payload")...)
	p, f = alpPacket(t, rohcALP(ir, 2), 1, 101)
	children := r.process(p, f, 2)
	if len(children) != 1 || len(children[0].Data()) != 35 || !bytes.HasSuffix(children[0].Data(), []byte("payload")) {
		t.Fatal(f, len(children))
	}
	p, f = alpPacket(t, rohcALP(ir, 2), 2, 102)
	if len(r.process(p, f, 3)) != 0 {
		t.Fatal("ROHC channel crossed interfaces")
	}
	r.finish()
	if r.health.BufferedBytes != 0 {
		t.Fatal(r.health)
	}
}
