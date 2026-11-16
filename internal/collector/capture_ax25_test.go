package collector

import (
	"bytes"
	"encoding/binary"
	"testing"
	"time"

	"github.com/dreadl0ck/netcap/internal/linkaudit"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

func TestAX25NegotiatedExtendedModeAndUpperPDUTables(t *testing.T) {
	r := &linkReconstructor{}
	frame := func(reverse bool, control ...byte) []byte {
		a, b := "DEST", "SOURCE"
		if reverse {
			a, b = b, a
		}
		wire := append(axAddress(a, false), axAddress(b, true)...)
		return append(wire, control...)
	}
	feed := func(wire []byte, ordinal uint64) ([]gopacket.Packet, *linkaudit.LinkFrame) {
		p := gopacket.NewPacket(wire, captureBusDecoder(3), gopacket.Default)
		p.Metadata().CaptureInfo = gopacket.CaptureInfo{Timestamp: time.Unix(100, int64(ordinal)), Length: len(wire), CaptureLength: len(wire)}
		if p.ErrorLayer() != nil {
			t.Fatal(p.ErrorLayer())
		}
		f := p.Layer(linkaudit.LayerLinkFrame).(*linkaudit.LinkFrame)
		return r.processAX25(p, f, ordinal), f
	}
	ip := alpIPv4(40000)
	information := append(frame(false, 2, 0, 0xcc), ip...)
	if children, _ := feed(information, 1); len(children) != 0 {
		t.Fatal("extended mode guessed without negotiation")
	}
	feed(frame(false, 0x6f), 2)
	feed(frame(true, 0x63), 3)
	children, f := feed(information, 4)
	if len(children) != 1 || !bytes.Equal(children[0].Data(), ip) || f.Fields["modulus"] != "128" || f.Fields["sequence_send"] != "1" {
		t.Fatal(f, len(children))
	}
	r.finish()
	if r.health.BufferedBytes != 0 {
		t.Fatal(r.health)
	}
	value := make([]byte, 4)
	binary.BigEndian.PutUint32(value, 0x0800)
	upper := append(upperTag(14, []byte("ethertype\x00")), upperTag(32, value)...)
	upper = append(upper, upperTag(0, nil)...)
	upper = append(upper, ip...)
	p := gopacket.NewPacket(upper, captureBusDecoder(252), gopacket.Default)
	if p.ErrorLayer() != nil || p.Layer(layers.LayerTypeIPv4) == nil {
		t.Fatal("registered Upper PDU table did not dispatch", p)
	}
}
