package collector

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"math"
	"testing"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"
)

func inputNFLOG(order binary.ByteOrder, family byte, payload []byte) []byte {
	data := make([]byte, 8+((len(payload)+3)&^3))
	data[0], data[3] = family, 42
	order.PutUint16(data[4:], uint16(4+len(payload)))
	order.PutUint16(data[6:], 9)
	copy(data[8:], payload)
	return data
}

func inputSLL2(payload []byte) []byte {
	data := make([]byte, 20)
	binary.BigEndian.PutUint16(data, 0x800)
	binary.BigEndian.PutUint32(data[4:], 7)
	binary.BigEndian.PutUint16(data[8:], 1)
	data[11] = 6
	copy(data[12:], []byte{1, 2, 3, 4, 5, 6})
	return append(data, payload...)
}

func inputDecode(data []byte, lt layers.LinkType, order binary.ByteOrder) gopacket.Packet {
	c := rawPacketCollector(1, 1, gopacket.DecodeOptions{SkipDecodeRecovery: true})
	ci := gopacket.CaptureInfo{Timestamp: time.Unix(123, 456), CaptureLength: len(data), Length: len(data), InterfaceIndex: 9, AncillaryData: []any{lt, capturePacketInfo{Order: order}}}
	return c.decodeRawPacketData(data, &ci)
}

func TestCaptureLinks(t *testing.T) {
	ip := rawPacketFixture(t, false, 64)[14:]
	for _, order := range []binary.ByteOrder{binary.LittleEndian, binary.BigEndian} {
		for _, tc := range []struct {
			lt    layers.LinkType
			data  []byte
			layer gopacket.LayerType
		}{
			{239, inputNFLOG(order, 2, ip), layerNFLOG},
			{104, append([]byte{0x0f, 0, 8, 0}, ip...), layerCHDLC},
			{276, inputSLL2(ip), layers.LayerTypeLinuxSLL2},
		} {
			p := inputDecode(tc.data, tc.lt, order)
			if p.ErrorLayer() != nil || p.Layer(tc.layer) == nil || p.Layer(layers.LayerTypeUDP) == nil {
				t.Fatalf("link %d: %v", tc.lt, p)
			}
			if !bytes.Equal(p.Data(), tc.data) || p.Metadata().CaptureLength != len(tc.data) || p.Metadata().InterfaceIndex != 9 {
				t.Fatal("link adapter changed evidence")
			}
			if p.NetworkLayer().NetworkFlow().Src().String() != "10.0.0.1" || p.TransportLayer().TransportFlow().Dst().String() != "40001" {
				t.Fatal("wrong network tuple")
			}
		}
	}
	ack := inputDecode([]byte{2, 0, 7}, 230, binary.LittleEndian)
	if ack.ErrorLayer() != nil || ack.Layer(layerIEEE802154) == nil {
		t.Fatal("valid no-FCS ACK rejected")
	}
	if linkTypeToLayerType(275) != 0 || linkTypeToLayerType(276) != layers.LayerTypeLinuxSLL2 {
		t.Fatal("SLL2 must be 276, not 275")
	}
	frame := []byte{0x41, 0x88, 7, 0x34, 0x12, 0x78, 0x56, 0xbc, 0x9a, 1, 2, 3, 4}
	p := inputDecode(frame, 230, binary.LittleEndian)
	mac, ok := p.Layer(layerIEEE802154).(*ieee802154Layer)
	if !ok || !bytes.Equal(mac.DestinationPAN, []byte{0x34, 0x12}) || !bytes.Equal(mac.SourcePAN, mac.DestinationPAN) || !bytes.Equal(mac.Source, []byte{0xbc, 0x9a}) || !bytes.Equal(mac.Destination, []byte{0x78, 0x56}) || !bytes.Equal(mac.Payload, []byte{1, 2, 3, 4}) {
		t.Fatalf("no-FCS MAC addressing or payload lost: %+v", mac)
	}
	var linkErr *captureLinkError
	if p.ErrorLayer() == nil || !errors.As(p.ErrorLayer().Error(), &linkErr) || !linkErr.Unsupported {
		t.Fatal("unimplemented WPAN payload must be explicitly qualified")
	}
}

func TestCaptureLinksMalformedAndUnsupported(t *testing.T) {
	le := binary.LittleEndian
	ip := rawPacketFixture(t, false, 64)[14:]
	nflog := inputNFLOG(le, 2, ip)
	badSLL := inputSLL2(ip)
	badSLL[11] = 9
	dup := append(bytes.Clone(nflog), nflog[4:]...)
	trailing := append(bytes.Clone(nflog), 0, 0, 1, 0)
	for _, tc := range []struct {
		name        string
		lt          layers.LinkType
		data        []byte
		unsupported bool
	}{
		{"nflog-short", 239, []byte{2, 0}, false},
		{"nflog-short-tlv", 239, []byte{2, 0, 0, 0, 4}, false},
		{"nflog-small-length", 239, []byte{2, 0, 0, 0, 3, 0, 9, 0}, false},
		{"nflog-big-length", 239, []byte{2, 0, 0, 0, 255, 255, 1, 0}, false},
		{"nflog-no-padding", 239, []byte{2, 0, 0, 0, 5, 0, 9, 0, 0x45}, false},
		{"nflog-duplicate", 239, dup, false},
		{"nflog-malformed-after-payload", 239, trailing, false},
		{"nflog-version", 239, []byte{2, 1, 0, 0}, true},
		{"nflog-family", 239, inputNFLOG(le, 99, ip), true},
		{"nflog-family-mismatch", 239, inputNFLOG(le, 10, ip), false},
		{"chdlc-short", 104, []byte{15, 0, 8}, false},
		{"chdlc-control", 104, append([]byte{15, 1, 8, 0}, ip...), false},
		{"chdlc-protocol", 104, []byte{15, 0, 0x80, 0x35}, true},
		{"sll2-address", 276, badSLL, false},
		{"sll2-short", 276, []byte{8, 0}, false},
		{"wrong-sll2-number", 275, inputSLL2(ip), true},
		{"wpan-short", 230, []byte{1, 0}, false},
		{"wpan-address-mode", 230, []byte{1, 4, 0}, false},
		{"wpan-address-truncated", 230, []byte{1, 8, 0}, false},
		{"wpan-pan-compression", 230, []byte{0x41, 0, 0}, false},
		{"wpan-v2", 230, []byte{1, 0x20, 0}, true},
		{"wpan-data", 230, []byte{1, 0, 0, 0x45}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := inputDecode(tc.data, tc.lt, le)
			failure := p.ErrorLayer()
			var le *captureLinkError
			if failure == nil || !errors.As(failure.Error(), &le) || le.Unsupported != tc.unsupported {
				t.Fatalf("wrong failure: %v", failure)
			}
			if p.Layer(layers.LayerTypeIPv4) != nil || p.Layer(layers.LayerTypeTCP) != nil {
				t.Fatal("malformed wrapper emitted network evidence")
			}
			if !bytes.Equal(p.Data(), tc.data) {
				t.Fatal("lost malformed raw bytes")
			}
		})
	}
}

func TestCaptureDiagnosticEvidence(t *testing.T) {
	var b bytes.Buffer
	w := newAtomicPcapGoWriter(&b, layers.LinkTypeEthernet)
	ip := rawPacketFixture(t, false, 64)[14:]
	frames := [][]byte{inputSLL2(ip), inputNFLOG(binary.BigEndian, 2, ip), append([]byte{15, 0, 8, 0}, ip...)}
	links := []layers.LinkType{276, 239, 104}
	orders := []binary.ByteOrder{binary.LittleEndian, binary.BigEndian, binary.LittleEndian}
	for i, data := range frames {
		ci := gopacket.CaptureInfo{Timestamp: time.Unix(123, int64(i)), CaptureLength: len(data), Length: len(data), InterfaceIndex: i, AncillaryData: []any{links[i], capturePacketInfo{Order: orders[i]}}}
		if err := w.writePacket(ci, data); err != nil {
			t.Fatal(err)
		}
	}
	r, err := pcapgo.NewNgReader(bytes.NewReader(b.Bytes()), pcapgo.NgReaderOptions{WantMixedLinkType: true})
	if err != nil {
		t.Fatal(err)
	}
	for i, data := range frames {
		got, ci, err := r.ReadPacketData()
		if err != nil || !bytes.Equal(got, data) || ci.AncillaryData[0] != links[i] || !ci.Timestamp.Equal(time.Unix(123, int64(i))) {
			t.Fatalf("diagnostic %d: %v %+v", i, err, ci)
		}
	}
	if _, _, err := r.ReadPacketData(); err != io.EOF {
		t.Fatal(err)
	}
	_, packets, infos := scanInputBytes(t, b.Bytes(), true, true)
	for i := range packets {
		p := inputDecode(packets[i], links[i], inputPacketInfo(infos[i]).Order)
		if p.ErrorLayer() != nil || p.NetworkLayer() == nil {
			t.Fatalf("native-order evidence replay %d: %v", i, p)
		}
	}
}

func TestCaptureDiagnosticTimestampBounds(t *testing.T) {
	for _, stamp := range []time.Time{time.Unix(-1, 0), time.Unix(0, math.MaxInt64).Add(time.Nanosecond), time.Unix(20_000_000_000, 0)} {
		var b bytes.Buffer
		w := newAtomicPcapGoWriter(&b, layers.LinkTypeEthernet)
		ci := gopacket.CaptureInfo{Timestamp: stamp, CaptureLength: 1, Length: 1}
		first := w.writePacket(ci, []byte{1})
		ci.Timestamp = time.Unix(0, 0)
		if first == nil || w.writePacket(ci, []byte{1}) != first || w.failure() != first || b.Len() != 0 || w.count != 0 {
			t.Fatal("out-of-range timestamp silently wrapped or writer failure was lost")
		}
	}
	for _, stamp := range []time.Time{time.Unix(0, 0), time.Unix(0, math.MaxInt64)} {
		var b bytes.Buffer
		w := newAtomicPcapGoWriter(&b, layers.LinkTypeEthernet)
		ci := gopacket.CaptureInfo{Timestamp: stamp, CaptureLength: 1, Length: 1}
		if err := w.writePacket(ci, []byte{1}); err != nil {
			t.Fatal(err)
		}
		_, _, infos := scanInputBytes(t, b.Bytes(), true, true)
		if len(infos) != 1 || !infos[0].Timestamp.Equal(stamp) {
			t.Fatal("diagnostic timestamp boundary failed round-trip")
		}
	}
}

func FuzzCaptureLinks(f *testing.F) {
	f.Add([]byte{2, 0, 0, 42, 4, 0, 9, 0}, uint8(0), false)
	f.Add([]byte{2, 0, 0}, uint8(3), false)
	f.Fuzz(func(t *testing.T, data []byte, kind uint8, big bool) {
		if len(data) > 4096 {
			t.Skip()
		}
		var order binary.ByteOrder = binary.LittleEndian
		if big {
			order = binary.BigEndian
		}
		links := []layers.LinkType{239, 104, 276, 230}
		p := inputDecode(data, links[int(kind)%len(links)], order)
		_ = p.Layers()
		if !bytes.Equal(p.Data(), data) {
			t.Fatal("adapter changed raw bytes")
		}
	})
}
