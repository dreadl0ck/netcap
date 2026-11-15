package collector

import (
	"bytes"
	"encoding/binary"
	"errors"
	"hash/crc32"
	"path/filepath"
	"testing"

	"github.com/dreadl0ck/netcap/internal/encoder"
	"github.com/dreadl0ck/netcap/internal/linkaudit"
	"github.com/dreadl0ck/netcap/types"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

func inputPPI(link uint32, fields, payload []byte) []byte {
	data := make([]byte, 8+len(fields))
	binary.LittleEndian.PutUint16(data[2:], uint16(len(data)))
	binary.LittleEndian.PutUint32(data[4:], link)
	copy(data[8:], fields)
	return append(data, payload...)
}

func TestPPIInnerTrafficAndEvidence(t *testing.T) {
	frame := rawPacketFixture(t, false, 64)
	for _, order := range []binary.ByteOrder{binary.LittleEndian, binary.BigEndian} {
		for _, data := range [][]byte{
			inputPPI(1, nil, frame),
			inputPPI(192, nil, inputPPI(1, nil, frame)),
			inputPPI(101, nil, frame[14:]),
		} {
			original := append([]byte(nil), data...)
			p := inputDecode(data, 192, order)
			if p.ErrorLayer() != nil || p.Layer(layers.LayerTypeUDP) == nil || p.Layer(layerPPI) == nil {
				t.Fatalf("PPI did not reach inner traffic: %v", p)
			}
			if !bytes.Equal(p.Data(), original) || !bytes.Equal(data, original) || p.Metadata().CaptureLength != len(data) {
				t.Fatal("PPI decoder changed original evidence")
			}
			if p.NetworkLayer().NetworkFlow().Src().String() != "10.0.0.1" || p.TransportLayer().TransportFlow().Dst().String() != "40001" {
				t.Fatal("PPI inner endpoint attribution differs")
			}
		}
	}
}

func TestPPIFramingFailures(t *testing.T) {
	for _, tc := range []struct {
		name        string
		data        []byte
		unsupported bool
	}{
		{"short", []byte{0, 0, 8}, false},
		{"short-header-length", []byte{0, 0, 7, 0, 1, 0, 0, 0}, false},
		{"oversized-header", []byte{0, 0, 9, 0, 1, 0, 0, 0}, false},
		{"partial-field", inputPPI(1, []byte{2}, nil), false},
		{"field-overflow", inputPPI(1, []byte{9, 0, 10, 0}, nil), false},
		{"short-common-field", inputPPI(105, []byte{2, 0, 0, 0}, nil), false},
		{"unknown-inner", inputPPI(65535, nil, nil), true},
		{"wide-inner", inputPPI(65537, nil, nil), true},
		{"version", []byte{1, 0, 8, 0, 1, 0, 0, 0}, true},
		{"flags", []byte{0, 2, 8, 0, 1, 0, 0, 0}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := inputDecode(tc.data, 192, binary.LittleEndian)
			var problem *captureLinkError
			if p.ErrorLayer() == nil || !errors.As(p.ErrorLayer().Error(), &problem) || problem.Unsupported != tc.unsupported {
				t.Fatalf("wrong failure classification: %v", p.ErrorLayer())
			}
		})
	}
	data := rawPacketFixture(t, false, 64)
	for i := 0; i < 9; i++ {
		link := uint32(192)
		if i == 0 {
			link = 1
		}
		data = inputPPI(link, nil, data)
	}
	p := inputDecode(data, 192, binary.LittleEndian)
	var problem *captureLinkError
	if p.ErrorLayer() == nil || !errors.As(p.ErrorLayer().Error(), &problem) || !problem.Unsupported {
		t.Fatal("nested PPI did not stop at the nesting bound")
	}
}

func TestPPIWirelessFCSProvenance(t *testing.T) {
	encoder.SetConfig(&encoder.Config{ZScore: true})
	beacon := append([]byte{0x80, 0, 0, 0, 2, 0, 0, 0, 0, 1, 2, 0, 0, 0, 0, 2, 2, 0, 0, 0, 0, 3, 0, 0}, make([]byte, 12)...)
	beacon = append(beacon, 0, 4, 't', 'e', 's', 't')
	for _, fcs := range []bool{false, true} {
		fields := make([]byte, 24)
		binary.LittleEndian.PutUint16(fields, 2)
		binary.LittleEndian.PutUint16(fields[2:], 20)
		frame := bytes.Clone(beacon)
		if fcs {
			binary.LittleEndian.PutUint16(fields[12:], 1)
			frame = binary.LittleEndian.AppendUint32(frame, crc32.ChecksumIEEE(frame))
		}
		out := runHuntInput(t, huntPCAP(192, inputPPI(105, fields, frame)), "Dot11")
		var report CaptureInputReport
		readInputJSON(t, filepath.Join(out, "capture-input.json"), &report)
		if report.Status != "complete" || report.DecodeErrors != 0 || report.ProcessedPackets != 1 {
			t.Fatal(report)
		}
		records := bookRecords(t, out, "Dot11", func() *types.Dot11 { return new(types.Dot11) })
		if len(records) != 1 || !records[0].FCSKnown || records[0].FCSPresent != fcs || records[0].SSID != "test" {
			t.Fatalf("PPI lost wireless evidence: %+v", records)
		}
	}
}

func TestPPIAlignedUnknownFields(t *testing.T) {
	fields := []byte{0x30, 0x75, 1, 0, 0xab, 0, 0, 0, 0x31, 0x75, 0, 0}
	data := inputPPI(1, fields, rawPacketFixture(t, false, 64))
	data[1] = 1
	p := inputDecode(data, 192, binary.LittleEndian)
	if p.ErrorLayer() != nil || p.Layer(layers.LayerTypeUDP) == nil {
		t.Fatalf("aligned private PPI fields hid inner traffic: %v", p)
	}
}

type ppiHeaderProbe struct{ gopacket.PacketBuilder }

func (*ppiHeaderProbe) AddLayer(gopacket.Layer)            {}
func (*ppiHeaderProbe) SetTruncated()                      {}
func (*ppiHeaderProbe) NextDecoder(gopacket.Decoder) error { return nil }

func FuzzPPIBounds(f *testing.F) {
	f.Add(inputPPI(1, nil, make([]byte, 14)))
	f.Add(inputPPI(105, []byte{2, 0, 20, 0}, nil))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 1<<16 {
			return
		}
		// Exercise PPI framing independently of unrelated downstream dissectors.
		_ = decodePPI(data, &ppiHeaderProbe{}, binary.LittleEndian, 0, &linkaudit.FrameCheck{})
	})
}
