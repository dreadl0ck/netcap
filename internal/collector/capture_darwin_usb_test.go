package collector

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

func darwinUSBFrame(request, endpoint, transfer byte, body []byte) []byte {
	header := make([]byte, 32)
	binary.LittleEndian.PutUint16(header, 0x0100)
	header[2], header[3], header[28], header[29], header[30], header[31] = 32, request, 3, 7, endpoint, transfer
	binary.LittleEndian.PutUint32(header[4:], uint32(len(body)))
	binary.LittleEndian.PutUint64(header[16:], 0x1122334455667788)
	binary.LittleEndian.PutUint32(header[24:], 0x1a110000)
	return append(header, body...)
}

func decodeDarwinUSB(data []byte) gopacket.Packet {
	return gopacket.NewPacket(data, gopacket.DecodeFunc(func(data []byte, p gopacket.PacketBuilder) error {
		return decodeCaptureUSB(data, p, 266, binary.BigEndian)
	}), gopacket.Default)
}

func TestDarwinUSBHeaderMappingAndSetup(t *testing.T) {
	for _, tc := range []struct {
		wire     []byte
		transfer layers.USBTransportType
		setup    bool
		payload  []byte
	}{
		{darwinUSBFrame(1, 0x82, 2, []byte("usb")), layers.USBTransportTypeBulk, false, []byte("usb")},
		{darwinUSBFrame(0, 0x00, 0, []byte{0x80, 6, 0, 1, 0, 0, 18, 0}), layers.USBTransportTypeControl, true, nil},
		{darwinUSBFrame(1, 0x81, 3, []byte{1, 2, 3}), layers.USBTransportTypeInterrupt, false, []byte{1, 2, 3}},
	} {
		p := decodeDarwinUSB(tc.wire)
		if p.ErrorLayer() != nil {
			t.Fatal(p.ErrorLayer().Error())
		}
		u := p.Layer(layers.LayerTypeUSB).(*layers.USB)
		if u.ID != 0x1122334455667788 || u.BusID != 26 || u.DeviceAddress != 7 || u.TransferType != tc.transfer || u.Setup != tc.setup || !bytes.Equal(u.Payload, tc.payload) {
			t.Fatal("Darwin header fields shifted or payload changed", u)
		}
		if tc.setup && p.Layer(layers.LayerTypeUSBRequestBlockSetup) == nil {
			t.Fatal("Darwin setup request missing")
		}
		if tc.wire[30]&0x80 != 0 && u.Direction != layers.USBDirectionTypeIn {
			t.Fatal("endpoint direction lost", u.Direction)
		}
		if !bytes.Equal(p.Data(), tc.wire) {
			t.Fatal("Darwin decoding rewrote capture bytes")
		}
	}
}

func TestDarwinUSBISODescriptorBounds(t *testing.T) {
	for _, complete := range []bool{false, true} {
		header := 20
		request := byte(0)
		if complete {
			header, request = 28, 1
		}
		var body []byte
		for i := range 2 {
			desc := make([]byte, header)
			binary.LittleEndian.PutUint32(desc, uint32(header))
			binary.LittleEndian.PutUint32(desc[4:], 3)
			binary.LittleEndian.PutUint64(desc[12:], uint64(i))
			body = append(body, desc...)
			if complete {
				body = append(body, 1, 2, 3)
				body = append(body, 0)
			}
		}
		wire := darwinUSBFrame(request, 0x81, 1, body)
		binary.LittleEndian.PutUint32(wire[12:], 2)
		p := decodeDarwinUSB(wire)
		if p.ErrorLayer() != nil || p.Layer(layers.LayerTypeUSB).(*layers.USB).IsoNumDesc != 2 {
			t.Fatal("valid Darwin ISO rejected", p.ErrorLayer())
		}
		binary.LittleEndian.PutUint32(wire[12:], 3)
		if decodeDarwinUSB(wire).ErrorLayer() == nil {
			t.Fatal("overclaimed ISO frames accepted")
		}
	}
	for _, wire := range [][]byte{nil, make([]byte, 31), darwinUSBFrame(0, 0, 0, []byte{1}), darwinUSBFrame(2, 0, 2, nil), darwinUSBFrame(1, 0x70, 2, nil)} {
		if decodeDarwinUSB(wire).ErrorLayer() == nil {
			t.Fatal("malformed Darwin USB accepted", wire)
		}
	}
}
