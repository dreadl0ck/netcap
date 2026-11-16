package collector

import (
	"encoding/binary"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

func decodeCaptureUSB(data []byte, p gopacket.PacketBuilder, link layers.LinkType, order binary.ByteOrder) error {
	if order == nil {
		order = binary.LittleEndian
	}
	u := &layers.USB{}
	var body, setup []byte
	switch link {
	case 189, 220:
		header := 48
		if link == 220 {
			header = 64
		}
		if len(data) < header {
			p.SetTruncated()
			return badLink("USB header shorter than %d bytes", header)
		}
		u.ID = order.Uint64(data[:8])
		u.EventType = layers.USBEventType(data[8])
		u.TransferType = layers.USBTransportType(data[9] & 3)
		u.EndpointNumber, u.DeviceAddress, u.BusID = data[10]&0x7f, data[11], order.Uint16(data[12:14])
		u.Direction = layers.USBDirectionTypeOut
		if data[10]&0x80 != 0 {
			u.Direction = layers.USBDirectionTypeIn
		}
		u.Setup, u.Data = data[14] == 0, data[15] == 0
		u.TimestampSec, u.TimestampUsec = int64(order.Uint64(data[16:24])), int32(order.Uint32(data[24:28]))
		u.Status, u.UrbLength, u.UrbDataLength = int32(order.Uint32(data[28:32])), order.Uint32(data[32:36]), order.Uint32(data[36:40])
		if link == 220 {
			u.UrbInterval = order.Uint32(data[48:52])
			u.UrbStartFrame = order.Uint32(data[52:56])
			u.IsoNumDesc = order.Uint32(data[60:64])
		}
		body = data[header:]
		if u.Setup {
			setup = data[40:48]
		}
		u.BaseLayer = layers.BaseLayer{Contents: data[:header]}
	case 249:
		if len(data) < 27 {
			p.SetTruncated()
			return badLink("USBPcap header shorter than 27 bytes")
		}
		header := int(binary.LittleEndian.Uint16(data[:2]))
		if header < 27 || header > len(data) {
			return badLink("invalid USBPcap header length %d", header)
		}
		u.ID = binary.LittleEndian.Uint64(data[2:10])
		u.Status = int32(binary.LittleEndian.Uint32(data[10:14]))
		u.EventType = layers.USBEventTypeSubmit
		if data[16]&1 != 0 {
			u.EventType = layers.USBEventTypeComplete
		}
		u.BusID = binary.LittleEndian.Uint16(data[17:19])
		device := binary.LittleEndian.Uint16(data[19:21])
		if device > 127 {
			return badLink("USBPcap device address %d exceeds 127", device)
		}
		u.DeviceAddress = byte(device)
		u.EndpointNumber = data[21] & 0x7f
		u.TransferType = layers.USBTransportType(data[22] & 3)
		u.Direction = layers.USBDirectionTypeOut
		if data[21]&0x80 != 0 {
			u.Direction = layers.USBDirectionTypeIn
		}
		u.UrbDataLength = binary.LittleEndian.Uint32(data[23:27])
		u.UrbLength = u.UrbDataLength
		u.Data = u.UrbDataLength > 0
		body = data[header:]
		u.BaseLayer = layers.BaseLayer{Contents: data[:header]}
		if u.TransferType == layers.USBTransportTypeControl && header >= 28 && data[27] == 0 && len(body) >= 8 {
			u.Setup = true
			setup = body[:8]
			body = body[8:]
		}
	case 266:
		if len(data) < 32 {
			p.SetTruncated()
			return badLink("Darwin USB header shorter than 32 bytes")
		}
		if binary.LittleEndian.Uint16(data[:2]) != 0x0100 {
			return unsupportedLink("unsupported Darwin USB header version 0x%04x", binary.LittleEndian.Uint16(data[:2]))
		}
		header := int(data[2])
		if header < 32 || header > len(data) {
			return badLink("invalid Darwin USB header length %d", header)
		}
		if data[3] > 1 || data[29] > 127 || data[30]&0x70 != 0 {
			return badLink("invalid Darwin USB request/device/endpoint fields")
		}
		if data[31] > 3 {
			return unsupportedLink("unsupported Darwin USB endpoint type %d", data[31])
		}
		u.ID = binary.LittleEndian.Uint64(data[16:24])
		u.BusID = uint16(binary.LittleEndian.Uint32(data[24:28]) >> 24)
		u.DeviceAddress, u.EndpointNumber = data[29], data[30]&0x0f
		u.Direction = layers.USBDirectionTypeOut
		if data[30]&0x80 != 0 {
			u.Direction = layers.USBDirectionTypeIn
		}
		u.TransferType = [4]layers.USBTransportType{layers.USBTransportTypeControl, layers.USBTransportTypeIsochronous, layers.USBTransportTypeBulk, layers.USBTransportTypeInterrupt}[data[31]]
		u.EventType = layers.USBEventTypeSubmit
		if data[3] == 1 {
			u.EventType = layers.USBEventTypeComplete
		}
		u.Status, u.UrbLength = int32(binary.LittleEndian.Uint32(data[8:12])), binary.LittleEndian.Uint32(data[4:8])
		u.IsoNumDesc = binary.LittleEndian.Uint32(data[12:16])
		u.BaseLayer = layers.BaseLayer{Contents: data[:header]}
		body = data[header:]
		u.Setup = data[3] == 0 && data[31] == 0
		if u.Setup {
			if len(body) < 8 {
				p.SetTruncated()
				return badLink("short Darwin USB setup data")
			}
			setup, body = body[:8], body[8:]
		}
		if data[31] == 1 {
			if err := validateDarwinISO(body, u.IsoNumDesc, data[3] == 1, header); err != nil {
				return err
			}
		} else if u.IsoNumDesc != 0 {
			return badLink("non-isochronous Darwin USB request has frame descriptors")
		}
		u.UrbDataLength = uint32(len(body))
		if data[3] == 1 && data[31] != 1 {
			u.UrbDataLength = u.UrbLength
		}
		u.Data = len(body) > 0
	default:
		return unsupportedLink("unsupported USB link type %d", link)
	}
	if !u.Data {
		body = nil
	}
	if uint64(u.UrbDataLength) > uint64(len(data)-len(u.Contents)) {
		p.SetTruncated()
	}
	u.Payload = body
	p.AddLayer(u)
	if len(setup) > 0 {
		s := &layers.USBRequestBlockSetup{}
		if err := s.DecodeFromBytes(setup, p); err != nil {
			return err
		}
		s.Payload = body
		p.AddLayer(s)
	}
	return p.NextDecoder(gopacket.LayerTypePayload)
}

func validateDarwinISO(data []byte, count uint32, complete bool, base int) error {
	minimum := 20
	if complete {
		minimum = 28
	}
	if uint64(count) > uint64(len(data))/uint64(minimum) {
		return badLink("Darwin USB isochronous frame count exceeds packet")
	}
	offset := 0
	for range count {
		if len(data)-offset < minimum {
			return badLink("short Darwin USB isochronous frame header")
		}
		header, size := uint64(binary.LittleEndian.Uint32(data[offset:])), uint64(binary.LittleEndian.Uint32(data[offset+4:]))
		if header < uint64(minimum) || header > uint64(len(data)-offset) {
			return badLink("invalid Darwin USB isochronous header length")
		}
		offset += int(header)
		if complete {
			if size > uint64(len(data)-offset) {
				return badLink("Darwin USB isochronous data exceeds packet")
			}
			offset += int(size)
		}
		if offset < len(data) {
			offset += (4 - (base+offset)&3) & 3
		}
	}
	return nil
}
