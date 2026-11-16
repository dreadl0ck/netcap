package collector

import (
	"encoding/binary"
	"fmt"
	"strconv"
	"strings"

	"github.com/dreadl0ck/netcap/internal/linkaudit"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

func busFrame(kind uint32, protocol string) *linkaudit.LinkFrame {
	return &linkaudit.LinkFrame{Type: kind, Protocol: protocol, PayloadProtocol: "opaque", Fields: map[string]string{}}
}

func finishBusFrame(data []byte, header int, frame *linkaudit.LinkFrame, p gopacket.PacketBuilder, next gopacket.Decoder) error {
	if header < 0 || header > len(data) {
		return badLink("invalid %s header boundary", frame.Protocol)
	}
	frame.Header, frame.Payload = data[:header], data[header:]
	if frame.PayloadProtocol == "opaque" && len(frame.Payload) > 0 {
		frame.Qualifications = append(frame.Qualifications, "upper-layer-not-decoded")
	}
	p.AddLayer(frame)
	if next == nil {
		next = gopacket.LayerTypePayload
	}
	return p.NextDecoder(next)
}

func decodeI2CLinux(data []byte, p gopacket.PacketBuilder) error {
	if len(data) < 6 {
		p.SetTruncated()
		return badLink("I2C Linux header shorter than 6 bytes")
	}
	f := busFrame(209, "I2C Linux")
	flags := binary.BigEndian.Uint32(data[1:5])
	f.Fields["bus"] = strconv.Itoa(int(data[0] & 0x7f))
	f.Fields["event"] = strconv.FormatBool(data[0]&0x80 != 0)
	f.Fields["flags"] = fmt.Sprintf("0x%08x", flags)
	f.Fields["address"] = fmt.Sprintf("0x%02x", data[5]>>1)
	f.Fields["read"] = strconv.FormatBool(flags&1 != 0)
	return finishBusFrame(data, 6, f, p, nil)
}

func decodeBluetoothH4(data []byte, p gopacket.PacketBuilder, pseudo bool) error {
	offset := 0
	kind := uint32(187)
	f := busFrame(kind, "Bluetooth HCI H4")
	if pseudo {
		if len(data) < 5 {
			p.SetTruncated()
			return badLink("short Bluetooth H4 direction header")
		}
		offset, f.Type = 4, 201
		direction := binary.BigEndian.Uint32(data[:4])
		f.Fields["direction_flags"] = fmt.Sprintf("0x%08x", direction)
		f.Source, f.Destination = "controller", "host"
		if direction&1 != 0 {
			f.Source, f.Destination = f.Destination, f.Source
		}
	}
	if len(data)-offset < 1 {
		return badLink("Bluetooth H4 packet indicator missing")
	}
	packetType := data[offset]
	f.Fields["packet_type"] = strconv.Itoa(int(packetType))
	offset++
	header, length := 0, 0
	switch packetType {
	case 1:
		header = 3
		if len(data)-offset >= header {
			length = int(data[offset+2])
			f.Fields["opcode"] = fmt.Sprintf("0x%04x", binary.LittleEndian.Uint16(data[offset:]))
		}
	case 2, 5:
		header = 4
		if len(data)-offset >= header {
			length = int(binary.LittleEndian.Uint16(data[offset+2:]))
			if packetType == 5 {
				length &= 0x3fff
			}
			f.Fields["handle_flags"] = fmt.Sprintf("0x%04x", binary.LittleEndian.Uint16(data[offset:]))
		}
	case 3:
		header = 3
		if len(data)-offset >= header {
			length = int(data[offset+2])
		}
	case 4:
		header = 2
		if len(data)-offset >= header {
			length = int(data[offset+1])
			f.Fields["event_code"] = fmt.Sprintf("0x%02x", data[offset])
		}
	default:
		f.Qualifications = append(f.Qualifications, "unknown-hci-packet-type")
		return finishBusFrame(data, offset, f, p, nil)
	}
	if len(data)-offset < header || length > len(data)-offset-header {
		p.SetTruncated()
		return badLink("Bluetooth H4 header/data length exceeds packet")
	}
	offset += header
	f.Fields["declared_payload_length"] = strconv.Itoa(length)
	if length != len(data)-offset {
		f.Qualifications = append(f.Qualifications, "trailing-capture-bytes")
	}
	return finishBusFrame(data, offset, f, p, nil)
}

func decodeMPEGTS(data []byte, p gopacket.PacketBuilder) error {
	if len(data) == 0 || len(data)%188 != 0 {
		return badLink("MPEG-2 TS capture is not a whole number of 188-byte packets")
	}
	f := busFrame(243, "MPEG-2 TS")
	f.Fields["packet_count"] = strconv.Itoa(len(data) / 188)
	for offset := 0; offset < len(data); offset += 188 {
		packet := data[offset : offset+188]
		if packet[0] != 0x47 || packet[3]&0x30 == 0 {
			return badLink("invalid MPEG-2 TS sync/adaptation control")
		}
		if packet[3]&0x20 != 0 && int(packet[4]) > 183 {
			return badLink("MPEG-2 TS adaptation field exceeds packet")
		}
	}
	f.Fields["pid"] = strconv.Itoa(int(binary.BigEndian.Uint16(data[1:3]) & 0x1fff))
	f.Fields["continuity_counter"] = strconv.Itoa(int(data[3] & 15))
	f.Fields["scrambling"] = strconv.Itoa(int(data[3] >> 6))
	return finishBusFrame(data, 4, f, p, nil)
}

func decodeAX25(data []byte, p gopacket.PacketBuilder) error {
	f := busFrame(3, "AX.25")
	var addresses []string
	offset := 0
	for {
		if len(addresses) >= 10 || len(data)-offset < 7 {
			return badLink("AX.25 address chain exceeds frame or limit")
		}
		a := data[offset : offset+7]
		var call [6]byte
		for i := range call {
			call[i] = a[i] >> 1
			if a[i]&1 != 0 || !(call[i] == ' ' || call[i] >= 'A' && call[i] <= 'Z' || call[i] >= '0' && call[i] <= '9') {
				return badLink("invalid AX.25 shifted callsign")
			}
		}
		address := strings.TrimRight(string(call[:]), " ")
		if address == "" {
			return badLink("empty AX.25 callsign")
		}
		if ssid := a[6] >> 1 & 15; ssid != 0 {
			address += "-" + strconv.Itoa(int(ssid))
		}
		addresses = append(addresses, address)
		offset += 7
		if a[6]&1 != 0 {
			break
		}
	}
	if len(addresses) < 2 || offset == len(data) {
		return badLink("AX.25 requires destination/source and control")
	}
	f.Source, f.Destination = addresses[1], addresses[0]
	if len(addresses) > 2 {
		f.Fields["digipeaters"] = strings.Join(addresses[2:], ",")
	}
	control := data[offset]
	offset++
	f.Fields["control"] = fmt.Sprintf("0x%02x", control)
	var next gopacket.Decoder
	if control&0xef == 3 {
		if offset == len(data) {
			return badLink("AX.25 UI protocol identifier missing")
		}
		pid := data[offset]
		offset++
		f.Fields["pid"] = fmt.Sprintf("0x%02x", pid)
		if pid == 0xcc && offset < len(data) && data[offset]>>4 == 4 {
			f.PayloadProtocol, next = "IPv4", layers.LayerTypeIPv4
		}
	} else {
		f.Qualifications = append(f.Qualifications, "AX25-control-mode-not-inferred")
	}
	return finishBusFrame(data, offset, f, p, next)
}

func decodeBACnetMSTP(data []byte, p gopacket.PacketBuilder) error {
	if len(data) < 8 || data[0] != 0x55 || data[1] != 0xff {
		return badLink("short or invalid BACnet MS/TP preamble/header")
	}
	length := int(binary.BigEndian.Uint16(data[5:7]))
	trailer := 0
	if length > 0 && data[2] <= 7 {
		trailer = 2
	}
	if length+trailer > len(data)-8 {
		p.SetTruncated()
		return badLink("BACnet MS/TP data length exceeds packet")
	}
	f := busFrame(165, "BACnet MS/TP")
	f.Source, f.Destination = strconv.Itoa(int(data[4])), strconv.Itoa(int(data[3]))
	f.Fields["frame_type"], f.Fields["declared_payload_length"] = strconv.Itoa(int(data[2])), strconv.Itoa(length)
	f.Fields["header_crc"] = fmt.Sprintf("0x%02x", data[7])
	f.Qualifications = append(f.Qualifications, "MS/TP-CRC-not-verified")
	if data[2] > 7 { f.Qualifications = append(f.Qualifications, "extended-or-proprietary-MS/TP-body-opaque") }
	if len(data) != 8+length+trailer {
		f.Qualifications = append(f.Qualifications, "trailing-capture-bytes")
	}
	if trailer != 0 {
		f.Fields["data_crc"] = fmt.Sprintf("0x%04x", binary.LittleEndian.Uint16(data[8+length:]))
	}
	return finishBusFrame(data, 8, f, p, nil)
}

func decodeMDB(data []byte, p gopacket.PacketBuilder) error {
	if len(data) < 2 || data[0] != 0 {
		return badLink("short or unsupported MDB pseudo-header")
	}
	f := busFrame(300, "MDB")
	f.Fields["event"] = fmt.Sprintf("0x%02x", data[1])
	header := 2
	switch data[1] {
	case 0xfd:
		f.PayloadProtocol = "bus-reset"
	case 0xff:
		if len(data) < 3 {
			return badLink("MDB master transfer lacks an address byte")
		}
		f.Source, f.Destination = "VMC", fmt.Sprintf("0x%02x", data[2]&0xf8)
		f.Fields["command"] = strconv.Itoa(int(data[2] & 7))
		if len(data) == 3 && (data[2] == 0 || data[2] == 0xaa || data[2] == 0xff) {
			f.Destination = ""
			f.Fields["control_reply"] = fmt.Sprintf("0x%02x", data[2])
			f.Qualifications = append(f.Qualifications, "peripheral-address-not-inferred")
		}
	case 0xfe:
		if len(data) < 4 {
			return badLink("MDB peripheral transfer lacks address or reply")
		}
		f.Source, f.Destination, header = fmt.Sprintf("0x%02x", data[2]&0xf8), "VMC", 3
	default:
		return badLink("unknown MDB event")
	}
	if len(data)-header > 1 && data[1] != 0xfd {
		var sum byte
		for _, value := range data[header : len(data)-1] {
			sum += value
		}
		f.Fields["checksum_valid"] = strconv.FormatBool(sum == data[len(data)-1])
	}
	return finishBusFrame(data, header, f, p, nil)
}
