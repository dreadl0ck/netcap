package collector

import (
	"encoding/binary"
	"strconv"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

func decodeALP(data []byte, p gopacket.PacketBuilder) error {
	if len(data) < 1 {
		return badLink("empty ATSC ALP header")
	}
	f := busFrame(289, "ATSC ALP")
	packetType := data[0] >> 5
	f.Fields["packet_type"] = strconv.Itoa(int(packetType))
	if packetType == 7 {
		header, count, deleted, hdm := 1, int(data[0]>>1&15), 0, false
		if count == 0 {
			count = 16
		}
		if data[0]&1 != 0 {
			if len(data) < 2 {
				return badLink("short ALP MPEG-TS additional header")
			}
			header, deleted, hdm = 2, int(data[1]&0x7f), data[1]&0x80 != 0
			if !hdm && deleted == 0 {
				deleted = 128
			}
		}
		unit := 187
		if hdm {
			unit = 184
		}
		length := 187 + (count-1)*unit
		if length > len(data)-header {
			p.SetTruncated()
			return badLink("ALP compressed TS data exceeds packet")
		}
		f.Fields["ts_packets"], f.Fields["deleted_null_packets"], f.Fields["header_deletion"] = strconv.Itoa(count), strconv.Itoa(deleted), strconv.FormatBool(hdm)
		f.Qualifications = append(f.Qualifications, "TS-reconstruction-not-performed")
		return finishBusFrame(data, header, f, p, nil)
	}
	if len(data) < 2 {
		return badLink("short ALP base header")
	}
	configuration := data[0]&0x10 != 0
	header, length, sif, hef := 2, int(binary.BigEndian.Uint16(data[:2])&0x7ff), false, false
	f.Fields["payload_configuration"] = strconv.FormatBool(configuration)
	if data[0]&8 != 0 || configuration {
		if len(data) < 3 {
			return badLink("short ALP extended base header")
		}
		header = 3
		if !configuration {
			length = int((uint32(data[0])<<16|uint32(data[1])<<8|uint32(data[2]))&0x07fff8) >> 3
			sif, hef = data[2]&2 != 0, data[2]&1 != 0
		} else if data[0]&8 == 0 {
			sif, hef = data[2]&2 != 0, data[2]&1 != 0
			f.Fields["segment_sequence"], f.Fields["last_segment"] = strconv.Itoa(int(data[2]>>3)), strconv.FormatBool(data[2]&4 != 0)
			f.Qualifications = append(f.Qualifications, "ALP-segment-reassembly-not-performed")
		} else {
			length = int((uint32(data[0])<<16|uint32(data[1])<<8|uint32(data[2]))&0x07fff0) >> 4
			count := int(data[2] >> 1 & 7)
			header += (count*12 + 7) / 8
			sif = data[2]&1 != 0
			f.Fields["concatenation_count"] = strconv.Itoa(count)
			f.Qualifications = append(f.Qualifications, "ALP-concatenated-packets-not-split")
		}
	}
	if header > len(data) {
		return badLink("ALP concatenation header exceeds packet")
	}
	if sif {
		if header == len(data) {
			return badLink("ALP substream identifier missing")
		}
		f.Fields["substream_id"] = strconv.Itoa(int(data[header]))
		header++
	}
	if hef {
		if len(data)-header < 2 {
			return badLink("short ALP header extension")
		}
		size := int(data[header+1]) + 1
		f.Fields["extension_type"], f.Fields["extension_length"] = strconv.Itoa(int(data[header])), strconv.Itoa(size)
		header += 2 + size
	}
	if packetType == 4 {
		header += 5
		f.Qualifications = append(f.Qualifications, "ALP-signalling-not-decoded")
	}
	if header > len(data) || length > len(data)-header {
		p.SetTruncated()
		return badLink("ALP header/payload length exceeds packet")
	}
	f.Fields["declared_payload_length"] = strconv.Itoa(length)
	if len(data)-header != length {
		f.Qualifications = append(f.Qualifications, "trailing-capture-bytes")
	}
	var next gopacket.Decoder
	if packetType == 0 && !configuration && length > 0 {
		if data[header]>>4 != 4 {
			return badLink("ALP IPv4 payload has a different version")
		}
		f.PayloadProtocol, next = "IPv4", layers.LayerTypeIPv4
	}
	return finishBusFrame(data, header, f, p, next)
}
