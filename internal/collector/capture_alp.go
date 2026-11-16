package collector

import (
	"encoding/binary"
	"strconv"

	"github.com/dreadl0ck/netcap/internal/linkaudit"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

func decodeALP(data []byte, p gopacket.PacketBuilder) error {
	if len(data) < 1 {
		return badLink("empty ATSC ALP header")
	}
	f := busFrame(289, "ATSC ALP")
	packetType := data[0] >> 5
	a := &linkaudit.ALPFrame{PacketType: packetType}
	f.ALP = a
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
		if length != len(data)-header {
			f.Qualifications = append(f.Qualifications, "trailing-capture-bytes")
		}
		a.Offset, a.Length = header, length
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
			length |= int(data[2]>>3) << 11
			sif, hef = data[2]&2 != 0, data[2]&1 != 0
		} else if data[0]&8 == 0 {
			sif, hef = data[2]&2 != 0, data[2]&1 != 0
			f.Fields["segment_sequence"], f.Fields["last_segment"] = strconv.Itoa(int(data[2]>>3)), strconv.FormatBool(data[2]&4 != 0)
			a.Segmented, a.Sequence, a.Last = true, data[2]>>3, data[2]&4 != 0
			if a.Sequence == 0 && a.Last {
				return badLink("ALP initial segment cannot be last")
			}
		} else {
			length |= int(data[2]>>4) << 11
			count := int(data[2]>>1&7) + 1
			header += (count*12 + 7) / 8
			if header > len(data) {
				return badLink("ALP component lengths exceed packet")
			}
			total := 0
			for i := 0; i < count; i++ {
				bit := i * 12
				v := int(binary.BigEndian.Uint16(data[3+bit/8:]))
				if bit%8 == 0 {
					v >>= 4
				} else {
					v &= 4095
				}
				if v == 0 || v >= length-total {
					return badLink("invalid ALP component length")
				}
				a.ComponentLengths = append(a.ComponentLengths, v)
				total += v
			}
			if count%2 != 0 && data[header-1]&15 != 0 {
				return badLink("nonzero ALP component padding")
			}
			a.ComponentLengths = append(a.ComponentLengths, length-total)
			sif = data[2]&1 != 0
			f.Fields["concatenation_count"] = strconv.Itoa(count + 1)
		}
	}
	if header > len(data) {
		return badLink("ALP concatenation header exceeds packet")
	}
	if packetType == 4 {
		if len(data)-header < 5 {
			return badLink("short ALP signalling information header")
		}
		f.Fields["signalling_type"] = strconv.Itoa(int(data[header]))
		f.Fields["signalling_type_extension"] = strconv.Itoa(int(binary.BigEndian.Uint16(data[header+1:])))
		f.Fields["signalling_version"] = strconv.Itoa(int(data[header+3]))
		f.Fields["signalling_format"] = strconv.Itoa(int(data[header+4] >> 6))
		f.Fields["signalling_encoding"] = strconv.Itoa(int(data[header+4] >> 4 & 3))
		header += 5
	} else if packetType == 6 {
		if len(data)-header < 2 {
			return badLink("short ALP type extension")
		}
		f.Fields["extended_type"] = strconv.Itoa(int(binary.BigEndian.Uint16(data[header:])))
		header += 2
	}
	if sif {
		if header == len(data) {
			return badLink("ALP substream identifier missing")
		}
		f.Fields["substream_id"] = strconv.Itoa(int(data[header]))
		a.SIDPresent, a.SID = true, data[header]
		header++
	}
	if hef {
		if len(data)-header < 2 {
			return badLink("short ALP header extension")
		}
		size := int(data[header+1]) + 1
		f.Fields["extension_type"], f.Fields["extension_length"] = strconv.Itoa(int(data[header])), strconv.Itoa(size)
		if size > len(data)-header-2 {
			return badLink("ALP extension exceeds packet")
		}
		if data[header] == 0xf1 && size == 1 {
			a.PLPPresent, a.PLP = true, data[header+2]>>2
			f.Fields["plp_id"] = strconv.Itoa(int(a.PLP))
		}
		header += 2 + size
	}
	if length == 0 || header > len(data) || length > len(data)-header {
		p.SetTruncated()
		return badLink("ALP header/payload length exceeds packet")
	}
	f.Fields["declared_payload_length"] = strconv.Itoa(length)
	a.Offset, a.Length = header, length
	if len(data)-header != length {
		f.Qualifications = append(f.Qualifications, "trailing-capture-bytes")
	}
	var next gopacket.Decoder
	if packetType == 0 && !configuration && length > 0 {
		if data[header]>>4 != 4 {
			return badLink("ALP IPv4 payload has a different version")
		}
		f.PayloadProtocol, next = "IPv4", gopacket.DecodeFunc(func(_ []byte, builder gopacket.PacketBuilder) error {
			return layers.LayerTypeIPv4.Decode(data[header:header+length], builder)
		})
	}
	return finishBusFrame(data, header, f, p, next)
}
