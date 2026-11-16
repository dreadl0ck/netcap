package rohc

import (
	"encoding/binary"
	"fmt"
)

type Context struct {
	Version                     byte
	Source, Destination         [16]byte
	SourcePort, DestinationPort uint16
	Flow                        uint32
	Traffic, Hop, Flags         byte
	ID, Checksum, SN            uint16
	Static, Dynamic             bool
}

// CRC uses the reflected ROHC polynomial and no final complement (RFC 3095 5.9).
func CRC(data []byte, width uint) byte {
	polynomial := map[uint]byte{3: 6, 7: 0x79, 8: 0xe0}[width]
	value := byte((1 << width) - 1)
	for _, b := range data {
		value ^= b
		for range 8 {
			bit := value & 1
			value >>= 1
			if bit != 0 {
				value ^= polynomial
			}
		}
	}
	return value
}

func Static(data []byte) (Context, int, error) {
	var c Context
	if len(data) == 0 {
		return c, 0, fmt.Errorf("ROHC static chain missing")
	}
	c.Version = data[0] >> 4
	length := 14
	switch c.Version {
	case 4:
		if len(data) < length || data[1] != 17 || data[0]&15 != 0 {
			return c, 0, fmt.Errorf("unsupported ROHC IPv4 static chain")
		}
		copy(c.Source[:4], data[2:6])
		copy(c.Destination[:4], data[6:10])
		c.SourcePort = binary.BigEndian.Uint16(data[10:])
		c.DestinationPort = binary.BigEndian.Uint16(data[12:])
	case 6:
		length = 40
		if len(data) < length || data[3] != 17 {
			return c, 0, fmt.Errorf("unsupported ROHC IPv6 static chain")
		}
		c.Flow = uint32(data[0]&15)<<16 | uint32(data[1])<<8 | uint32(data[2])
		copy(c.Source[:], data[4:20])
		copy(c.Destination[:], data[20:36])
		c.SourcePort = binary.BigEndian.Uint16(data[36:])
		c.DestinationPort = binary.BigEndian.Uint16(data[38:])
	default:
		return c, 0, fmt.Errorf("unsupported ROHC IP static version")
	}
	c.Static = true
	return c, length, nil
}

func Dynamic(c Context, data []byte) (Context, int, error) {
	n := 10
	if c.Version == 6 {
		n = 7
	}
	if !c.Static || len(data) < n {
		return c, 0, fmt.Errorf("ROHC dynamic chain is short or lacks static context")
	}
	c.Traffic, c.Hop = data[0], data[1]
	index := 3
	if c.Version == 4 {
		c.ID = binary.BigEndian.Uint16(data[2:])
		c.Flags = data[4]
		index = 6
		if data[5] != 0 {
			return c, 0, fmt.Errorf("ROHC extension list not supported")
		}
	} else if data[2] != 0 {
		return c, 0, fmt.Errorf("ROHC extension list not supported")
	}
	c.Checksum = binary.BigEndian.Uint16(data[index:])
	c.SN = binary.BigEndian.Uint16(data[index+2:])
	c.Dynamic = true
	return c, n, nil
}

func lsb(reference, encoded uint16, bits uint) uint16 {
	mask := uint16((1 << bits) - 1)
	first := reference + 1
	return first + ((encoded - (first & mask)) & mask)
}
func swap(value uint16) uint16 { return value<<8 | value>>8 }

// DecodeUDP takes the original wire header so CID octets remain CRC-covered.
// first points to the packet-type octet; afterCID points past an optional large CID.
func DecodeUDP(previous Context, wire []byte, first, afterCID int) (Context, []byte, error) {
	if first < 0 || first >= len(wire) || afterCID < first+1 || afterCID > len(wire) {
		return previous, nil, fmt.Errorf("invalid ROHC CID boundary")
	}
	kind := wire[first]
	c := previous
	offset := afterCID
	if kind&0xfe == 0xfc || kind == 0xf8 {
		if len(wire)-offset < 2 || wire[offset] != 2 {
			return previous, nil, fmt.Errorf("unsupported ROHC profile")
		}
		crcOffset := offset + 1
		offset += 2
		var err error
		var n int
		if kind&0xfe == 0xfc {
			c, n, err = Static(wire[offset:])
			if err != nil {
				return previous, nil, err
			}
			offset += n
		}
		if kind == 0xf8 || kind&1 != 0 {
			c, n, err = Dynamic(c, wire[offset:])
			if err != nil {
				return previous, nil, err
			}
			offset += n
		}
		header := append([]byte(nil), wire[:offset]...)
		header[crcOffset] = 0
		if CRC(header, 8) != wire[crcOffset] {
			return previous, nil, fmt.Errorf("invalid ROHC IR CRC8")
		}
		if !c.Dynamic || offset == len(wire) {
			return c, nil, nil
		}
		packet, err := c.packet(wire[offset:])
		if err != nil {
			return previous, nil, err
		}
		return c, packet, nil
	}
	if !c.Static || !c.Dynamic {
		return previous, nil, fmt.Errorf("ROHC compressed packet lacks full context")
	}
	if c.Version == 4 && c.Flags&0x40 != 0 {
		return previous, nil, fmt.Errorf("ROHC random IP-ID not supported")
	}
	var snBits uint
	var encodedSN, idBits uint16
	var idWidth uint
	var checksum byte
	var crcWidth uint
	switch {
	case kind&0x80 == 0:
		snBits = 4
		encodedSN = uint16(kind >> 3 & 15)
		checksum = kind & 7
		crcWidth = 3
	case kind&0xc0 == 0x80:
		if offset == len(wire) {
			return previous, nil, fmt.Errorf("short ROHC UO-1")
		}
		snBits = 5
		encodedSN = uint16(wire[offset] >> 3)
		checksum = wire[offset] & 7
		crcWidth = 3
		idBits = uint16(kind & 63)
		idWidth = 6
		offset++
	case kind&0xe0 == 0xc0:
		if offset == len(wire) {
			return previous, nil, fmt.Errorf("short ROHC UOR-2")
		}
		extended := wire[offset]&0x80 != 0
		snBits = 5
		encodedSN = uint16(kind & 31)
		checksum = wire[offset] & 127
		crcWidth = 7
		offset++
		if extended {
			if offset == len(wire) {
				return previous, nil, fmt.Errorf("ROHC extension missing")
			}
			extension := wire[offset]
			offset++
			if extension>>6 > 1 {
				return previous, nil, fmt.Errorf("ROHC extension 2/3 not supported")
			}
			encodedSN = encodedSN<<3 | uint16(extension>>3&7)
			snBits += 3
			idBits = uint16(extension & 7)
			idWidth = 3
			if extension>>6 == 1 {
				if offset == len(wire) {
					return previous, nil, fmt.Errorf("short ROHC extension 1")
				}
				idBits = idBits<<8 | uint16(wire[offset])
				idWidth = 11
				offset++
			}
		}
	default:
		return previous, nil, fmt.Errorf("ROHC packet type not supported")
	}
	c.SN = lsb(previous.SN, encodedSN, snBits)
	if c.Version == 4 {
		id := previous.ID
		if c.Flags&0x20 == 0 {
			id = swap(id)
		}
		difference := id - previous.SN
		if idWidth > 0 {
			mask := uint16((1 << idWidth) - 1)
			difference = (difference &^ mask) | idBits
			if int16(difference-(id-previous.SN)) > int16(1<<(idWidth-1)) {
				difference -= 1 << idWidth
			} else if int16(difference-(id-previous.SN)) < -int16(1<<(idWidth-1)) {
				difference += 1 << idWidth
			}
		}
		if c.Flags&0x80 != 0 && previous.ID == 0 {
			c.ID = 0
		} else {
			c.ID = c.SN + difference
			if c.Flags&0x20 == 0 {
				c.ID = swap(c.ID)
			}
		}
	}
	if previous.Checksum != 0 {
		if len(wire)-offset < 2 {
			return previous, nil, fmt.Errorf("ROHC UDP checksum missing")
		}
		c.Checksum = binary.BigEndian.Uint16(wire[offset:])
		offset += 2
	}
	packet, err := c.packet(wire[offset:])
	if err != nil {
		return previous, nil, err
	}
	if CRC(crcHeader(packet, c.Version), crcWidth) != checksum {
		return previous, nil, fmt.Errorf("invalid ROHC compressed-header CRC")
	}
	return c, packet, nil
}

func (c Context) packet(payload []byte) ([]byte, error) {
	header := 20
	if c.Version == 6 {
		header = 40
	}
	if len(payload) > 65535-header-8 || c.Version == 6 && c.Checksum == 0 {
		return nil, fmt.Errorf("invalid ROHC expanded UDP length/checksum")
	}
	out := make([]byte, header+8+len(payload))
	if c.Version == 4 {
		out[0], out[1], out[8], out[9] = 0x45, c.Traffic, c.Hop, 17
		binary.BigEndian.PutUint16(out[2:], uint16(len(out)))
		binary.BigEndian.PutUint16(out[4:], c.ID)
		if c.Flags&0x80 != 0 {
			out[6] = 0x40
		}
		copy(out[12:16], c.Source[:4])
		copy(out[16:20], c.Destination[:4])
		binary.BigEndian.PutUint16(out[10:], ipChecksum(out[:20]))
	} else {
		binary.BigEndian.PutUint32(out, 0x60000000|uint32(c.Traffic)<<20|c.Flow)
		binary.BigEndian.PutUint16(out[4:], uint16(len(out)-40))
		out[6], out[7] = 17, c.Hop
		copy(out[8:24], c.Source[:])
		copy(out[24:40], c.Destination[:])
	}
	udp := out[header:]
	binary.BigEndian.PutUint16(udp, c.SourcePort)
	binary.BigEndian.PutUint16(udp[2:], c.DestinationPort)
	binary.BigEndian.PutUint16(udp[4:], uint16(len(udp)))
	binary.BigEndian.PutUint16(udp[6:], c.Checksum)
	copy(udp[8:], payload)
	return out, nil
}

func ipChecksum(data []byte) uint16 {
	var sum uint32
	for len(data) >= 2 {
		sum += uint32(binary.BigEndian.Uint16(data))
		data = data[2:]
	}
	for sum>>16 != 0 {
		sum = (sum & 65535) + (sum >> 16)
	}
	return ^uint16(sum)
}
func crcHeader(packet []byte, version byte) []byte {
	var out []byte
	if version == 4 {
		out = append(out, packet[:2]...)
		out = append(out, packet[6:10]...)
		out = append(out, packet[12:24]...)
		out = append(out, packet[2:6]...)
		out = append(out, packet[10:12]...)
		out = append(out, packet[24:28]...)
	} else {
		out = append(out, packet[:4]...)
		out = append(out, packet[6:44]...)
		out = append(out, packet[4:6]...)
		out = append(out, packet[44:48]...)
	}
	return out
}
