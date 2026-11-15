package packetview

import (
	"encoding/binary"

	"github.com/dreadl0ck/netcap/types"
	"github.com/gopacket/gopacket/layers"
)

func mobileTunnel(u *layers.UDP, port uint16, makeTunnel func(string) *types.Encapsulation) (*types.Encapsulation, []byte, uint16, error) {
	data := u.Payload
	var t *types.Encapsulation
	var payload []byte
	var protocol uint16
	var err error
	switch port {
	case 2152:
		if len(data) < 2 || data[0]&0xf8 != 0x30 {
			return nil, nil, 0, nil
		}
		// Echo and control messages are not user-plane IP datagrams.
		if len(data) >= 2 && data[1] != 0xff {
			return nil, nil, 0, nil
		}
		t = makeTunnel("gtpu")
		payload, t.Identifier, err = gtpuPayload(data)
	case 3544:
		if len(data) == 0 || data[0]>>4 != 6 && (len(data) < 2 || binary.BigEndian.Uint16(data) > 1) {
			return nil, nil, 0, nil
		}
		t = makeTunnel("teredo")
		payload, err = teredoPayload(data)
		protocol = 0x86dd
	case 1701:
		if len(data) >= 2 && binary.BigEndian.Uint16(data)&15 != 2 {
			return nil, nil, 0, nil
		}
		if len(data) >= 2 && binary.BigEndian.Uint16(data)&0x8000 != 0 {
			return nil, nil, 0, nil
		}
		t = makeTunnel("l2tpv2")
		payload, protocol, t.Identifier, err = l2tpPayload(data)
	default:
		return nil, nil, 0, nil
	}
	t.SrcPort, t.DstPort = uint32(u.SrcPort), uint32(u.DstPort)
	if err != nil {
		return t, nil, 0, err
	}
	if protocol == 0 {
		if len(payload) == 0 {
			return t, nil, 0, errMalformed
		}
		switch payload[0] >> 4 {
		case 4:
			protocol = 0x0800
		case 6:
			protocol = 0x86dd
		default:
			return t, nil, 0, errMalformed
		}
	}
	return t, payload, protocol, nil
}

func gtpuPayload(data []byte) ([]byte, uint32, error) {
	if len(data) < 8 || data[0]&0xf8 != 0x30 || data[1] != 0xff || int(binary.BigEndian.Uint16(data[2:4])) != len(data)-8 {
		return nil, 0, errMalformed
	}
	id := binary.BigEndian.Uint32(data[4:8])
	pos := 8
	next := byte(0)
	if data[0]&7 != 0 {
		if len(data) < 12 {
			return nil, id, errMalformed
		}
		pos = 12
		if data[0]&4 != 0 {
			next = data[11]
		} else if data[11] != 0 {
			return nil, id, errMalformed
		}
	}
	for depth := 0; next != 0; depth++ {
		if depth >= 16 || pos >= len(data) {
			return nil, id, errMalformed
		}
		size := int(data[pos]) * 4
		if size < 4 || size > len(data)-pos {
			return nil, id, errMalformed
		}
		next = data[pos+size-1]
		pos += size
	}
	return data[pos:], id, nil
}

func teredoPayload(data []byte) ([]byte, error) {
	if len(data) >= 2 && binary.BigEndian.Uint16(data) == 1 {
		if len(data) < 4 {
			return nil, errMalformed
		}
		size := 13 + int(data[2]) + int(data[3])
		if size > len(data) {
			return nil, errMalformed
		}
		data = data[size:]
	}
	if len(data) >= 2 && binary.BigEndian.Uint16(data) == 0 {
		if len(data) < 8 {
			return nil, errMalformed
		}
		data = data[8:]
	}
	if len(data) < 40 || data[0]>>4 != 6 {
		return nil, errMalformed
	}
	return data, nil
}

func l2tpPayload(data []byte) ([]byte, uint16, uint32, error) {
	if len(data) < 6 {
		return nil, 0, 0, errMalformed
	}
	flags := binary.BigEndian.Uint16(data)
	if flags&0xb4f0 != 0 || flags&15 != 2 {
		return nil, 0, 0, errMalformed
	}
	pos := 2
	if flags&0x4000 != 0 {
		if len(data) < 8 || int(binary.BigEndian.Uint16(data[2:4])) != len(data) {
			return nil, 0, 0, errMalformed
		}
		pos += 2
	}
	if pos+4 > len(data) {
		return nil, 0, 0, errMalformed
	}
	id := binary.BigEndian.Uint32(data[pos : pos+4])
	pos += 4
	if flags&0x0800 != 0 {
		pos += 4
	}
	if flags&0x0200 != 0 {
		if pos+2 > len(data) {
			return nil, 0, id, errMalformed
		}
		size := int(binary.BigEndian.Uint16(data[pos : pos+2]))
		pos += 2 + size
	}
	if pos >= len(data) {
		return nil, 0, id, errMalformed
	}
	data = data[pos:]
	if len(data) >= 2 && data[0] == 0xff && data[1] == 3 {
		data = data[2:]
	}
	if len(data) == 0 {
		return nil, 0, id, errMalformed
	}
	protocol := uint16(data[0])
	pos = 1
	if protocol&1 == 0 {
		if len(data) < 2 {
			return nil, 0, id, errMalformed
		}
		protocol = binary.BigEndian.Uint16(data)
		pos = 2
	}
	switch protocol {
	case 0x21:
		protocol = 0x0800
	case 0x57:
		protocol = 0x86dd
	default:
		return nil, 0, id, errMalformed
	}
	return data[pos:], protocol, id, nil
}
