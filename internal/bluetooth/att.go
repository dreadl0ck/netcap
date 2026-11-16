package bluetooth

import (
	"encoding/binary"
	"encoding/hex"
)

func decodeATT(data []byte) Event {
	e := Event{Protocol: "ATT", Fields: map[string]any{}}
	bad := func() Event { e.Qualifications = []string{"invalid-ATT-length-or-format"}; return e }
	if len(data) == 0 || len(data) > 517 {
		return bad()
	}
	op := data[0]
	body := data[1:]
	e.Fields["Opcode"], e.Fields["Command"], e.Fields["Signed"] = op, op&0x40 != 0, op&0x80 != 0
	if op == 0xd2 {
		e.Qualifications = append(e.Qualifications, "ATT-signature-not-verified")
	}
	handle := func() { e.Fields["Handle"] = binary.LittleEndian.Uint16(body) }
	switch op {
	case 1:
		if len(body) != 4 {
			return bad()
		}
		e.Fields["RequestOpcode"], e.Fields["Handle"], e.Fields["ErrorCode"] = body[0], binary.LittleEndian.Uint16(body[1:]), body[3]
	case 2, 3:
		if len(body) != 2 {
			return bad()
		}
		mtu := binary.LittleEndian.Uint16(body)
		if mtu < 23 || mtu > 517 {
			return bad()
		}
		e.Fields["MTU"] = mtu
	case 4, 6, 8, 0x10:
		if len(body) < 4 {
			return bad()
		}
		start, end := binary.LittleEndian.Uint16(body), binary.LittleEndian.Uint16(body[2:])
		if start == 0 || end < start {
			return bad()
		}
		e.Fields["StartHandle"], e.Fields["EndHandle"] = start, end
		if op == 8 || op == 0x10 {
			if len(body) != 6 && len(body) != 20 {
				return bad()
			}
			e.Fields["UUIDLittleEndian"] = hex.EncodeToString(body[4:])
		}
		if op == 4 && len(body) != 4 || op == 6 && len(body) < 6 {
			return bad()
		}
	case 5:
		if len(body) < 1 {
			return bad()
		}
		size := 4
		if body[0] == 2 {
			size = 18
		} else if body[0] != 1 {
			return bad()
		}
		body = body[1:]
		if len(body) == 0 || len(body)%size != 0 || len(body)/size > 256 {
			return bad()
		}
		var entries []map[string]any
		for len(body) > 0 {
			entries = append(entries, map[string]any{"Handle": binary.LittleEndian.Uint16(body), "UUIDLittleEndian": hex.EncodeToString(body[2:size])})
			body = body[size:]
		}
		e.Fields["Attributes"] = entries
	case 7:
		if len(body) == 0 || len(body)%4 != 0 || len(body) > 1024 {
			return bad()
		}
		e.Fields["HandlePairCount"] = len(body) / 4
	case 9, 0x11:
		if len(body) < 1 {
			return bad()
		}
		size := int(body[0])
		body = body[1:]
		minimum := 2
		if op == 0x11 {
			minimum = 4
		}
		if size < minimum || len(body) == 0 || len(body)%size != 0 || len(body)/size > 256 {
			return bad()
		}
		var handles []uint16
		for offset := 0; offset < len(body); offset += size {
			handles = append(handles, binary.LittleEndian.Uint16(body[offset:]))
		}
		e.Fields["Handles"], e.Fields["EntryLength"] = handles, size
	case 0x0a:
		if len(body) != 2 {
			return bad()
		}
		handle()
	case 0x0c:
		if len(body) != 4 {
			return bad()
		}
		handle()
		e.Fields["Offset"] = binary.LittleEndian.Uint16(body[2:])
	case 0x0e:
		if len(body) < 4 || len(body)%2 != 0 || len(body) > 512 {
			return bad()
		}
		var handles []uint16
		for offset := 0; offset < len(body); offset += 2 {
			handles = append(handles, binary.LittleEndian.Uint16(body[offset:]))
		}
		e.Fields["Handles"] = handles
	case 0x12, 0x52, 0xd2, 0x1b, 0x1d:
		if len(body) < 2 || op == 0xd2 && len(body) < 14 {
			return bad()
		}
		handle()
		e.Fields["ValueLength"] = len(body) - 2
		if op == 0xd2 {
			e.Fields["ValueLength"] = len(body) - 14
		}
	case 0x16, 0x17:
		if len(body) < 4 {
			return bad()
		}
		handle()
		e.Fields["Offset"], e.Fields["ValueLength"] = binary.LittleEndian.Uint16(body[2:]), len(body)-4
	case 0x18:
		if len(body) != 1 || body[0] > 1 {
			return bad()
		}
		e.Fields["Execute"] = body[0] == 1
	case 0x13, 0x19, 0x1e:
		if len(body) != 0 {
			return bad()
		}
	case 0x0b, 0x0d, 0x0f:
		e.Fields["ValueLength"] = len(body)
	default:
		e.Qualifications = []string{"ATT-opcode-not-decoded"}
	}
	return e
}
