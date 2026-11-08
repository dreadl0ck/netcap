package smb

import (
	"bytes"
	"encoding/binary"
)

func probeSMB(data []byte) bool {
	for len(data) >= 4 {
		n := int(data[1])<<16 | int(data[2])<<8 | int(data[3])
		switch data[0] {
		case 0x81: // NetBIOS session request: encoded called/calling names.
			if n != 68 || len(data) < 72 || data[4] != 32 || data[38] != 32 || data[37] != 0 || data[71] != 0 {
				return false
			}
			for _, name := range [][]byte{data[5:37], data[39:71]} {
				for _, b := range name {
					if b < 'A' || b > 'P' {
						return false
					}
				}
			}
		case 0x82, 0x85: // Positive session response / keepalive.
			if n != 0 {
				return false
			}
		case 0:
			body := data[4:min(len(data), n+4)]
			if n >= 64 && len(body) >= 20 && bytes.HasPrefix(body, []byte(SMB2Signature)) {
				return binary.LittleEndian.Uint16(body[4:6]) == 64 && binary.LittleEndian.Uint16(body[12:14]) <= 0x12
			}
			return n >= 32 && len(body) >= 24 && bytes.HasPrefix(body, []byte(SMB1Signature)) && body[22] == 0 && body[23] == 0
		default:
			return false
		}
		data = data[n+4:]
	}
	return false
}
