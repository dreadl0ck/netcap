package modbus

import (
	"encoding/binary"
	"fmt"

	"github.com/dreadl0ck/netcap/types"
)

func word(b []byte) uint32 { return uint32(binary.BigEndian.Uint16(b)) }

func words(b []byte) []uint32 {
	v := make([]uint32, len(b)/2)
	for i := range v {
		v[i] = word(b[2*i:])
	}
	return v
}

func validRange(address, quantity, max uint32) bool {
	return quantity > 0 && quantity <= max && address+quantity <= 65536
}

// parsePDU consumes a complete PDU, independently of framing and payload capture.
// Unknown roles are inferred only when exactly one wire layout is valid.
func parsePDU(pdu []byte, role string) *types.Modbus {
	if role == "unknown" || role == "" {
		if len(pdu) > 0 && pdu[0]&0x80 != 0 {
			return parsePDU(pdu, "response")
		}
		req, res := parsePDU(pdu, "request"), parsePDU(pdu, "response")
		if req.ParseStatus == "valid" && res.ParseStatus != "valid" {
			return req
		}
		if res.ParseStatus == "valid" && req.ParseStatus != "valid" {
			return res
		}
		if req.ParseStatus == "valid" && res.ParseStatus == "valid" {
			switch req.FunctionCode {
			case 1, 2, 3, 4, 20:
				return &types.Modbus{FunctionCode: req.FunctionCode, Bank: req.Bank,
					MessageRole: "unknown", ParseStatus: "valid", CorrelationStatus: "not_applicable"}
			}
		}
		req.MessageRole = "unknown"
		return req
	}
	m := &types.Modbus{MessageRole: role, ParseStatus: "valid", CorrelationStatus: "not_applicable"}
	bad := func(reason string) *types.Modbus {
		// Never publish partially decoded values from an invalid PDU.
		return &types.Modbus{FunctionCode: m.FunctionCode, Exception: m.Exception,
			MessageRole: role, ParseStatus: "malformed", ParseError: reason, CorrelationStatus: "not_applicable"}
	}
	if len(pdu) < 1 || len(pdu) > maxPDUSize {
		return bad("PDU length outside 1..253")
	}
	f := pdu[0] & 0x7f
	m.FunctionCode, m.Exception = int32(f), pdu[0]&0x80 != 0
	switch f {
	case 1, 5, 15:
		m.Bank = "coils"
	case 2:
		m.Bank = "discrete_inputs"
	case 3, 6, 16, 22, 23:
		m.Bank = "holding_registers"
	case 4:
		m.Bank = "input_registers"
	case 20, 21:
		m.Bank = "file_records"
	}
	if m.Exception {
		if role != "response" || len(pdu) != 2 || pdu[1] == 0 {
			return bad("invalid exception PDU")
		}
		m.ExceptionCode = uint32(pdu[1])
		return m
	}
	b := pdu[1:]
	request := role == "request"
	switch f {
	case 1, 2, 3, 4:
		if request {
			if len(b) != 4 {
				return bad("read request requires address and quantity")
			}
			m.HasAddress, m.Address, m.Quantity = true, word(b), word(b[2:])
			max := uint32(125)
			if f <= 2 {
				max = 2000
			}
			if !validRange(m.Address, m.Quantity, max) {
				return bad("invalid read range")
			}
		} else {
			if len(b) < 2 || int(b[0]) != len(b)-1 || b[0] > 250 {
				return bad("invalid read byte count")
			}
			if f <= 2 {
				for _, v := range b[1:] {
					for bit := 0; bit < 8; bit++ {
						m.Values = append(m.Values, uint32(v>>bit&1))
					}
				}
				// Without a request, trailing padding bits cannot be distinguished.
			} else {
				if b[0]%2 != 0 {
					return bad("odd register byte count")
				}
				m.Values = words(b[1:])
				m.Quantity = uint32(len(m.Values))
			}
		}
	case 5, 6:
		if len(b) != 4 {
			return bad("single write requires address and value")
		}
		m.HasAddress, m.Address, m.Quantity = true, word(b), 1
		v := word(b[2:])
		if f == 5 {
			if v != 0 && v != 0xff00 {
				return bad("coil value must be 0000 or FF00")
			}
			v >>= 15
		}
		m.Values = []uint32{v}
	case 15, 16:
		if len(b) < 4 {
			return bad("short multiple write")
		}
		m.HasAddress, m.Address, m.Quantity = true, word(b), word(b[2:])
		max := uint32(123)
		if f == 15 {
			max = 1968
		}
		if !validRange(m.Address, m.Quantity, max) {
			return bad("invalid write range")
		}
		if !request {
			if len(b) != 4 {
				return bad("write response must echo address and quantity")
			}
			break
		}
		count := int(m.Quantity) * 2
		if f == 15 {
			count = int((m.Quantity + 7) / 8)
		}
		if len(b) != 5+count || int(b[4]) != count {
			return bad("invalid write byte count")
		}
		if f == 15 {
			if n := m.Quantity % 8; n != 0 && b[len(b)-1]>>n != 0 {
				return bad("nonzero coil padding")
			}
			for i := uint32(0); i < m.Quantity; i++ {
				m.Values = append(m.Values, uint32(b[5+i/8]>>(i%8)&1))
			}
		} else {
			m.Values = words(b[5:])
		}
	case 22:
		if len(b) != 6 {
			return bad("mask write requires address and two masks")
		}
		m.HasAddress, m.Address, m.Quantity = true, word(b), 1
		m.AndMask, m.OrMask = word(b[2:]), word(b[4:])
	case 23:
		if request {
			if len(b) < 9 {
				return bad("short read/write request")
			}
			m.HasReadAddress, m.ReadAddress, m.ReadQuantity = true, word(b), word(b[2:])
			m.HasWriteAddress, m.WriteAddress, m.WriteQuantity = true, word(b[4:]), word(b[6:])
			if !validRange(m.ReadAddress, m.ReadQuantity, 125) || !validRange(m.WriteAddress, m.WriteQuantity, 121) {
				return bad("invalid read/write range")
			}
			if int(b[8]) != int(m.WriteQuantity)*2 || len(b) != 9+int(b[8]) {
				return bad("invalid read/write byte count")
			}
			m.WriteValues = words(b[9:])
		} else {
			if len(b) < 3 || b[0] == 0 || b[0] > 250 || b[0]%2 != 0 || len(b) != 1+int(b[0]) {
				return bad("invalid read/write response count")
			}
			m.Values = words(b[1:])
			m.ReadQuantity = uint32(len(m.Values))
		}
	case 8:
		if len(b) < 4 || len(b)%2 != 0 {
			return bad("diagnostic requires subfunction and word data")
		}
		m.HasDiagnostic, m.DiagnosticSubfunction = true, word(b)
		if m.DiagnosticSubfunction != 0 && len(b) != 4 {
			return bad("diagnostic subfunction requires one data word")
		}
		m.DiagnosticData = append([]byte(nil), b[2:]...)
	case 20, 21:
		if len(b) < 2 || int(b[0]) != len(b)-1 || b[0] > 251 {
			return bad("invalid file record byte count")
		}
		for rest := b[1:]; len(rest) > 0; {
			r := &types.ModbusFileRecord{}
			if f == 20 && !request {
				if len(rest) < 2 || rest[0] < 3 || rest[0]%2 != 1 || int(rest[0])+1 > len(rest) || rest[1] != 6 {
					return bad("invalid file read subresponse")
				}
				n := int(rest[0]) + 1
				r.ReferenceType, r.RecordLength, r.Values = 6, uint32((n-2)/2), words(rest[2:n])
				rest = rest[n:]
			} else {
				if len(rest) < 7 || rest[0] != 6 {
					return bad("invalid file record header")
				}
				r.ReferenceType, r.FileNumber, r.RecordNumber, r.RecordLength = 6, word(rest[1:]), word(rest[3:]), word(rest[5:])
				if r.FileNumber == 0 || r.RecordNumber > 9999 || !validRange(r.RecordNumber, r.RecordLength, 125) {
					return bad("invalid file record range")
				}
				n := 7
				if f == 21 {
					n += int(r.RecordLength) * 2
					if n > len(rest) {
						return bad("short file record values")
					}
					r.Values = words(rest[7:n])
				}
				rest = rest[n:]
			}
			m.FileRecords = append(m.FileRecords, r)
		}
		if f == 20 && request {
			size := 2
			for _, r := range m.FileRecords {
				size += 2 + 2*int(r.RecordLength)
			}
			if size > maxPDUSize {
				return bad("file read response exceeds maximum PDU")
			}
		}
	case 43:
		if len(b) == 0 {
			return bad("missing MEI type")
		}
		m.MEIType = uint32(b[0])
		if b[0] != 14 {
			m.ParseStatus = "unsupported"
			m.ParseError = fmt.Sprintf("unsupported MEI type %d", b[0])
			break
		}
		if len(b) < 3 || b[1] < 1 || b[1] > 4 {
			return bad("invalid device identification code")
		}
		m.ReadDeviceIDCode = uint32(b[1])
		if request {
			if len(b) != 3 {
				return bad("invalid device identification request length")
			}
			m.DeviceIDObjectID = uint32(b[2])
		} else {
			if len(b) < 6 || (b[2]&0x7f) < 1 || (b[2]&0x7f) > 3 || (b[3] != 0 && b[3] != 255) {
				return bad("invalid device identification response header")
			}
			m.DeviceIDConformityLevel, m.DeviceIDMoreFollows, m.DeviceIDNextObjectID = uint32(b[2]), b[3] == 255, uint32(b[4])
			rest := b[6:]
			last := -1
			for i := 0; i < int(b[5]); i++ {
				if len(rest) < 2 || len(rest) < 2+int(rest[1]) || int(rest[0]) <= last {
					return bad("invalid device identification object")
				}
				n := 2 + int(rest[1])
				last = int(rest[0])
				m.DeviceIDObjects = append(m.DeviceIDObjects, &types.ModbusDeviceIDObject{ID: uint32(rest[0]), Value: append([]byte(nil), rest[2:n]...)})
				rest = rest[n:]
			}
			if len(rest) != 0 {
				return bad("trailing device identification bytes")
			}
			if b[1] == 4 && (b[5] != 1 || b[3] != 0 || b[4] != 0) {
				return bad("invalid individual device identification response")
			}
		}
	default:
		m.ParseStatus = "unsupported"
		m.ParseError = fmt.Sprintf("unsupported function %d", f)
	}
	return m
}
