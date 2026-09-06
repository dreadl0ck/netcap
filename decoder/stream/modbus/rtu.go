package modbus

import (
	"encoding/binary"

	decoderconfig "github.com/dreadl0ck/netcap/decoder/config"
	"github.com/dreadl0ck/netcap/decoder/core"
	"github.com/dreadl0ck/netcap/reassembly"
	"github.com/dreadl0ck/netcap/types"
)

func crc16RTU(b []byte) uint16 {
	crc := uint16(0xffff)
	for _, v := range b {
		crc ^= uint16(v)
		for i := 0; i < 8; i++ {
			if crc&1 != 0 {
				crc = crc>>1 ^ 0xa001
			} else {
				crc >>= 1
			}
		}
	}
	return crc
}

// rtuLength returns zero for incomplete length metadata, -1 for unsupported
// framing. Never infer a length by searching for an arbitrary CRC suffix.
func rtuLength(b []byte, request bool) int {
	if len(b) < 2 {
		return 0
	}
	if b[0] > 247 {
		return -1
	}
	f := b[1]
	if f&0x80 != 0 {
		if request || !isValidFunctionCode(f&0x7f) {
			return -1
		}
		return 5
	}
	count := func(offset, overhead int) int {
		if len(b) <= offset {
			return 0
		}
		n := int(b[offset]) + overhead
		if n > 256 {
			return -1
		}
		return n
	}
	switch f {
	case 1, 2, 3, 4:
		if request {
			return 8
		}
		return count(2, 5)
	case 5, 6:
		return 8
	case 8:
		if len(b) < 4 {
			return 0
		}
		// Return Query Data has no byte count and may be variable length.
		sub := binary.BigEndian.Uint16(b[2:4])
		if sub == 0 || sub > 0x14 || (sub > 4 && sub < 10) || sub == 0x13 {
			return -1
		}
		return 8
	case 15, 16:
		if request {
			return count(6, 9)
		}
		return 8
	case 20, 21:
		return count(2, 5)
	case 22:
		return 10
	case 23:
		if request {
			return count(10, 13)
		}
		return count(2, 5)
	case 43:
		if len(b) < 3 {
			return 0
		}
		if b[2] != 14 {
			return -1
		}
		if request {
			return 7
		}
		if len(b) < 8 {
			return 0
		}
		n := 8
		for i := 0; i < int(b[7]); i++ {
			if n+2 > 254 {
				return -1
			}
			if len(b) < n+2 {
				return 0
			}
			n += 2 + int(b[n+1])
			if n > 254 {
				return -1
			}
		}
		return n + 2
	}
	return -1
}

type rtuDirection struct {
	data  [256]byte
	times [256]int64
	n     int
	// Leading offsets already rejected at a fully determined length. Neither
	// appended bytes nor the fixed direction role can turn those into frame
	// starts, and rescanning them costs a checksum per offset per input byte.
	scanned int
}

func (d *rtuDirection) reset() { d.n, d.scanned = 0, 0 }

func (d *rtuDirection) feed(data []byte, timestamp int64, role string, final bool, emit func(*types.Modbus), lost func()) {
	for index := 0; index <= len(data); index++ {
		if index == len(data) && !final {
			break
		}
		if index < len(data) {
			if d.n == len(d.data) {
				copy(d.data[:], d.data[1:])
				copy(d.times[:], d.times[1:])
				d.n--
				d.scanned = max(d.scanned-1, 0)
				lost()
			}
			d.data[d.n], d.times[d.n] = data[index], timestamp
			d.n++
		}
		for offset := d.scanned; offset+5 <= d.n; offset++ {
			buf := d.data[offset:d.n]
			var msg *types.Modbus
			length := 0
			incomplete := false
			for _, r := range []string{"request", "response"} {
				if role != "unknown" && role != r {
					continue
				}
				n := rtuLength(buf, r == "request")
				if n == 0 || n > len(buf) {
					incomplete = true
				}
				if n < 5 || n > len(buf) || crc16RTU(buf[:n-2]) != binary.LittleEndian.Uint16(buf[n-2:n]) {
					continue
				}
				p := parsePDU(buf[1:n-2], r)
				if p.ParseStatus != "valid" {
					continue
				}
				// Broadcast carries no response; only writes and the diagnostics
				// permitted for unit 0 (restart, force listen only, clear counters)
				// are meaningful, and FC23 always expects a read reply.
				if buf[0] == 0 && (r != "request" || buf[1] != 8 && (!IsCriticalFunction(buf[1]) || buf[1] == 23)) {
					continue
				}
				if msg != nil {
					if length != n {
						msg = nil
						break
					}
					msg = parsePDU(buf[1:n-2], "unknown")
				} else {
					msg, length = p, n
				}
			}
			if msg == nil {
				// Prefer a plausible frame start over CRC-like bytes inside its body.
				if incomplete && !(final && index == len(data)) && d.n < len(d.data) {
					break
				}
				if !incomplete && offset == d.scanned {
					d.scanned++
				}
				continue
			}
			if offset > 0 {
				lost()
			}
			msg.Transport, msg.UnitID = "rtu_tcp", int32(buf[0])
			msg.HasChecksum, msg.ChecksumValid, msg.Broadcast = true, true, buf[0] == 0
			msg.Timestamp = d.times[offset]
			if decoderconfig.Instance.IncludePayloads {
				msg.Payload = append([]byte(nil), buf[1:length-2]...)
			}
			emit(msg)
			used := offset + length
			copy(d.data[:], d.data[used:d.n])
			copy(d.times[:], d.times[used:d.n])
			d.n -= used
			d.scanned, offset = 0, -1
		}
	}
}

func (m *modbusReader) frameRTU(emit func(*types.Modbus)) {
	oriented := m.conversation.TCPHandshakeComplete
	for _, fragments := range []core.DataFragments{m.conversation.Data, m.conversation.ClientData, m.conversation.ServerData} {
		for _, f := range fragments {
			s, ok := f.(*core.StreamData)
			if !ok || s.SkippedBytes == -1 {
				oriented = false
			}
		}
	}
	var dirs [2]rtuDirection
	var stopped [2]bool
	var pending *pendingRequest
	blocked := !oriented
	lost := func() { pending = nil; blocked = true }
	feed := func(f interface {
		Direction() reassembly.TCPFlowDirection
	}, final bool) {
		i := 0
		if f.Direction() == reassembly.TCPDirServerToClient {
			i = 1
		}
		s, ok := f.(*core.StreamData)
		if stopped[i] {
			return
		}
		if !ok {
			dirs[i].reset()
			lost()
			return
		}
		if s.SkippedBytes != 0 {
			dirs[i].reset()
			lost()
			if s.SkippedBytes == -1 && !decoderconfig.Instance.AllowMissingInit {
				stopped[i] = true
				return
			}
		}
		role := "unknown"
		if oriented {
			role = "request"
			if i == 1 {
				role = "response"
			}
		}
		ts := s.CaptureInfo().Timestamp.UnixNano()
		if s.Context() != nil {
			ts = s.Context().GetCaptureInfo().Timestamp.UnixNano()
		}
		dirs[i].feed(s.Raw(), ts, role, final, func(msg *types.Modbus) {
			msg.SrcIP, msg.DstIP = m.conversation.ClientIP, m.conversation.ServerIP
			msg.SrcPort, msg.DstPort = int32(m.conversation.ClientPort), int32(m.conversation.ServerPort)
			if i == 1 {
				msg.SrcIP, msg.DstIP = msg.DstIP, msg.SrcIP
				msg.SrcPort, msg.DstPort = msg.DstPort, msg.SrcPort
			}
			msg.CommunityID = m.conversation.CommunityID
			if msg.Broadcast || msg.FunctionCode == 8 && msg.DiagnosticSubfunction == 4 {
				msg.CorrelationStatus = "not_applicable"
			} else if blocked || msg.MessageRole == "unknown" {
				msg.CorrelationStatus = "ambiguous"
			} else if msg.MessageRole == "request" {
				if pending != nil {
					lost()
					msg.CorrelationStatus = "ambiguous"
				} else {
					p := newPendingRequest(msg, false)
					pending = &p
				}
			} else {
				msg.CorrelationStatus = "unmatched"
				if pending != nil && pending.unitID == msg.UnitID && pending.functionCode == msg.FunctionCode && msg.Timestamp >= pending.timestamp && uint64(msg.Timestamp)-uint64(pending.timestamp) <= uint64(requestTimeout) && compatibleResponse(pending, msg) {
					enrichResponse(pending, msg)
					pending = nil
				}
			}
			emit(msg)
		}, lost)
	}
	c, s := m.conversation.ClientData, m.conversation.ServerData
	if c == nil && s == nil {
		for _, f := range m.conversation.Data {
			feed(f, false)
		}
	}
	for len(c) > 0 || len(s) > 0 {
		useClient := len(s) == 0
		if len(c) > 0 && len(s) > 0 {
			ct, st := c[0].CaptureInfo().Timestamp, s[0].CaptureInfo().Timestamp
			if c[0].Context() != nil {
				ct = c[0].Context().GetCaptureInfo().Timestamp
			}
			if s[0].Context() != nil {
				st = s[0].Context().GetCaptureInfo().Timestamp
			}
			useClient = !st.Before(ct)
		}
		if useClient {
			feed(c[0], false)
			c = c[1:]
		} else {
			feed(s[0], false)
			s = s[1:]
		}
	}
	feed(&core.StreamData{}, true)
	feed(&core.StreamData{Dir: reassembly.TCPDirServerToClient}, true)
}
