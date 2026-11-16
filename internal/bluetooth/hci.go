package bluetooth

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"sort"
)

type Event struct {
	Protocol       string
	Fields         map[string]any
	Qualifications []string `json:",omitempty"`
	Sources        []uint64 `json:",omitempty"`
	Packet         []byte   `json:"-"`
}
type fragment struct {
	data    []byte
	sources []uint64
	ordinal uint64
	credit  int
}
type Processor struct {
	Reserve func(int) bool
	Release func(int)
	pending map[string]*fragment
	credit  int
}

func (p *Processor) reserve(n int) bool {
	if p.credit+n > 8<<20 || p.Reserve != nil && !p.Reserve(n) {
		return false
	}
	p.credit += n
	return true
}
func (p *Processor) remove(key string) {
	if f := p.pending[key]; f != nil {
		p.credit -= f.credit
		if p.Release != nil {
			p.Release(f.credit)
		}
		delete(p.pending, key)
	}
}
func (p *Processor) Reset() {
	for key := range p.pending {
		p.remove(key)
	}
	p.pending = nil
}
func (p *Processor) Expire(ordinal uint64) {
	for key, f := range p.pending {
		if ordinal >= f.ordinal && ordinal-f.ordinal > 4096 {
			p.remove(key)
		}
	}
}
func (p *Processor) Incomplete() []Event {
	var events []Event
	keys := make([]string, 0, len(p.pending))
	for key := range p.pending {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		f := p.pending[key]
		events = append(events, Event{Protocol: "L2CAP", Fields: map[string]any{"Scope": key, "BufferedBytes": len(f.data)}, Qualifications: []string{"capture-end-fragment-incomplete"}, Sources: f.sources})
	}
	return events
}

func address(data []byte) string {
	if len(data) < 6 {
		return ""
	}
	return fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", data[5], data[4], data[3], data[2], data[1], data[0])
}

func (p *Processor) Push(scope string, packetType byte, header, body []byte, direction *byte, ordinal uint64) ([]Event, error) {
	p.Expire(ordinal)
	e := Event{Protocol: "HCI", Fields: map[string]any{"PacketType": packetType}, Sources: []uint64{ordinal}}
	switch packetType {
	case 1:
		if len(header) < 3 {
			return nil, fmt.Errorf("short HCI command")
		}
		e.Fields["Opcode"] = binary.LittleEndian.Uint16(header)
		e.Fields["ParameterLength"] = len(body)
	case 4:
		if len(header) < 2 {
			return nil, fmt.Errorf("short HCI event")
		}
		code := header[0]
		e.Fields["EventCode"] = code
		if code == 0x0e && len(body) >= 4 {
			opcode := binary.LittleEndian.Uint16(body[1:])
			e.Fields["Opcode"], e.Fields["Status"] = opcode, body[3]
			if body[3] == 0 && opcode == 0x1001 && len(body) >= 12 {
				e.Fields["HCIVersion"], e.Fields["HCIRevision"], e.Fields["LMPVersion"], e.Fields["Manufacturer"], e.Fields["LMPSubversion"] = body[4], binary.LittleEndian.Uint16(body[5:]), body[7], binary.LittleEndian.Uint16(body[8:]), binary.LittleEndian.Uint16(body[10:])
			}
			if body[3] == 0 && opcode == 0x1009 && len(body) >= 10 {
				e.Fields["ControllerAddress"] = address(body[4:])
			}
		}
		if code == 3 && len(body) >= 11 || code == 5 && len(body) >= 4 {
			handle := binary.LittleEndian.Uint16(body[1:]) & 0xfff
			e.Fields["Handle"], e.Fields["Status"] = handle, body[0]
			if body[0] == 0 {
				for _, d := range []byte{0, 1} {
					p.remove(fmt.Sprintf("%s/%d/%d", scope, handle, d))
				}
			}
			if code == 3 && len(body) >= 11 {
				e.Fields["PeerAddress"], e.Fields["LinkType"], e.Fields["Encryption"] = address(body[3:]), body[9], body[10]
			}
			if code == 5 {
				e.Fields["Reason"] = body[3]
			}
		}
		if code == 0x3e && len(body) >= 12 && (body[0] == 1 || body[0] == 10) {
			handle := binary.LittleEndian.Uint16(body[2:]) & 0xfff
			e.Fields["LESubevent"], e.Fields["Status"], e.Fields["Handle"], e.Fields["Role"], e.Fields["PeerAddressType"], e.Fields["PeerAddress"] = body[0], body[1], handle, body[4], body[5], address(body[6:])
			if body[1] == 0 {
				for _, d := range []byte{0, 1} {
					p.remove(fmt.Sprintf("%s/%d/%d", scope, handle, d))
				}
			}
		}
	case 2:
		if len(header) < 4 {
			return nil, fmt.Errorf("short HCI ACL header")
		}
		flags := binary.LittleEndian.Uint16(header)
		handle, boundary := flags&0xfff, flags>>12&3
		e.Fields["Handle"], e.Fields["Boundary"] = handle, boundary
		if boundary != 1 && len(body) >= 4 && int(binary.LittleEndian.Uint16(body))+4 == len(body) {
			if direction != nil {
				p.remove(fmt.Sprintf("%s/%d/%d", scope, handle, *direction))
			}
			return decodeL2CAP(body, []uint64{ordinal}), nil
		}
		if direction == nil {
			e.Qualifications = []string{"L2CAP-fragment-direction-unavailable"}
			return []Event{e}, nil
		}
		if boundary == 3 {
			e.Qualifications = []string{"L2CAP-complete-flag-length-mismatch"}
			return []Event{e}, nil
		}
		key := fmt.Sprintf("%s/%d/%d", scope, handle, *direction)
		if p.pending == nil {
			p.pending = map[string]*fragment{}
		}
		if boundary != 1 {
			p.remove(key)
			if len(p.pending) >= 128 || !p.reserve(512) {
				return nil, fmt.Errorf("Bluetooth fragment/state budget exceeded")
			}
			p.pending[key] = &fragment{credit: 512}
		}
		f := p.pending[key]
		if f == nil {
			e.Qualifications = []string{"L2CAP-continuation-missing-start"}
			return []Event{e}, nil
		}
		if len(f.sources) >= 256 || len(body) > 65539-len(f.data) {
			p.remove(key)
			e.Qualifications = []string{"L2CAP-fragment-length-or-source-limit"}
			return []Event{e}, nil
		}
		amount := len(body) + 32
		if !p.reserve(amount) {
			return nil, fmt.Errorf("Bluetooth fragment/state budget exceeded")
		}
		f.credit += amount
		data := make([]byte, len(f.data)+len(body))
		copy(data, f.data)
		copy(data[len(f.data):], body)
		f.data = data
		f.sources = append(f.sources, ordinal)
		f.ordinal = ordinal
		if len(data) >= 4 {
			expected := 4 + int(binary.LittleEndian.Uint16(data))
			if len(data) > expected {
				p.remove(key)
				e.Qualifications = []string{"L2CAP-reassembled-length-mismatch"}
				return []Event{e}, nil
			}
			if len(data) == expected {
				events := decodeL2CAP(data, f.sources)
				p.remove(key)
				return events, nil
			}
		}
		e.Qualifications = []string{"L2CAP-fragment-pending"}
	default:
		e.Qualifications = []string{"HCI-payload-profile-not-decoded"}
	}
	return []Event{e}, nil
}

func decodeL2CAP(data []byte, sources []uint64) []Event {
	cid := binary.LittleEndian.Uint16(data[2:])
	body := data[4:]
	e := Event{Protocol: "L2CAP", Fields: map[string]any{"CID": cid, "Length": len(body)}, Sources: sources, Packet: bytes.Clone(data)}
	switch cid {
	case 4:
		att := decodeATT(body)
		att.Sources = sources
		return []Event{e, att}
	case 1, 5:
		var commands []map[string]any
		for offset := 0; offset < len(body); {
			if len(body)-offset < 4 || len(commands) >= 64 {
				e.Qualifications = []string{"invalid-L2CAP-signalling-length-or-count"}
				return []Event{e}
			}
			n := int(binary.LittleEndian.Uint16(body[offset+2:]))
			if n > len(body)-offset-4 {
				e.Qualifications = []string{"L2CAP-signalling-command-exceeds-PDU"}
				return []Event{e}
			}
			code, id := body[offset], body[offset+1]
			value := body[offset+4 : offset+4+n]
			item := map[string]any{"Code": code, "Identifier": id, "Length": n}
			switch code {
			case 2:
				if len(value) >= 4 {
					item["PSM"], item["SourceCID"] = binary.LittleEndian.Uint16(value), binary.LittleEndian.Uint16(value[2:])
				}
			case 3:
				if len(value) >= 8 {
					item["DestinationCID"], item["SourceCID"], item["Result"], item["Status"] = binary.LittleEndian.Uint16(value), binary.LittleEndian.Uint16(value[2:]), binary.LittleEndian.Uint16(value[4:]), binary.LittleEndian.Uint16(value[6:])
				}
			case 6, 7:
				if len(value) >= 4 {
					item["DestinationCID"], item["SourceCID"] = binary.LittleEndian.Uint16(value), binary.LittleEndian.Uint16(value[2:])
				}
			case 0x14:
				if len(value) >= 10 {
					item["LEPSM"], item["SourceCID"], item["MTU"], item["MPS"], item["Credits"] = binary.LittleEndian.Uint16(value), binary.LittleEndian.Uint16(value[2:]), binary.LittleEndian.Uint16(value[4:]), binary.LittleEndian.Uint16(value[6:]), binary.LittleEndian.Uint16(value[8:])
				}
			}
			commands = append(commands, item)
			offset += 4 + n
		}
		e.Fields["Signalling"] = commands
	case 6:
		if len(body) > 0 {
			e.Fields["SMPCode"] = body[0]
			if (body[0] == 1 || body[0] == 2) && len(body) == 7 {
				e.Fields["IOCapability"], e.Fields["OOB"], e.Fields["AuthenticationRequirements"], e.Fields["KeySize"] = body[1], body[2], body[3], body[4]
			}
			e.Qualifications = []string{"SMP-key-material-not-exposed-as-metadata"}
		}
	default:
		e.Qualifications = []string{"L2CAP-channel-profile-not-decoded"}
	}
	return []Event{e}
}
