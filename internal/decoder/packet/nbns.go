package packet

import (
	"encoding/binary"
	"net"
	"strings"

	"github.com/dreadl0ck/netcap/types"
	"github.com/gogo/protobuf/proto"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

var nbnsDecoder = newPacketDecoder(types.Type_NC_NBNS, "NBNS", "NetBIOS name service queries, registrations and address assertions", nil, decodeNBNS, nil)

func decodeNBNS(p gopacket.Packet) proto.Message {
	u, ok := p.Layer(layers.LayerTypeUDP).(*layers.UDP)
	if !ok || (u.SrcPort != 137 && u.DstPort != 137) || len(u.Payload) < 12 {
		return nil
	}
	data := u.Payload
	count := 0
	for i := 4; i < 12; i += 2 {
		count += int(binary.BigEndian.Uint16(data[i:]))
	}
	if count > 256 {
		return nil
	}
	wire, ok := parseNBNS(data)
	if !ok {
		return nil
	}
	r := &types.NBNS{Timestamp: p.Metadata().Timestamp.UnixNano(), ID: uint32(wire.id), Response: wire.response, OpCode: uint32(wire.opCode), ResponseCode: uint32(wire.responseCode), SrcPort: int32(u.SrcPort), DstPort: int32(u.DstPort)}
	if n := p.NetworkLayer(); n != nil {
		r.SrcIP, r.DstIP = n.NetworkFlow().Src().String(), n.NetworkFlow().Dst().String()
	}
	name := func(encoded string, section string, typ uint32) *types.NBNSName {
		label := encoded
		if len(label) != 32 {
			return nil
		}
		var decoded [16]byte
		for i := range decoded {
			a, b := label[2*i], label[2*i+1]
			if a < 'A' || a > 'P' || b < 'A' || b > 'P' {
				return nil
			}
			decoded[i] = (a-'A')<<4 | (b - 'A')
		}
		return &types.NBNSName{Name: strings.TrimRight(string(decoded[:15]), " \x00"), Suffix: uint32(decoded[15]), Section: section, Type: typ}
	}
	for _, q := range wire.questions {
		if n := name(q.name, "question", uint32(q.typ)); n != nil {
			r.Names = append(r.Names, n)
		}
	}
	for _, section := range []struct {
		name    string
		records []nbnsRR
	}{{"answer", wire.answers}, {"authority", wire.authorities}, {"additional", wire.additionals}} {
		for _, rr := range section.records {
			n := name(rr.name, section.name, uint32(rr.typ))
			if n == nil {
				continue
			}
			switch {
			case rr.typ == 0x20 && len(rr.data)%6 == 0:
				for i := 0; i+6 <= len(rr.data); i += 6 {
					c := *n
					c.Group = binary.BigEndian.Uint16(rr.data[i:])&0x8000 != 0
					c.IP = net.IP(rr.data[i+2 : i+6]).String()
					r.Names = append(r.Names, &c)
				}
			case rr.typ == 0x21 && len(rr.data) >= 1:
				// Node status: a count byte, then 18-byte entries (15 name, 1 suffix, 2 flags).
				entries := int(rr.data[0])
				for i := 0; i < entries && 1+(i+1)*18 <= len(rr.data); i++ {
					e := rr.data[1+i*18 : 1+(i+1)*18]
					r.Names = append(r.Names, &types.NBNSName{
						Name:    strings.TrimRight(string(e[:15]), " \x00"),
						Suffix:  uint32(e[15]),
						Group:   binary.BigEndian.Uint16(e[16:])&0x8000 != 0,
						Section: section.name,
						Type:    uint32(rr.typ),
					})
				}
			default:
				r.Names = append(r.Names, n)
			}
		}
	}
	return r
}

type nbnsQuestion struct {
	name string
	typ  uint16
}

type nbnsRR struct {
	name string
	typ  uint16
	data []byte
}

type nbnsMessage struct {
	id                                uint16
	response                          bool
	opCode, responseCode              uint8
	questions                         []nbnsQuestion
	answers, authorities, additionals []nbnsRR
}

// readNBNSName returns the first label of a (possibly compressed) name and the offset after it.
// NetBIOS names are a single 32-byte encoded label plus an optional scope, so only the first
// label is needed. layers.DNS cannot be used: it decodes type 33 (NBSTAT) as SRV and fails.
func readNBNSName(data []byte, off int) (label string, next int, ok bool) {
	next = -1
	for hops := 0; hops < 16; hops++ {
		if off >= len(data) {
			return "", 0, false
		}
		l := int(data[off])
		switch {
		case l == 0:
			if next < 0 {
				next = off + 1
			}
			return label, next, true
		case l&0xc0 == 0xc0:
			if off+1 >= len(data) {
				return "", 0, false
			}
			if next < 0 {
				next = off + 2
			}
			off = int(binary.BigEndian.Uint16(data[off:]) & 0x3fff)
		case l&0xc0 != 0 || off+1+l > len(data):
			return "", 0, false
		default:
			if label == "" {
				label = string(data[off+1 : off+1+l])
			}
			off += 1 + l
		}
	}
	return "", 0, false
}

func parseNBNS(data []byte) (*nbnsMessage, bool) {
	if len(data) < 12 {
		return nil, false
	}
	m := &nbnsMessage{
		id:           binary.BigEndian.Uint16(data),
		response:     data[2]&0x80 != 0,
		opCode:       data[2] >> 3 & 0x0f,
		responseCode: data[3] & 0x0f,
	}
	off := 12
	for i := 0; i < int(binary.BigEndian.Uint16(data[4:])); i++ {
		name, next, ok := readNBNSName(data, off)
		if !ok || next+4 > len(data) {
			return nil, false
		}
		m.questions = append(m.questions, nbnsQuestion{name: name, typ: binary.BigEndian.Uint16(data[next:])})
		off = next + 4
	}
	for s, dst := range []*[]nbnsRR{&m.answers, &m.authorities, &m.additionals} {
		for i := 0; i < int(binary.BigEndian.Uint16(data[6+2*s:])); i++ {
			name, next, ok := readNBNSName(data, off)
			if !ok || next+10 > len(data) {
				return nil, false
			}
			n := int(binary.BigEndian.Uint16(data[next+8:]))
			if next+10+n > len(data) {
				return nil, false
			}
			*dst = append(*dst, nbnsRR{name: name, typ: binary.BigEndian.Uint16(data[next:]), data: data[next+10 : next+10+n]})
			off = next + 10 + n
		}
	}
	return m, true
}
