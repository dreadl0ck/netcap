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
	var wire layers.DNS
	if wire.DecodeFromBytes(data, gopacket.NilDecodeFeedback) != nil {
		return nil
	}
	r := &types.NBNS{Timestamp: p.Metadata().Timestamp.UnixNano(), ID: uint32(wire.ID), Response: wire.QR, OpCode: uint32(wire.OpCode), ResponseCode: uint32(wire.ResponseCode), SrcPort: int32(u.SrcPort), DstPort: int32(u.DstPort)}
	if n := p.NetworkLayer(); n != nil {
		r.SrcIP, r.DstIP = n.NetworkFlow().Src().String(), n.NetworkFlow().Dst().String()
	}
	name := func(encoded []byte, section string, typ uint32) *types.NBNSName {
		label, _, _ := strings.Cut(string(encoded), ".")
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
	for _, q := range wire.Questions {
		if n := name(q.Name, "question", uint32(q.Type)); n != nil {
			r.Names = append(r.Names, n)
		}
	}
	for _, section := range []struct {
		name    string
		records []layers.DNSResourceRecord
	}{{"answer", wire.Answers}, {"authority", wire.Authorities}, {"additional", wire.Additionals}} {
		for _, rr := range section.records {
			n := name(rr.Name, section.name, uint32(rr.Type))
			if n == nil {
				continue
			}
			if uint16(rr.Type) == 0x20 && len(rr.Data)%6 == 0 {
				for i := 0; i+6 <= len(rr.Data); i += 6 {
					c := *n
					c.Group = binary.BigEndian.Uint16(rr.Data[i:])&0x8000 != 0
					c.IP = net.IP(rr.Data[i+2 : i+6]).String()
					r.Names = append(r.Names, &c)
				}
			} else {
				r.Names = append(r.Names, n)
			}
		}
	}
	return r
}
