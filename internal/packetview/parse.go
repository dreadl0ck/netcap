package packetview

import (
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

var errMalformed = errors.New("malformed or truncated datagram")

type datagram struct {
	raw, payload            []byte
	network                 gopacket.NetworkLayer
	headers                 []gopacket.Layer
	proto                   layers.IPProtocol
	fragment                bool
	id                      uint32
	offset                  int
	more                    bool
	headerEnd, previousNext int
	v6                      bool
	truncated               bool
}

func parseIP(raw []byte) (*datagram, error) {
	if len(raw) == 0 {
		return nil, errMalformed
	}
	d := &datagram{raw: raw}
	switch raw[0] >> 4 {
	case 4:
		ip := &layers.IPv4{}
		if err := ip.DecodeFromBytes(raw, gopacket.NilDecodeFeedback); err != nil {
			return nil, err
		}
		if ip.Version != 4 {
			return nil, errMalformed
		}
		d.truncated = int(ip.Length) > len(raw)
		d.raw, d.payload, d.network, d.proto = raw[:min(int(ip.Length), len(raw))], ip.Payload, ip, ip.Protocol
		d.headers = []gopacket.Layer{ip}
		d.fragment = ip.FragOffset != 0 || ip.Flags&layers.IPv4MoreFragments != 0
		d.id, d.offset, d.more = uint32(ip.Id), int(ip.FragOffset)*8, ip.Flags&layers.IPv4MoreFragments != 0
		d.headerEnd = int(ip.IHL) * 4
	case 6:
		if len(raw) < 40 {
			return nil, errMalformed
		}
		total := 40 + int(binary.BigEndian.Uint16(raw[4:6]))
		if total == 40 {
			return nil, errMalformed
		}
		d.truncated = total > len(raw)
		total = min(total, len(raw))
		d.raw, d.v6 = raw[:total], true
		ip := &layers.IPv6{}
		if err := ip.DecodeFromBytes(d.raw, gopacket.NilDecodeFeedback); err != nil {
			return nil, err
		}
		d.network, d.headers = ip, []gopacket.Layer{ip}
		next, pos, prev := raw[6], 40, 6
		for n := 0; ; n++ {
			if n > 16 {
				return nil, errors.New("IPv6 extension depth limit")
			}
			if next == 44 {
				if pos+8 > total || raw[pos+1] != 0 || raw[pos+3]&6 != 0 {
					return nil, errMalformed
				}
				d.fragment, d.id = true, binary.BigEndian.Uint32(raw[pos+4:pos+8])
				d.offset, d.more = int(binary.BigEndian.Uint16(raw[pos+2:pos+4])>>3)*8, raw[pos+3]&1 != 0
				d.headerEnd, d.previousNext, d.proto = pos, prev, layers.IPProtocol(raw[pos])
				d.payload = d.raw[pos+8:]
				// Decode only the fragment header; gopacket deliberately stops here.
				p := gopacket.NewPacket(d.raw[pos:], layers.LayerTypeIPv6Fragment, gopacket.NoCopy)
				if l := p.Layer(layers.LayerTypeIPv6Fragment); l != nil {
					d.headers = append(d.headers, l)
				}
				return d, nil
			}
			var ext interface {
				gopacket.Layer
				DecodeFromBytes([]byte, gopacket.DecodeFeedback) error
			}
			switch next {
			case 0:
				ext = &layers.IPv6HopByHop{}
			case 43: // Parsed below; gopacket has no DecodeFromBytes for routing.
			case 60:
				ext = &layers.IPv6Destination{}
			case 51:
				ext = &layers.IPSecAH{}
			default:
				d.proto, d.payload, d.headerEnd = layers.IPProtocol(next), d.raw[pos:], pos
				return d, nil
			}
			if pos+2 > total {
				return nil, errMalformed
			}
			size := (int(raw[pos+1]) + 1) * 8
			if next == 51 {
				size = (int(raw[pos+1]) + 2) * 4
			}
			if size < 8 || pos+size > total {
				return nil, errMalformed
			}
			if next == 43 {
				r := &layers.IPv6Routing{}
				r.BaseLayer = layers.BaseLayer{Contents: d.raw[pos : pos+size], Payload: d.raw[pos+size:]}
				r.NextHeader, r.HeaderLength, r.ActualLength = layers.IPProtocol(raw[pos]), raw[pos+1], size
				r.RoutingType, r.SegmentsLeft, r.Reserved = raw[pos+2], raw[pos+3], d.raw[pos+4:pos+8]
				d.headers = append(d.headers, r)
			} else {
				if err := ext.DecodeFromBytes(d.raw[pos:], gopacket.NilDecodeFeedback); err != nil {
					return nil, err
				}
				d.headers = append(d.headers, ext)
			}
			prev, next, pos = pos, raw[pos], pos+size
		}
	default:
		return nil, errMalformed
	}
	return d, nil
}

// levelPacket never recursively decodes encapsulation. Layers() and Layer() expose
// exactly one IP/transport pairing, including to legacy application decoders.
func levelPacket(d *datagram, link []gopacket.Layer, extra []gopacket.Layer, transport bool) gopacket.Packet {
	data := d.raw
	if len(link) > 0 {
		data = nil
		for _, l := range link {
			data = append(data, l.LayerContents()...)
		}
		data = append(data, d.raw...)
	}
	p := gopacket.NewPacket(data, gopacket.DecodeFunc(func(_ []byte, b gopacket.PacketBuilder) error {
		for _, l := range link {
			b.AddLayer(l)
			if ll, ok := l.(gopacket.LinkLayer); ok {
				b.SetLinkLayer(ll)
			}
		}
		for _, l := range d.headers {
			b.AddLayer(l)
		}
		b.SetNetworkLayer(d.network)
		for _, l := range extra {
			b.AddLayer(l)
			if tl, ok := l.(gopacket.TransportLayer); ok {
				b.SetTransportLayer(tl)
			}
		}
		if transport {
			return b.NextDecoder(d.proto)
		}
		return nil
	}), gopacket.NoCopy)
	p.Metadata().Truncated = p.Metadata().Truncated || d.truncated
	return p
}

func malformedEvidence(original gopacket.Packet) gopacket.Packet {
	return gopacket.NewPacket(original.Data(), gopacket.DecodeFunc(func(_ []byte, b gopacket.PacketBuilder) error {
		for _, l := range original.Layers() {
			b.AddLayer(l)
			if n, ok := l.(gopacket.NetworkLayer); ok {
				b.SetNetworkLayer(n)
				break
			}
			if ll, ok := l.(gopacket.LinkLayer); ok {
				b.SetLinkLayer(ll)
			}
		}
		return errMalformed
	}), gopacket.NoCopy)
}

func innerLink(raw []byte, protocol uint16) ([]byte, []gopacket.Layer, error) {
	if protocol == 0x0800 || protocol == 0x86dd {
		if len(raw) == 0 || (protocol == 0x0800 && raw[0]>>4 != 4) || (protocol == 0x86dd && raw[0]>>4 != 6) {
			return nil, nil, errMalformed
		}
		return raw, nil, nil
	}
	if protocol != 0x6558 {
		return nil, nil, fmt.Errorf("unsupported tunnel payload %#x", protocol)
	}
	eth := &layers.Ethernet{}
	if err := eth.DecodeFromBytes(raw, gopacket.NilDecodeFeedback); err != nil {
		return nil, nil, err
	}
	ls, data, kind := []gopacket.Layer{eth}, eth.Payload, eth.EthernetType
	for n := 0; kind == layers.EthernetTypeDot1Q || kind == layers.EthernetTypeQinQ; n++ {
		if n == 4 {
			return nil, nil, errors.New("VLAN depth limit")
		}
		v := &layers.Dot1Q{}
		if err := v.DecodeFromBytes(data, gopacket.NilDecodeFeedback); err != nil {
			return nil, nil, err
		}
		ls, data, kind = append(ls, v), v.Payload, v.Type
	}
	if kind != layers.EthernetTypeIPv4 && kind != layers.EthernetTypeIPv6 {
		return nil, nil, errMalformed
	}
	data, _, err := innerLink(data, uint16(kind))
	return data, ls, err
}
