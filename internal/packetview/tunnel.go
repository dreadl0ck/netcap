package packetview

import (
	"encoding/binary"
	"errors"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"

	"github.com/dreadl0ck/netcap/types"
)

func tunnel(d *datagram) (t *types.Encapsulation, raw []byte, protocol uint16, headers []gopacket.Layer, err error) {
	newTunnel := func(name string) *types.Encapsulation {
		return &types.Encapsulation{Protocol: name, SrcIP: d.network.NetworkFlow().Src().String(), DstIP: d.network.NetworkFlow().Dst().String()}
	}
	switch d.proto {
	case 4, 41:
		t, raw, protocol = newTunnel("ipip"), d.payload, 0x0800
		if d.proto == 41 {
			protocol = 0x86dd
		}
	case layers.IPProtocolGRE:
		t = newTunnel("gre")
		g := &layers.GRE{}
		if err = g.DecodeFromBytes(d.payload, gopacket.NilDecodeFeedback); err != nil {
			return
		}
		headers = append(headers, g)
		if g.Version != 0 || g.RoutingPresent || g.StrictSourceRoute || g.AckPresent || g.RecursionControl != 0 || g.Flags != 0 {
			err = errors.New("unsupported GRE flags/version")
			return
		}
		t.Identifier, t.KeyPresent, raw, protocol = g.Key, g.KeyPresent, g.Payload, uint16(g.Protocol)
		t.GREKey = g.Key
		switch protocol {
		case 0x88be:
			if !g.SeqPresent { // ERSPAN I has no ERSPAN header.
				t.Protocol, protocol = "erspan-i", 0x6558
				return
			}
			e := &layers.ERSPANII{}
			if err = e.DecodeFromBytes(raw, gopacket.NilDecodeFeedback); err != nil {
				return
			}
			if e.Version != 1 {
				err = errMalformed
				return
			}
			headers = append(headers, e)
			t.Protocol, t.Identifier, t.VLAN = "erspan-ii", uint32(e.SessionID), uint32(e.VLANIdentifier)
			raw, protocol = e.Payload, 0x6558
		case 0x22eb:
			if len(raw) < 12 || raw[0]>>4 != 2 {
				err = errMalformed
				return
			}
			t.Protocol, t.Identifier, t.VLAN = "erspan-iii", uint32(binary.BigEndian.Uint16(raw[2:4])&0x3ff), uint32(binary.BigEndian.Uint16(raw[:2])&0xfff)
			size := 12
			if raw[11]&1 != 0 {
				size += 8
			} // optional platform-specific subheader
			if len(raw) < size {
				err = errMalformed
				return
			}
			raw, protocol = raw[size:], 0x6558
		}
	case layers.IPProtocolUDP:
		u := &layers.UDP{}
		if e := u.DecodeFromBytes(d.payload, gopacket.NilDecodeFeedback); e != nil {
			if len(d.payload) >= 4 {
				port := binary.BigEndian.Uint16(d.payload[2:4])
				if port == 4789 || port == 6081 {
					t, err = newTunnel("vxlan"), errMalformed
					if port == 6081 {
						t.Protocol = "geneve"
					}
					return
				}
			}
			return nil, nil, 0, nil, nil
		}
		port := u.DstPort
		if port != 4789 && port != 6081 {
			return
		}
		t = newTunnel("vxlan")
		t.SrcPort, t.DstPort = uint32(u.SrcPort), uint32(u.DstPort)
		headers = append(headers, u)
		if int(u.Length) > len(d.payload) || u.Length < 16 || len(u.Payload) < 8 {
			err = errMalformed
			return
		}
		raw = u.Payload
		if port == 4789 {
			// RFC 7348: receivers ignore reserved fields; require the VNI-valid bit.
			if raw[0]&8 == 0 {
				err = errMalformed
				return
			}
			v := &layers.VXLAN{}
			if err = v.DecodeFromBytes(raw, gopacket.NilDecodeFeedback); err != nil {
				return
			}
			headers = append(headers, v)
			t.Identifier, raw, protocol = v.VNI, raw[8:], 0x6558
		} else {
			t.Protocol = "geneve"
			if raw[0]>>6 != 0 || raw[1]&0xc0 != 0 {
				err = errors.New("unsupported Geneve version/OAM/critical options")
				return
			}
			size := 8 + int(raw[0]&63)*4
			if size > len(raw) {
				err = errMalformed
				return
			}
			for pos := 8; pos < size; {
				if pos+4 > size {
					err = errMalformed
					return
				}
				n := 4 + int(raw[pos+3]&31)*4
				if pos+n > size || raw[pos+2]&0x80 != 0 {
					err = errMalformed
					return
				}
				pos += n
			}
			g := &layers.Geneve{}
			if err = g.DecodeFromBytes(raw, gopacket.NilDecodeFeedback); err != nil {
				return
			}
			headers = append(headers, g)
			t.Identifier = uint32(raw[4])<<16 | uint32(raw[5])<<8 | uint32(raw[6])
			protocol, raw = binary.BigEndian.Uint16(raw[2:4]), raw[size:]
		}
	}
	return
}
