package collector

import (
	"net"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

// LINKTYPE_IEEE802_5 (DLT 6). Addresses are kept as recorded; Token Ring
// hardware writes them most-significant bit first.
var layerTokenRing = gopacket.RegisterLayerType(12007, gopacket.LayerTypeMetadata{Name: "TokenRing", Decoder: gopacket.DecodeFunc(decodeTokenRing)})

type tokenRingLayer struct {
	layers.BaseLayer
	AccessControl, FrameControl byte
	DstMAC, SrcMAC              net.HardwareAddr
	RouteInformation            []byte
}

func (*tokenRingLayer) LayerType() gopacket.LayerType { return layerTokenRing }

func (t *tokenRingLayer) LinkFlow() gopacket.Flow {
	return gopacket.NewFlow(layers.EndpointMAC, t.SrcMAC, t.DstMAC)
}

// decodeTokenRing strips the 802.5 MAC header and its source-routing field,
// then decodes 802.2 LLC/SNAP. MAC management frames carry no LLC.
func decodeTokenRing(data []byte, p gopacket.PacketBuilder) error {
	if len(data) < 14 {
		p.SetTruncated()
		return badLink("Token Ring header shorter than 14 bytes")
	}
	header := 14
	src := append(net.HardwareAddr(nil), data[8:14]...)
	var route []byte
	// The individual/group bit of the source address flags a routing field.
	if src[0]&0x80 != 0 {
		src[0] &^= 0x80
		if len(data) < 15 {
			p.SetTruncated()
			return badLink("Token Ring routing field missing")
		}
		size := int(data[14] & 0x1f)
		if size < 2 || size%2 != 0 || size > 18 || len(data) < 14+size {
			return badLink("invalid Token Ring routing field length %d", size)
		}
		route = data[14 : 14+size]
		header += size
	}
	layer := &tokenRingLayer{BaseLayer: layers.BaseLayer{Contents: data[:header], Payload: data[header:]},
		AccessControl: data[0], FrameControl: data[1], DstMAC: net.HardwareAddr(data[2:8]), SrcMAC: src, RouteInformation: route}
	p.AddLayer(layer)
	p.SetLinkLayer(layer)
	if layer.FrameControl>>6 != 1 || len(layer.Payload) == 0 {
		return p.NextDecoder(gopacket.LayerTypePayload)
	}
	llc := &layers.LLC{}
	if err := llc.DecodeFromBytes(layer.Payload, p); err != nil {
		return badLink("Token Ring LLC: %v", err)
	}
	p.AddLayer(llc)
	// LLC SAPs without a gopacket decoder (NetBIOS F0, IPX E0) stay payload.
	if next := llc.NextLayerType(); next != gopacket.LayerTypeZero {
		return p.NextDecoder(next)
	}
	return p.NextDecoder(gopacket.LayerTypePayload)
}
