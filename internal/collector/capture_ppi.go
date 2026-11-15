package collector

import (
	"encoding/binary"

	"github.com/dreadl0ck/netcap/internal/linkaudit"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

const layerPPI gopacket.LayerType = 12005

func init() {
	gopacket.RegisterLayerType(int(layerPPI), gopacket.LayerTypeMetadata{Name: "PPI", Decoder: gopacket.DecodeFunc(func(data []byte, p gopacket.PacketBuilder) error {
		return decodePPI(data, p, binary.NativeEndian, 0, &linkaudit.FrameCheck{})
	})})
}

type ppiLayer struct {
	layers.BaseLayer
	Version, Flags byte
	LinkType       uint32
}

func (*ppiLayer) LayerType() gopacket.LayerType { return layerPPI }

func decodePPI(data []byte, p gopacket.PacketBuilder, order binary.ByteOrder, depth int, check *linkaudit.FrameCheck) error {
	if depth >= 8 {
		return unsupportedLink("PPI nesting exceeds 8 headers")
	}
	if len(data) < 8 {
		p.SetTruncated()
		return badLink("PPI header shorter than 8 bytes")
	}
	header := int(binary.LittleEndian.Uint16(data[2:4]))
	if header < 8 || header > len(data) {
		if header > len(data) {
			p.SetTruncated()
		}
		return badLink("PPI header length %d exceeds captured bounds %d", header, len(data))
	}
	layer := &ppiLayer{BaseLayer: layers.BaseLayer{Contents: data[:header], Payload: data[header:]}, Version: data[0], Flags: data[1], LinkType: binary.LittleEndian.Uint32(data[4:8])}
	p.AddLayer(layer)
	if layer.Version != 0 || layer.Flags & ^byte(1) != 0 {
		return unsupportedLink("unsupported PPI version/flags %d/0x%02x", layer.Version, layer.Flags)
	}
	var fcs, fcsKnown bool
	for offset := 8; offset < header; {
		if header-offset < 4 {
			return badLink("PPI field header truncated at %d", offset)
		}
		kind := binary.LittleEndian.Uint16(data[offset:])
		length := int(binary.LittleEndian.Uint16(data[offset+2:]))
		offset += 4
		if length > header-offset {
			return badLink("PPI field %d length %d exceeds header", kind, length)
		}
		if kind == 2 {
			if length != 20 {
				return badLink("PPI 802.11 common field length %d, expected 20", length)
			}
			fcs = binary.LittleEndian.Uint16(data[offset+8:])&1 != 0
			fcsKnown = true
		}
		offset += length
		if layer.Flags&1 != 0 {
			offset = (offset + 3) &^ 3
			if offset > header {
				return badLink("PPI field alignment exceeds header")
			}
		}
	}
	// The PPI DLT is 32 bits; do not truncate it into a different known type.
	if layer.LinkType > 65535 {
		return unsupportedLink("unsupported PPI link type %d", layer.LinkType)
	}
	lt := layers.LinkType(layer.LinkType)
	var decoder gopacket.Decoder
	switch lt {
	case 192:
		decoder = gopacket.DecodeFunc(func(data []byte, p gopacket.PacketBuilder) error { return decodePPI(data, p, order, depth+1, check) })
	case layers.LinkTypeIEEE802_11:
		check.Known, check.Present = fcsKnown, fcs
		decoder = gopacket.DecodeFunc(func(data []byte, p gopacket.PacketBuilder) error { return linkaudit.DecodeDot11(data, p, fcs) })
	case layers.LinkTypeIEEE80211Radio:
		decoder = gopacket.DecodeFunc(func(data []byte, p gopacket.PacketBuilder) error { return linkaudit.DecodeRadioTap(data, p, check) })
	case 189, 220, 249:
		decoder = gopacket.DecodeFunc(func(data []byte, p gopacket.PacketBuilder) error { return decodeCaptureUSB(data, p, lt, order) })
	case 239:
		decoder = gopacket.DecodeFunc(func(data []byte, p gopacket.PacketBuilder) error { return decodeNFLOG(data, p, order) })
	case 195:
		decoder = gopacket.DecodeFunc(decodeIEEE802154FCS)
	case 230:
		decoder = gopacket.DecodeFunc(decodeIEEE802154)
	default:
		if next := linkTypeToLayerType(lt); next != 0 {
			decoder = next
		}
	}
	if decoder == nil {
		return unsupportedLink("unsupported PPI link type %d", layer.LinkType)
	}
	return p.NextDecoder(decoder)
}
