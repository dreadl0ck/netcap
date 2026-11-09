package collector

import (
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/dreadl0ck/netcap/internal/linkaudit"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

var (
	layerNFLOG = gopacket.RegisterLayerType(12001, gopacket.LayerTypeMetadata{Name: "NFLOG", Decoder: gopacket.DecodeFunc(func(data []byte, p gopacket.PacketBuilder) error {
		return decodeNFLOG(data, p, binary.NativeEndian)
	})})
	layerCHDLC      = gopacket.RegisterLayerType(12002, gopacket.LayerTypeMetadata{Name: "CiscoHDLC", Decoder: gopacket.DecodeFunc(decodeCHDLC)})
	layerIEEE802154 = linkaudit.LayerIEEE802154
	layerRawIP      = gopacket.RegisterLayerType(12004, gopacket.LayerTypeMetadata{Name: "CaptureRawIP", Decoder: gopacket.DecodeFunc(decodeRawIP)})
)

type captureLinkError struct {
	Reason      string
	Unsupported bool
}

func (e *captureLinkError) Error() string { return e.Reason }

func badLink(format string, args ...any) error {
	return &captureLinkError{Reason: fmt.Sprintf(format, args...)}
}

func unsupportedLink(format string, args ...any) error {
	return &captureLinkError{Reason: fmt.Sprintf(format, args...), Unsupported: true}
}

type nflogLayer struct {
	layers.BaseLayer
	Family  byte
	Version byte
	Group   uint16
}

func (*nflogLayer) LayerType() gopacket.LayerType { return layerNFLOG }

// NFLOG attribute framing uses the capture/section byte order, not network byte
// order. Walk every TLV before decoding payload, including TLVs after type 9.
func decodeNFLOG(data []byte, p gopacket.PacketBuilder, order binary.ByteOrder) error {
	if len(data) < 4 {
		p.SetTruncated()
		return badLink("NFLOG header shorter than 4 bytes")
	}
	layer := &nflogLayer{BaseLayer: layers.BaseLayer{Contents: data[:4]}, Family: data[0], Version: data[1], Group: binary.BigEndian.Uint16(data[2:4])}
	p.AddLayer(layer)
	if layer.Version != 0 {
		return unsupportedLink("unsupported NFLOG version %d", layer.Version)
	}
	start, size := -1, 0
	for offset := 4; offset < len(data); {
		if len(data)-offset < 4 {
			return badLink("NFLOG truncated TLV header at %d", offset)
		}
		n, kind := int(order.Uint16(data[offset:])), order.Uint16(data[offset+2:])&0x3fff
		if n < 4 || n > len(data)-offset {
			return badLink("NFLOG invalid TLV length %d at %d (%d bytes remain)", n, offset, len(data)-offset)
		}
		padded := (n + 3) &^ 3
		if padded > len(data)-offset {
			return badLink("NFLOG missing TLV padding at %d", offset)
		}
		want := 0
		switch kind {
		case 1, 2, 4, 5, 6, 7, 11, 12, 13, 14:
			want = 8
		case 15, 17: // NFULA_HWTYPE/HWLEN carry __be16, including in nflog-http.pcap.
			want = 6
		case 3:
			want = 20
		case 8:
			want = 16
		case 10:
			if n < 5 || data[offset+n-1] != 0 {
				return badLink("NFLOG prefix TLV lacks terminating NUL")
			}
		}
		if want != 0 && n != want {
			return badLink("NFLOG TLV type %d has length %d, expected %d", kind, n, want)
		}
		if kind == 9 {
			if start >= 0 {
				return badLink("NFLOG duplicate payload TLV")
			}
			start, size = offset+4, n-4
		}
		offset += padded
	}
	if start < 0 {
		return unsupportedLink("NFLOG record has no network payload TLV")
	}
	layer.BaseLayer = layers.BaseLayer{Contents: data[:start], Payload: data[start : start+size]}
	switch layer.Family {
	case 2:
		return decodeIPPayload(layer.Payload, p, 4)
	case 10:
		return decodeIPPayload(layer.Payload, p, 6)
	default:
		return unsupportedLink("unsupported NFLOG address family %d", layer.Family)
	}
}

type chdlcLayer struct {
	layers.BaseLayer
	Address, Control byte
	Protocol         layers.EthernetType
}

func (*chdlcLayer) LayerType() gopacket.LayerType { return layerCHDLC }

func decodeCHDLC(data []byte, p gopacket.PacketBuilder) error {
	if len(data) < 4 {
		p.SetTruncated()
		return badLink("Cisco HDLC header shorter than 4 bytes")
	}
	layer := &chdlcLayer{BaseLayer: layers.BaseLayer{Contents: data[:4], Payload: data[4:]}, Address: data[0], Control: data[1], Protocol: layers.EthernetType(binary.BigEndian.Uint16(data[2:4]))}
	p.AddLayer(layer)
	if (layer.Address != 0x0f && layer.Address != 0x8f) || layer.Control != 0 {
		return badLink("invalid Cisco HDLC address/control %02x/%02x", layer.Address, layer.Control)
	}
	switch layer.Protocol {
	case layers.EthernetTypeIPv4:
		return decodeIPPayload(layer.Payload, p, 4)
	case layers.EthernetTypeIPv6:
		return decodeIPPayload(layer.Payload, p, 6)
	}
	if layer.Protocol.LayerType() == gopacket.LayerTypeZero {
		return unsupportedLink("unsupported Cisco HDLC protocol 0x%04x", uint16(layer.Protocol))
	}
	return p.NextDecoder(layer.Protocol)
}

type ieee802154Layer = linkaudit.IEEE802154

func decodeIEEE802154(data []byte, p gopacket.PacketBuilder) error {
	return ieee802154Error(linkaudit.DecodeIEEE802154(data, p))
}
func decodeIEEE802154FCS(data []byte, p gopacket.PacketBuilder) error {
	return ieee802154Error(linkaudit.DecodeIEEE802154FCS(data, p))
}
func ieee802154Error(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, linkaudit.ErrUnsupported) {
		return unsupportedLink("%v", err)
	}
	return badLink("%v", err)
}

func decodeIPPayload(data []byte, p gopacket.PacketBuilder, version byte) error {
	if len(data) == 0 || data[0]>>4 != version {
		return badLink("link header declares IPv%d but payload version is absent or different", version)
	}
	if version == 4 {
		return p.NextDecoder(layers.LayerTypeIPv4)
	}
	return p.NextDecoder(layers.LayerTypeIPv6)
}

func decodeRawIP(data []byte, p gopacket.PacketBuilder) error {
	if len(data) == 0 || (data[0]>>4 != 4 && data[0]>>4 != 6) {
		return badLink("RAW capture has no IPv4/IPv6 version")
	}
	if data[0]>>4 == 4 {
		return layers.LayerTypeIPv4.Decode(data, p)
	}
	return layers.LayerTypeIPv6.Decode(data, p)
}

func decodeSLL2(data []byte, p gopacket.PacketBuilder) error {
	if len(data) < 20 {
		p.SetTruncated()
		return badLink("Linux SLL2 header shorter than 20 bytes")
	}
	if data[2] != 0 || data[3] != 0 || data[10] > 6 || data[11] > 8 {
		return badLink("invalid Linux SLL2 reserved/packet-type/address-length fields")
	}
	sll := &layers.LinuxSLL2{}
	if err := sll.DecodeFromBytes(data, p); err != nil {
		return err
	}
	p.AddLayer(sll)
	p.SetLinkLayer(sll)
	if uint16(sll.ProtocolType) == 0x8035 && sll.ARPHardwareType == 1 {
		return p.NextDecoder(layers.LayerTypeARP)
	}
	if sll.NextLayerType() == gopacket.LayerTypeZero {
		return unsupportedLink("unsupported Linux SLL2 hardware/protocol %d/0x%04x", sll.ARPHardwareType, uint16(sll.ProtocolType))
	}
	return p.NextDecoder(sll.NextLayerType())
}
