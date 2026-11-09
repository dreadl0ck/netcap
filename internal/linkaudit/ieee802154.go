package linkaudit

import (
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

var LayerIEEE802154 = gopacket.RegisterLayerType(12003, gopacket.LayerTypeMetadata{Name: "IEEE802.15.4", Decoder: gopacket.DecodeFunc(DecodeIEEE802154)})
var EndpointIEEE802154 = gopacket.RegisterEndpointType(12003, gopacket.EndpointTypeMetadata{Name: "IEEE802.15.4", Formatter: func(b []byte) string { return fmt.Sprintf("%x", b) }})
var ErrUnsupported = errors.New("unsupported IEEE 802.15.4 format")

type IEEE802154 struct {
	layers.BaseLayer
	FrameControl                                   uint16
	Sequence                                       byte
	SequenceSuppressed                             bool
	DestinationPAN, SourcePAN, Destination, Source []byte
	HeaderLength                                   int
	PayloadProtocol                                string
	HasFCS, FCSValid                               bool
	FCS                                            uint16
}

func (*IEEE802154) LayerType() gopacket.LayerType { return LayerIEEE802154 }
func (l *IEEE802154) LinkFlow() gopacket.Flow {
	a := append(append([]byte(nil), l.SourcePAN...), l.Source...)
	b := append(append([]byte(nil), l.DestinationPAN...), l.Destination...)
	return gopacket.NewFlow(EndpointIEEE802154, a, b)
}
func (l *IEEE802154) ScopeTag() string {
	a, b := fmt.Sprintf("%x", l.SourcePAN), fmt.Sprintf("%x", l.DestinationPAN)
	if a > b {
		a, b = b, a
	}
	return "/pan:" + a + ":" + b
}

func DecodeIEEE802154(data []byte, p gopacket.PacketBuilder) error    { return decode(data, p, false) }
func DecodeIEEE802154FCS(data []byte, p gopacket.PacketBuilder) error { return decode(data, p, true) }

func decode(data []byte, p gopacket.PacketBuilder, fcs bool) error {
	var trailer uint16
	valid := false
	if fcs {
		if len(data) < 4 {
			p.SetTruncated()
			return fmt.Errorf("short IEEE 802.15.4 FCS frame")
		}
		trailer = binary.LittleEndian.Uint16(data[len(data)-2:])
		data = data[:len(data)-2]
		valid = crc16(data) == trailer
	}
	if len(data) < 2 {
		p.SetTruncated()
		return fmt.Errorf("IEEE 802.15.4 header shorter than two bytes")
	}
	fcf := binary.LittleEndian.Uint16(data)
	version, dst, src, kind := (fcf>>12)&3, (fcf>>10)&3, (fcf>>14)&3, fcf&7
	if dst == 1 || src == 1 || fcf&0x80 != 0 {
		return fmt.Errorf("invalid IEEE 802.15.4 control/address format")
	}
	if version == 3 || kind > 3 {
		return ErrUnsupported
	}
	l := &IEEE802154{FrameControl: fcf, SequenceSuppressed: fcf&0x100 != 0, HasFCS: fcs, FCS: trailer, FCSValid: valid, PayloadProtocol: "opaque"}
	offset := 2
	if version < 2 && fcf&0x300 != 0 {
		return fmt.Errorf("IEEE 802.15.4 legacy frame uses sequence suppression/IE bits")
	}
	take := func(n int) []byte {
		if n > len(data)-offset {
			return nil
		}
		b := data[offset : offset+n]
		offset += n
		return b
	}
	if !l.SequenceSuppressed {
		seq := take(1)
		if seq == nil {
			p.SetTruncated()
			return fmt.Errorf("truncated IEEE 802.15.4 sequence")
		}
		l.Sequence = seq[0]
	}
	compressed := fcf&0x40 != 0
	dstPAN, srcPAN := dst != 0, src != 0 && !compressed
	if version < 2 && compressed && (src == 0 || dst == 0) {
		return fmt.Errorf("IEEE 802.15.4 PAN compression without both addresses")
	}
	if version == 2 {
		switch {
		case dst == 0 && src == 0:
			dstPAN, srcPAN = compressed, false
		case dst == 0:
			dstPAN, srcPAN = false, !compressed
		case src == 0:
			dstPAN, srcPAN = !compressed, false
		case dst == 3 && src == 3:
			dstPAN, srcPAN = !compressed, false
		default:
			dstPAN, srcPAN = true, !compressed
		}
	}
	if dstPAN {
		l.DestinationPAN = take(2)
		if l.DestinationPAN == nil {
			p.SetTruncated()
			return fmt.Errorf("truncated IEEE 802.15.4 destination PAN")
		}
	}
	address := func(mode uint16) []byte {
		if mode == 0 {
			return nil
		}
		if mode == 2 {
			return take(2)
		}
		return take(8)
	}
	l.Destination = address(dst)
	if dst != 0 && l.Destination == nil {
		p.SetTruncated()
		return fmt.Errorf("truncated IEEE 802.15.4 destination")
	}
	if srcPAN {
		l.SourcePAN = take(2)
		if l.SourcePAN == nil {
			p.SetTruncated()
			return fmt.Errorf("truncated IEEE 802.15.4 source PAN")
		}
	} else {
		l.SourcePAN = l.DestinationPAN
	}
	l.Source = address(src)
	if src != 0 && l.Source == nil {
		p.SetTruncated()
		return fmt.Errorf("truncated IEEE 802.15.4 source")
	}
	l.HeaderLength = offset
	l.BaseLayer = layers.BaseLayer{Contents: data[:offset], Payload: data[offset:]}
	if fcf&8 != 0 {
		l.PayloadProtocol = "protected"
	} else if kind == 1 && fcf&0x200 == 0 && len(l.Payload) > 0 {
		if l.Payload[0] == 0x41 {
			l.PayloadProtocol = "6lowpan-ipv6"
			l.Contents = data[:offset+1]
			l.Payload = data[offset+1:]
		} else if l.Payload[0]&0xe0 == 0x60 {
			l.PayloadProtocol = "6lowpan-iphc"
		}
	}
	p.AddLayer(l)
	p.SetLinkLayer(l)
	if l.PayloadProtocol == "6lowpan-ipv6" {
		return p.NextDecoder(layers.LayerTypeIPv6)
	}
	if len(l.Payload) > 0 {
		return p.NextDecoder(gopacket.LayerTypePayload)
	}
	return nil
}

func crc16(data []byte) uint16 {
	crc := uint16(0)
	for _, b := range data {
		crc ^= uint16(b)
		for range 8 {
			if crc&1 != 0 {
				crc = crc>>1 ^ 0x8408
			} else {
				crc >>= 1
			}
		}
	}
	return crc
}
