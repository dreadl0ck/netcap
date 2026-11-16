package packet

import (
	"bytes"

	decoderconfig "github.com/dreadl0ck/netcap/internal/decoder/config"
	"github.com/dreadl0ck/netcap/internal/linkaudit"
	"github.com/dreadl0ck/netcap/types"
	"github.com/gogo/protobuf/proto"
	"github.com/gopacket/gopacket"
)

var linkFrameDecoder = newPacketDecoder(types.Type_NC_LinkFrame, "LinkFrame", "Validated bus/link framing and raw header evidence; undecoded upper layers remain explicitly opaque", nil, func(p gopacket.Packet) proto.Message {
	l, ok := p.Layer(linkaudit.LayerLinkFrame).(*linkaudit.LinkFrame)
	if !ok {
		return nil
	}
	r := &types.LinkFrame{Timestamp: p.Metadata().Timestamp.UnixNano(), LinkType: l.Type, Protocol: l.Protocol, Source: l.Source, Destination: l.Destination, HeaderLength: uint32(len(l.Header)), PayloadLength: uint32(len(l.Payload)), PayloadProtocol: l.PayloadProtocol, Header: bytes.Clone(l.Header), Fields: l.Fields, Qualifications: l.Qualifications}
	if decoderconfig.Instance.IncludePayloads {
		r.Payload = bytes.Clone(l.Payload)
	}
	return r
}, nil)
