package packet

import (
	"encoding/hex"
	"github.com/dreadl0ck/netcap/internal/linkaudit"
	"github.com/dreadl0ck/netcap/types"
	"github.com/gogo/protobuf/proto"
	"github.com/gopacket/gopacket"
)

var ieee802154Decoder = newPacketDecoder(types.Type_NC_IEEE802154, "IEEE802154", "IEEE 802.15.4 MAC metadata; protected and compressed payloads remain explicitly opaque", nil, func(p gopacket.Packet) proto.Message {
	l, ok := p.Layer(linkaudit.LayerIEEE802154).(*linkaudit.IEEE802154)
	if !ok {
		return nil
	}
	return &types.IEEE802154{Timestamp: p.Metadata().Timestamp.UnixNano(), FrameControl: uint32(l.FrameControl), FrameType: uint32(l.FrameControl & 7), FrameVersion: uint32(l.FrameControl >> 12 & 3), Sequence: uint32(l.Sequence), SequenceSuppressed: l.SequenceSuppressed, SourcePAN: hex.EncodeToString(l.SourcePAN), DestinationPAN: hex.EncodeToString(l.DestinationPAN), Source: hex.EncodeToString(l.Source), Destination: hex.EncodeToString(l.Destination), HeaderLength: uint32(l.HeaderLength), PayloadLength: uint32(len(l.Payload)), PayloadProtocol: l.PayloadProtocol, HasFCS: l.HasFCS, FCSValid: l.FCSValid, FCS: uint32(l.FCS)}
}, nil)
