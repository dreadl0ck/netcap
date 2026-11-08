package packet

import (
	"github.com/dreadl0ck/netcap/internal/sipaudit"
	"github.com/dreadl0ck/netcap/types"
	"github.com/gogo/protobuf/proto"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

func init() {
	// Keep the established layer type for selection, but use the shared parser
	// before gopacket can discard compact headers or segmented TCP messages.
	gopacket.OverrideLayerType(int(layers.LayerTypeSIP), gopacket.LayerTypeMetadata{Name: "SIP", Decoder: gopacket.DecodeFunc(func(data []byte, p gopacket.PacketBuilder) error {
		wire, _, err := sipaudit.Parse(data, false)
		if err != nil {
			return err
		}
		p.AddLayer(wire)
		p.SetApplicationLayer(wire)
		return nil
	})})
}

var sipDecoder = newGoPacketDecoder(types.Type_NC_SIP, layers.LayerTypeSIP,
	"Session Initiation Protocol signaling", func(layer gopacket.Layer, at int64) proto.Message {
		if wire, ok := layer.(*layers.SIP); ok {
			return sipaudit.Record(wire, at)
		}
		return nil
	})
