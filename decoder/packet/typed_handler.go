package packet

import (
	"github.com/gogo/protobuf/proto"
	"github.com/gopacket/gopacket"
)

// typedLayerHandler adapts a typed converter to the runtime layer registry.
func typedLayerHandler[L gopacket.Layer](decode func(L, int64) proto.Message) goPacketDecoderHandler {
	return func(layer gopacket.Layer, timestamp int64) proto.Message {
		typed, ok := layer.(L)
		if !ok {
			return nil
		}
		return decode(typed, timestamp)
	}
}
