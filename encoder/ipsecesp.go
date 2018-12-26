package encoder

import (
	"github.com/dreadl0ck/netcap/types"
	"github.com/golang/protobuf/proto"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

var ipSecESPEncoder = CreateLayerEncoder(types.Type_NC_IPSecESP, layers.LayerTypeIPSecESP, func(layer gopacket.Layer, timestamp string) proto.Message {
	if ipsecesp, ok := layer.(*layers.IPSecESP); ok {
		return &types.IPSecESP{
			Timestamp:    timestamp,
			SPI:          int32(ipsecesp.SPI),            // int32
			Seq:          int32(ipsecesp.Seq),            // int32
			LenEncrypted: int32(len(ipsecesp.Encrypted)), // int32
		}
	}
	return nil
})
