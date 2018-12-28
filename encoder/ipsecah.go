package encoder

import (
	"github.com/dreadl0ck/netcap/types"
	"github.com/golang/protobuf/proto"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

var ipSecAHEncoder = CreateLayerEncoder(types.Type_NC_IPSecAH, layers.LayerTypeIPSecAH, func(layer gopacket.Layer, timestamp string) proto.Message {
	if ipsecah, ok := layer.(*layers.IPSecAH); ok {
		return &types.IPSecAH{
			Timestamp:          timestamp,
			Reserved:           int32(ipsecah.Reserved),    // int32
			SPI:                int32(ipsecah.SPI),         // int32
			Seq:                int32(ipsecah.Seq),         // int32
			AuthenticationData: ipsecah.AuthenticationData, // []byte
		}
	}
	return nil
})
