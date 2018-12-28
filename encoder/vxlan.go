package encoder

import (
	"github.com/dreadl0ck/netcap/types"
	"github.com/golang/protobuf/proto"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

var vxlanEncoder = CreateLayerEncoder(types.Type_NC_VXLAN, layers.LayerTypeVXLAN, func(layer gopacket.Layer, timestamp string) proto.Message {
	if vx, ok := layer.(*layers.VXLAN); ok {
		return &types.VXLAN{
			Timestamp:        timestamp,
			ValidIDFlag:      bool(vx.ValidIDFlag),
			VNI:              uint32(vx.VNI),
			GBPExtension:     bool(vx.GBPExtension),
			GBPDontLearn:     bool(vx.GBPDontLearn),
			GBPApplied:       bool(vx.GBPApplied),
			GBPGroupPolicyID: int32(vx.GBPGroupPolicyID),
		}
	}
	return nil
})
