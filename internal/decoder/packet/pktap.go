package packet

import (
	"github.com/gogo/protobuf/proto"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"

	"github.com/dreadl0ck/netcap/types"
)

var pktapDecoder = newGoPacketDecoder(types.Type_NC_PKTAP, layers.LayerTypePktap,
	"Apple PKTAP v1 capture metadata with interface, process, direction and service class",
	func(layer gopacket.Layer, timestamp int64) proto.Message {
		p, ok := layer.(*layers.PktapV1)
		if !ok {
			return nil
		}
		return &types.PKTAP{
			Timestamp: timestamp, HeaderLength: p.HeaderLength, RecordType: p.RecordType, DLT: p.DLT,
			InterfaceName: p.InterfaceName, Flags: p.Flags, ProtocolFamily: p.ProtocolFamily,
			LinkLayerHeaderLength: p.LinkLayerHeaderLength, LinkLayerTrailerLength: p.LinkLayerTrailerLength,
			PID: p.PID, CommandName: p.CommandName, ServiceClass: uint32(p.ServiceClass),
			InterfaceType: uint32(p.InterfaceType), InterfaceUnit: uint32(p.InterfaceUnit),
			EffectivePID: p.EffectivePID, EffectiveCommandName: p.EffectiveCommandName,
			Direction: p.Direction().String(), ServiceClassName: p.ServiceClass.String(),
		}
	})
