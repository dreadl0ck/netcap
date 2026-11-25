package packet

import (
	"fmt"

	"github.com/dreadl0ck/netcap/types"
	"github.com/gogo/protobuf/proto"
	"github.com/gopacket/gopacket/layers"
)

func init() { layers.RegisterOTDecoders() }

var _ = newGoPacketDecoder(types.Type_NC_PTPv2, layers.LayerTypePTP, "IEEE 1588 precision time messages", typedLayerHandler(func(p *layers.PTP, t int64) proto.Message {
	return &types.PTPv2{Timestamp: t, MessageType: p.MessageType.String(), Domain: uint32(p.Domain), SequenceID: uint32(p.SequenceID), SourcePortIdentity: fmt.Sprint(p.SourcePort), CorrectionScaledNs: p.Correction, Flags: uint32(p.Flags), TLVCount: uint32(len(p.TLVs))}
}))

var _ = newGoPacketDecoder(types.Type_NC_GOOSE, layers.LayerTypeGOOSE, "IEC 61850 substation events", typedLayerHandler(func(p *layers.GOOSE, t int64) proto.Message {
	return &types.GOOSE{Timestamp: t, AppID: uint32(p.AppID), ControlBlock: p.GocbRef, DataSet: p.DatSet, GoID: p.GoID, State: p.StNum, Sequence: p.SqNum, Revision: p.ConfRev, Simulation: p.Simulation, TimeAllowedToLive: p.TimeAllowedToLive}
}))

var _ = newGoPacketDecoder(types.Type_NC_SampledValues, layers.LayerTypeSV, "IEC 61850 sampled values", typedLayerHandler(func(p *layers.SV, t int64) proto.Message {
	r := &types.SampledValues{Timestamp: t, AppID: uint32(p.AppID)}
	for _, a := range p.ASDUs {
		r.StreamID = append(r.StreamID, a.SvID)
		r.SampleCounter = append(r.SampleCounter, uint32(a.SmpCnt))
		r.Revision = append(r.Revision, a.ConfRev)
	}
	return r
}))

var _ = newGoPacketDecoder(types.Type_NC_OPCUAPubSub, layers.LayerTypeOPCUAPubSub, "OPC UA UADP NetworkMessages", typedLayerHandler(func(p *layers.OPCUAPubSub, t int64) proto.Message {
	r := &types.OPCUAPubSub{Timestamp: t, MessageType: p.Type.String(), Version: uint32(p.Version), Encrypted: p.Security.Flags&layers.OPCUAPubSubEncrypted != 0, Chunk: p.Chunk != nil}
	for _, id := range p.DataSetWriterIDs {
		r.DataSetWriterIDs = append(r.DataSetWriterIDs, uint32(id))
	}
	if p.PayloadError != nil {
		r.PayloadError = p.PayloadError.Error()
	}
	return r
}))
