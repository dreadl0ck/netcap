package types

import (
	"time"

	"github.com/dreadl0ck/netcap/encoder"
	"github.com/prometheus/client_golang/prometheus"
)

var fieldsPKTAP = []string{
	fieldTimestamp, "HeaderLength", "RecordType", "DLT", "InterfaceName", "Flags", "ProtocolFamily",
	"LinkLayerHeaderLength", "LinkLayerTrailerLength", "PID", "CommandName", "ServiceClass",
	"InterfaceType", "InterfaceUnit", "EffectivePID", "EffectiveCommandName", "Direction", "ServiceClassName",
	fieldSrcIP, fieldDstIP, fieldSrcPort, fieldDstPort, fieldCommunityID,
}

func (p *PKTAP) CSVHeader() []string { return filter(fieldsPKTAP) }
func (p *PKTAP) CSVRecord() []string {
	return filter([]string{
		formatTimestamp(p.Timestamp), formatUint32(p.HeaderLength), formatUint32(p.RecordType), formatUint32(p.DLT),
		p.InterfaceName, formatUint32(p.Flags), formatUint32(p.ProtocolFamily), formatUint32(p.LinkLayerHeaderLength),
		formatUint32(p.LinkLayerTrailerLength), formatUint32(p.PID), p.CommandName, formatUint32(p.ServiceClass),
		formatUint32(p.InterfaceType), formatUint32(p.InterfaceUnit), formatUint32(p.EffectivePID), p.EffectiveCommandName,
		p.Direction, p.ServiceClassName, p.SrcIP, p.DstIP, formatInt32(p.SrcPort), formatInt32(p.DstPort), p.CommunityID,
	})
}

func (p *PKTAP) Time() int64 { return p.Timestamp }
func (p *PKTAP) JSON() (string, error) {
	copy := *p
	copy.Timestamp /= int64(time.Millisecond)
	return jsonMarshaler.MarshalToString(&copy)
}

var pktapMetric = prometheus.NewCounter(prometheus.CounterOpts{Name: "nc_pktap", Help: "PKTAP audit records"})

func (p *PKTAP) Inc() { pktapMetric.Inc() }
func (p *PKTAP) SetPacketContext(ctx *PacketContext) {
	p.SrcIP, p.DstIP = ctx.SrcIP, ctx.DstIP
	p.SrcPort, p.DstPort = ctx.SrcPort, ctx.DstPort
	p.CommunityID = ctx.CommunityID
}
func (p *PKTAP) Src() string      { return p.SrcIP }
func (p *PKTAP) Dst() string      { return p.DstIP }
func (p *PKTAP) Analyze()         {}
func (p *PKTAP) NetcapType() Type { return Type_NC_PKTAP }

var pktapEncoder = encoder.NewValueEncoder()

func (p *PKTAP) Encode() []string {
	return filter([]string{
		pktapEncoder.Int64(fieldTimestamp, p.Timestamp), pktapEncoder.Uint32("HeaderLength", p.HeaderLength),
		pktapEncoder.Uint32("RecordType", p.RecordType), pktapEncoder.Uint32("DLT", p.DLT),
		pktapEncoder.String("InterfaceName", p.InterfaceName), pktapEncoder.Uint32("Flags", p.Flags),
		pktapEncoder.Uint32("ProtocolFamily", p.ProtocolFamily), pktapEncoder.Uint32("LinkLayerHeaderLength", p.LinkLayerHeaderLength),
		pktapEncoder.Uint32("LinkLayerTrailerLength", p.LinkLayerTrailerLength), pktapEncoder.Uint32("PID", p.PID),
		pktapEncoder.String("CommandName", p.CommandName), pktapEncoder.Uint32("ServiceClass", p.ServiceClass),
		pktapEncoder.Uint32("InterfaceType", p.InterfaceType), pktapEncoder.Uint32("InterfaceUnit", p.InterfaceUnit),
		pktapEncoder.Uint32("EffectivePID", p.EffectivePID), pktapEncoder.String("EffectiveCommandName", p.EffectiveCommandName),
		pktapEncoder.String("Direction", p.Direction), pktapEncoder.String("ServiceClassName", p.ServiceClassName),
		pktapEncoder.String(fieldSrcIP, p.SrcIP), pktapEncoder.String(fieldDstIP, p.DstIP),
		pktapEncoder.Int32(fieldSrcPort, p.SrcPort), pktapEncoder.Int32(fieldDstPort, p.DstPort),
		pktapEncoder.String(fieldCommunityID, p.CommunityID),
	})
}
