package collector

import (
	"fmt"
	"sort"
	"sync/atomic"
	"time"

	"github.com/dreadl0ck/netcap/internal/decoder"
	"github.com/dreadl0ck/netcap/internal/decoder/core"
	"github.com/dreadl0ck/netcap/internal/decoder/packet"
	"github.com/dreadl0ck/netcap/internal/decoder/stream/bacnetip"
	"github.com/dreadl0ck/netcap/internal/decoder/stream/dnp3"
	"github.com/dreadl0ck/netcap/internal/linkaudit"
	"github.com/dreadl0ck/netcap/internal/packetview"
	"github.com/dreadl0ck/netcap/types"
	"github.com/gogo/protobuf/proto"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

type industrialRecord interface {
	proto.Message
	types.AuditRecord
}
type industrialEvent struct {
	record industrialRecord
	scope  string
}
type industrialSink struct {
	d     core.DecoderAPI
	count *int64
}
type industrialCapture struct {
	sinks            map[types.Type]industrialSink
	bacnet           bacnetip.Assembly
	pn               map[string]*pnTransfer
	ec               map[string]*ecTransfer
	dnp              map[string]*udpDNP
	nextSweep        int64
	payload, metrics bool
}
type udpDNP struct {
	d    dnp3.Datagrams
	last int64
}

const industrialMaxTransfers = 64
const industrialIdle = int64(30 * time.Second)

func (c *Collector) initIndustrial() {
	o := &industrialCapture{sinks: make(map[types.Type]industrialSink), pn: make(map[string]*pnTransfer), ec: make(map[string]*ecTransfer), dnp: make(map[string]*udpDNP), payload: c.config.DecoderConfig.IncludePayloads, metrics: c.config.DecoderConfig.ExportMetrics}
	for _, d := range c.streamDecoders {
		switch d.GetType() {
		case types.Type_NC_DNP3:
			if c.config.ReassembleConnections {
				continue
			}
			fallthrough
		case types.Type_NC_BACnetIP, types.Type_NC_PROFINET:
			o.sinks[d.GetType()] = industrialSink{d, &d.(*decoder.StreamDecoder).NumRecordsWritten}
		}
	}
	for _, d := range c.abstractDecoders {
		if d.GetType() == types.Type_NC_EtherCAT {
			o.sinks[d.GetType()] = industrialSink{d, &d.(*decoder.AbstractDecoder).NumRecordsWritten}
		}
	}
	_, c.config.DecoderConfig.PacketBACnet = o.sinks[types.Type_NC_BACnetIP]
	if len(o.sinks) > 0 {
		c.industrial = o
	}
}
func (o *industrialCapture) write(e industrialEvent) error {
	sink := o.sinks[e.record.NetcapType()]
	w := sink.d.GetWriter()
	var err error
	if sw, ok := w.(interface {
		WriteScoped(proto.Message, string) error
	}); ok {
		err = sw.WriteScoped(e.record, e.scope)
	} else {
		err = w.Write(e.record)
	}
	if err == nil {
		atomic.AddInt64(sink.count, 1)
		if o.metrics {
			e.record.Inc()
		}
	}
	return err
}
func (o *industrialCapture) enabled(t types.Type) bool { _, ok := o.sinks[t]; return ok }

func (o *industrialCapture) observe(p, original gopacket.Packet) []industrialEvent {
	at := original.Metadata().Timestamp.UnixNano()
	var out []industrialEvent
	if at >= o.nextSweep {
		out = o.expire(at-industrialIdle, false)
		o.nextSweep = at + int64(time.Second)
	}
	if p == nil {
		if l, ok := original.Layer(linkaudit.LayerLinkFrame).(*linkaudit.LinkFrame); ok && l.Type == 165 {
			p = original
		} else {
			return out
		}
	}
	var kind types.Type
	var carrier string
	switch {
	case p.Layer(layers.LayerTypeProfinet) != nil || p.Layer(layers.LayerTypeProfinetIORPC) != nil:
		kind = types.Type_NC_PROFINET
	case p.Layer(layers.LayerTypeEtherCAT) != nil:
		kind = types.Type_NC_EtherCAT
	case p.Layer(layers.LayerTypeBVLC) != nil:
		kind, carrier = types.Type_NC_BACnetIP, "BACnet/IP"
	case p.Layer(layers.LayerTypeBVLC6) != nil:
		kind, carrier = types.Type_NC_BACnetIP, "BACnet/IPv6"
	case p.Layer(layers.LayerTypeDNP3) != nil && p.Layer(layers.LayerTypeUDP) != nil:
		kind = types.Type_NC_DNP3
	default:
		l, ok := p.Layer(linkaudit.LayerLinkFrame).(*linkaudit.LinkFrame)
		if !ok || l.Type != 165 {
			return out
		}
		kind, carrier = types.Type_NC_BACnetIP, "MS/TP"
	}
	if !o.enabled(kind) {
		return out
	}
	ctx := &types.PacketContext{}
	packetview.FillContext(ctx, p)
	ctx.CommunityID = packet.CalcCommunityID(p)
	if l := p.LinkLayer(); l != nil {
		ctx.SrcMAC, ctx.DstMAC = l.LinkFlow().Src().String(), l.LinkFlow().Dst().String()
	}
	if n := p.NetworkLayer(); n != nil {
		ctx.SrcIP, ctx.DstIP = n.NetworkFlow().Src().String(), n.NetworkFlow().Dst().String()
	}
	if u, ok := p.TransportLayer().(*layers.UDP); ok {
		ctx.SrcPort, ctx.DstPort = int32(u.SrcPort), int32(u.DstPort)
	}
	route := fmt.Sprintf("%s/%s/%s/%s/%d/%s/%d", ctx.NetworkScope, ctx.SrcMAC, ctx.DstMAC, ctx.SrcIP, ctx.SrcPort, ctx.DstIP, ctx.DstPort)
	var r industrialRecord
	switch kind {
	case types.Type_NC_BACnetIP:
		if carrier == "MS/TP" {
			p = gopacket.NewPacket(p.Data(), layers.LayerTypeBACnetMSTP, gopacket.NoCopy)
		}
		if b := o.bacnet.Decode(p, route, carrier, ctx, at, o.payload); b != nil {
			r = b
		}
	case types.Type_NC_PROFINET:
		if pn := o.profinet(p, ctx, route, at); pn != nil {
			r = pn
		}
	case types.Type_NC_EtherCAT:
		r = o.ethercat(p.Layer(layers.LayerTypeEtherCAT).(*layers.EtherCAT), ctx, at)
	case types.Type_NC_DNP3:
		s := o.dnp[route]
		if s == nil {
			if len(o.dnp) >= industrialMaxTransfers {
				return append(out, industrialEvent{&types.DNP3{Timestamp: at, CommunityID: ctx.CommunityID, ParseStatus: "lost", ParseError: "UDP assembly limit"}, ctx.NetworkScope})
			}
			s = &udpDNP{}
			o.dnp[route] = s
		}
		s.last = at
		s.d.Decode(p.Layer(layers.LayerTypeUDP).(*layers.UDP).Payload, ctx, at, func(d *types.DNP3) { out = append(out, industrialEvent{d, ctx.NetworkScope}) })
	}
	if r != nil {
		out = append(out, industrialEvent{r, ctx.NetworkScope})
	}
	return out
}

func (o *industrialCapture) expire(before int64, all bool) (out []industrialEvent) {
	why := "idle expiry"
	if all {
		why = "EOF"
	}
	o.bacnet.Flush(before, all, func(r *types.BACnetIP) { out = append(out, industrialEvent{r, r.NetworkScope}) })
	for k, v := range o.pn {
		if all || v.last < before {
			delete(o.pn, k)
			out = append(out, industrialEvent{&types.PROFINET{Timestamp: v.first, Context: v.ctx, FrameType: "Fragment", Assembly: &types.OTAssembly{FirstTimestamp: v.first, Pieces: v.count, Status: "incomplete", Reason: why}}, v.ctx.NetworkScope})
		}
	}
	for k, v := range o.ec {
		if all || v.last < before {
			delete(o.ec, k)
			m := &types.MailboxTransfer{Station: uint32(v.station), Protocol: v.protocol, FirstTimestamp: v.first, Status: "incomplete: " + why}
			if t := v.join.FlushFoE(v.station); t != nil {
				m.Kind = t.Kind.String()
				m.Length = uint32(len(t.Data))
			}
			out = append(out, industrialEvent{&types.EtherCAT{Timestamp: v.first, Context: v.ctx, FrameType: "Mailbox", Mailboxes: []*types.MailboxTransfer{m}}, v.ctx.NetworkScope})
		}
	}
	for k, v := range o.dnp {
		if all || v.last < before {
			delete(o.dnp, k)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.scope != b.scope {
			return a.scope < b.scope
		}
		if a.record.Time() != b.record.Time() {
			return a.record.Time() < b.record.Time()
		}
		return a.record.String() < b.record.String()
	})
	return out
}
