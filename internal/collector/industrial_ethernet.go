package collector

import (
	"encoding/binary"
	"fmt"
	"net"
	"strings"

	"github.com/dreadl0ck/netcap/types"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

type pnTransfer struct {
	join        layers.ProfinetFragAssembler
	ctx         *types.PacketContext
	first, last int64
	count       uint32
}
type ecTransfer struct {
	join        layers.EtherCATMailboxAssembler
	ctx         *types.PacketContext
	first, last int64
	station     uint16
	protocol    string
}

func (o *industrialCapture) profinet(p gopacket.Packet, ctx *types.PacketContext, route string, at int64) *types.PROFINET {
	r := &types.PROFINET{Timestamp: at, SrcIP: ctx.SrcIP, DstIP: ctx.DstIP, SrcPort: ctx.SrcPort, DstPort: ctx.DstPort, CommunityID: ctx.CommunityID, Context: ctx, Assembly: &types.OTAssembly{Status: "complete", FirstTimestamp: at, Pieces: 1}}
	if rpc, ok := p.Layer(layers.LayerTypeProfinetIORPC).(*layers.ProfinetIORPC); ok {
		if rpc.Interface() == layers.ProfinetRPCInterfaceOther {
			return nil
		}
		r.FrameType = "PNIO-RPC"
		r.ServiceName = rpc.Interface().String()
		r.SequenceNumber = rpc.SequenceNumber
		r.OperationType, r.OperationTypeName = int32(rpc.Opnum), rpc.Opnum.String()
		r.IsRequest = rpc.PacketType == layers.ProfinetRPCRequest
		if rpc.Fragmented() {
			r.Assembly.Status, r.Assembly.Reason = "incomplete", "RPC fragment"
		} else if len(rpc.Blocks) > 0 {
			pnBlock(r, &rpc.Blocks[0])
		}
		return r
	}
	v := p.Layer(layers.LayerTypeProfinet).(*layers.Profinet)
	r.FrameID, r.FrameType, r.FrameTypeName = int32(v.FrameID), v.FrameID.Class().String(), v.FrameID.Name()
	if v.FrameID.Class() == layers.ProfinetFrameClassFragment {
		key := fmt.Sprintf("%s/%04x", route, uint16(v.FrameID))
		s := o.pn[key]
		if s == nil {
			if v.FragStatus.Number() != 0 {
				r.Assembly.Status, r.Assembly.Reason = "incomplete", "missing first RT fragment"
				return r
			}
			if len(o.pn) >= industrialMaxTransfers {
				r.Assembly.Status, r.Assembly.Reason = "limited", "pending RT limit"
				return r
			}
			s = &pnTransfer{}
			o.pn[key] = s
		}
		if v.FragStatus.Number() == 0 {
			s.first, s.ctx, s.count = at, ctx, 0
		}
		s.count++
		s.last = at
		r.Assembly.FirstTimestamp, r.Assembly.Pieces = s.first, s.count
		src, _ := net.ParseMAC(ctx.SrcMAC)
		dst, _ := net.ParseMAC(ctx.DstMAC)
		frame, err := s.join.Add(src, dst, v)
		if err != nil {
			delete(o.pn, key)
			r.Assembly.Status, r.Assembly.Reason = "incomplete", err.Error()
			return r
		}
		if frame == nil {
			r.Assembly.Status = "pending"
			return r
		}
		delete(o.pn, key)
		if len(frame) < 2 {
			r.Assembly.Status = "malformed"
			return r
		}
		t := layers.EthernetType(binary.BigEndian.Uint16(frame))
		r.Timestamp = s.first
		if t != layers.EthernetTypeProfinet {
			r.FrameTypeName = t.String()
			r.IODataLength = int32(len(frame) - 2)
			return r
		}
		p = gopacket.NewPacket(frame[2:], layers.LayerTypeProfinet, gopacket.NoCopy)
		var ok bool
		v, ok = p.Layer(layers.LayerTypeProfinet).(*layers.Profinet)
		if !ok {
			r.Assembly.Status = "malformed"
			return r
		}
		r.FrameID, r.FrameTypeName = int32(v.FrameID), v.FrameID.Name()
	}
	if v.Security != nil && v.Security.Encrypted() {
		r.Assembly.Status = "opaque"
		return r
	}
	r.CycleCounter, r.DataStatus, r.TransferStatus = int32(v.CycleCounter), int32(v.DataStatus), int32(v.TransferStatus)
	r.IODataLength = int32(len(v.IOData))
	if d, ok := p.Layer(layers.LayerTypeProfinetDCP).(*layers.ProfinetDCP); ok {
		r.ServiceID, r.ServiceName = int32(d.ServiceID), d.ServiceID.String()
		r.SequenceNumber = d.Xid
		r.IsRequest = d.ServiceType == 0
		for _, b := range d.Blocks {
			if b.Option == 2 {
				switch b.Suboption {
				case 2:
					r.StationName = b.Name
				case 3:
					r.VendorID, r.DeviceID = fmt.Sprintf("0x%04x", b.VendorID), fmt.Sprintf("0x%04x", b.DeviceID)
				case 4:
					r.DeviceRole = fmt.Sprintf("0x%02x", b.Role)
				}
			}
		}
	}
	if t, ok := p.Layer(layers.LayerTypeProfinetPTCP).(*layers.ProfinetPTCP); ok {
		r.SequenceNumber = uint32(t.SequenceID)
	}
	if a, ok := p.Layer(layers.LayerTypeProfinetAlarm).(*layers.ProfinetAlarm); ok {
		r.IsAlarm = true
		r.SequenceNumber = uint32(a.SendSeqNum)
		if a.Block != nil {
			pnBlock(r, a.Block)
		}
	}
	if p.ErrorLayer() != nil {
		r.Assembly.Status, r.Assembly.Reason = "malformed", p.ErrorLayer().Error().Error()
	}
	return r
}
func pnBlock(r *types.PROFINET, b *layers.ProfinetBlock) {
	r.BlockType, r.BlockTypeName, r.BlockLength = int32(b.Type), b.Type.String(), int32(b.Length)
	r.BlockVersionHigh, r.BlockVersionLow = int32(b.VersionHigh), int32(b.VersionLow)
	if a := b.Alarm; a != nil {
		r.AlarmType, r.AlarmTypeName = int32(a.AlarmType), a.AlarmType.String()
		r.API, r.SlotNumber, r.SubslotNumber = a.API, int32(a.Slot), int32(a.Subslot)
	}
	if a := b.Record; a != nil {
		r.API, r.SlotNumber, r.SubslotNumber = a.API, int32(a.Slot), int32(a.Subslot)
	}
	if a := b.AR; a != nil {
		r.StationName = a.StationName
	}
}

func (o *industrialCapture) ethercat(v *layers.EtherCAT, ctx *types.PacketContext, at int64) *types.EtherCAT {
	r := &types.EtherCAT{Timestamp: at, Context: ctx, FrameType: v.Type.String(), Length: uint32(v.Length)}
	if v.Mailbox != nil {
		r.Mailboxes = append(r.Mailboxes, &types.MailboxTransfer{Protocol: v.Mailbox.Type.String(), Status: "observed", FirstTimestamp: at})
	}
	for i := range v.Datagrams {
		d := &v.Datagrams[i]
		r.Commands = append(r.Commands, d.Command.String())
		r.WorkingCounters = append(r.WorkingCounters, uint32(d.WorkingCounter))
		if d.Mailbox == nil {
			continue
		}
		a, b := fmt.Sprintf("%s/%s/%d", ctx.SrcMAC, ctx.SrcIP, ctx.SrcPort), fmt.Sprintf("%s/%s/%d", ctx.DstMAC, ctx.DstIP, ctx.DstPort)
		if a > b {
			a, b = b, a
		}
		m := &types.MailboxTransfer{Station: uint32(d.ADP()), Protocol: d.Mailbox.Type.String()}
		r.Mailboxes = append(r.Mailboxes, m)
		k := fmt.Sprintf("%s/%s/%s/%d/%d/%d", ctx.NetworkScope, a, b, d.ADP(), d.Mailbox.Channel, d.Mailbox.Type)
		s := o.ec[k]
		if s == nil {
			if len(o.ec) >= industrialMaxTransfers {
				m.Status = "limited"
				continue
			}
			s = &ecTransfer{ctx: ctx, first: at, station: d.ADP(), protocol: m.Protocol, join: layers.EtherCATMailboxAssembler{MaxOpen: 4, MaxBytes: 256 << 10}}
		}
		s.last = at
		m.FirstTimestamp = s.first
		t, status := s.join.Feed(d)
		m.Status = strings.ToLower(status.String())
		if t != nil {
			m.Kind = t.Kind.String()
			m.Length = uint32(len(t.Data))
			m.Index, m.SubIndex = uint32(t.Index), uint32(t.SubIndex)
			if t.Unfinished {
				m.Status = "incomplete"
			}
		}
		if s.join.Open() > 0 {
			o.ec[k] = s
		} else {
			delete(o.ec, k)
		}
	}
	return r
}
