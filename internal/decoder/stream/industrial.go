package stream

import (
	"sync/atomic"

	"github.com/dreadl0ck/netcap/internal/decoder"
	"github.com/dreadl0ck/netcap/internal/decoder/core"
	"github.com/dreadl0ck/netcap/internal/decoder/stream/otframe"
	"github.com/dreadl0ck/netcap/internal/decoder/stream/s7comm"
	"github.com/dreadl0ck/netcap/types"
	"github.com/gogo/protobuf/proto"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

var otStreams = map[int32]*decoder.AbstractDecoder{
	102: {Name: "MMS", Type: types.Type_NC_MMS, Description: "IEC 61850 Manufacturing Message Specification"}, 2404: {Name: "IEC104", Type: types.Type_NC_IEC104, Description: "IEC 60870-5-104 control and information messages"}, 48898: {Name: "AMS", Type: types.Type_NC_AMS, Description: "AMS/ADS over TCP"},
}

func ObserveIndustrial(c *core.ConversationInfo, primary string) {
	port := c.ServerPort
	if otStreams[port] == nil {
		port = c.ClientPort
	}
	d := otStreams[port]
	if d == nil {
		return
	}
	fallbackS7 := port == 102 && primary != "S7Comm" && primary != "RDP" && configuredDecoder("S7Comm") && s7comm.Decoder.Writer != nil
	if d.Writer == nil && !fallbackS7 {
		return
	}
	if primary == "RDP" {
		return
	}
	split, _, _ := layers.OTStreamDecoder(layers.TCPPort(port))
	limit := map[int32]int{102: 65535, 2404: 255, 48898: (16 << 20) + 6}[port]
	var iso [2]otframe.ISO
	var s7 [2]s7comm.Assembly
	var identified [2]bool
	write := func(side int, r proto.Message) {
		if r == nil || d.Writer == nil {
			return
		}
		identified[side] = true
		if err := d.Writer.Write(r); err != nil {
			c.FragmentError = err
		} else {
			atomic.AddInt64(&d.NumRecordsWritten, 1)
		}
	}
	otframe.Walk(c, split, limit, func(f otframe.Frame) {
		a := &types.OTAssembly{Status: "complete", FirstTimestamp: f.At, Pieces: 1}
		switch port {
		case 102:
			u, err := iso[f.Side].Feed(f)
			if err != nil {
				return
			}
			if fallbackS7 {
				s7[f.Side].Observe(c, u, false)
			}
			if u.Type != layers.LayerTypeISOSession {
				return
			}
			p := gopacket.NewPacket(u.Data, u.Type, gopacket.Default)
			m, ok := p.Layer(layers.LayerTypeMMS).(*layers.MMS)
			if !ok {
				return
			}
			a.FirstTimestamp, a.Pieces = u.At, u.Pieces
			r := &types.MMS{Context: f.Context, Timestamp: u.At, PDUType: m.Type.String(), InvokeID: m.InvokeID, Assembly: a}
			if !m.NoService {
				switch m.Type {
				case layers.MMSConfirmedRequest, layers.MMSConfirmedResponse:
					r.Service = m.Service.String()
				case layers.MMSUnconfirmed:
					r.Service = m.Unconfirmed.String()
				}
			}
			if m.ServiceDecodeErr != nil {
				r.ServiceError = m.ServiceDecodeErr.Error()
				a.Status = "incomplete"
			}
			write(f.Side, r)
		case 2404:
			var p layers.IEC104
			if p.DecodeFromBytes(f.Data, gopacket.NilDecodeFeedback) != nil || p.Skipped != 0 || p.Faults != 0 {
				return
			}
			r := &types.IEC104{Timestamp: f.At, Context: f.Context, Assembly: a, Format: p.Format.String(), SendSequence: uint32(p.SendSeq), ReceiveSequence: uint32(p.RecvSeq), TypeID: uint32(p.ASDU.TypeID), CommonAddress: uint32(p.ASDU.CommonAddr), Cause: uint32(p.ASDU.Cause), ObjectCount: uint32(p.ASDU.NumObjects)}
			if p.UFunction != 0 {
				r.UFunction = p.UFunction.String()
			}
			write(f.Side, r)
		case 48898:
			var p layers.EtherCATAMSTCP
			if p.DecodeFromBytes(f.Data, gopacket.NilDecodeFeedback) != nil || len(p.PDUs) != 1 {
				return
			}
			v := p.PDUs[0]
			if v.Truncated {
				return
			}
			r := &types.AMS{Timestamp: f.At, Context: f.Context, Assembly: a, Command: v.Command.String(), Length: v.Length}
			switch v.Command {
			case layers.EtherCATAMSTCPPacket:
				m := v.AMS
				if m == nil || m.Length != uint32(len(m.Data)) {
					return
				}
				r.ADSCommand = m.Command.String()
				r.InvokeID = m.InvokeID
				r.ErrorCode = uint32(m.ErrorCode)
				r.TargetNetID = m.TargetNetID.String()
				r.SourceNetID = m.SourceNetID.String()
			case layers.EtherCATAMSTCPPortClose, layers.EtherCATAMSTCPPortConnect, layers.EtherCATAMSTCPRouterNote, layers.EtherCATAMSTCPGetLocalAddr:
			default:
				return
			}
			write(f.Side, r)
		}
	}, func(f otframe.Frame, why string) {
		pending := iso[f.Side].Pending()
		iso[f.Side] = otframe.ISO{}
		if fallbackS7 {
			s7[f.Side].Reset(c, f, why)
		}
		if !identified[f.Side] || why == "EOF" && !pending {
			return
		}
		a := &types.OTAssembly{Status: "incomplete", Reason: why, FirstTimestamp: f.At}
		switch port {
		case 102:
			write(f.Side, &types.MMS{Timestamp: f.At, Context: f.Context, Assembly: a})
		case 2404:
			write(f.Side, &types.IEC104{Timestamp: f.At, Context: f.Context, Assembly: a})
		case 48898:
			write(f.Side, &types.AMS{Timestamp: f.At, Context: f.Context, Assembly: a})
		}
	})
}
