package stream

import (
	"encoding/binary"
	"sync/atomic"

	"github.com/dreadl0ck/netcap/internal/decoder"
	"github.com/dreadl0ck/netcap/internal/decoder/core"
	"github.com/dreadl0ck/netcap/internal/decoder/stream/iec62351"
	"github.com/dreadl0ck/netcap/internal/decoder/stream/otframe"
	"github.com/dreadl0ck/netcap/internal/decoder/stream/s7comm"
	"github.com/dreadl0ck/netcap/types"
	"github.com/gogo/protobuf/proto"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

var otStreams = map[int32]*decoder.AbstractDecoder{
	102:   {Name: "MMS", Type: types.Type_NC_MMS, Description: "IEC 61850 Manufacturing Message Specification"},
	2404:  {Name: "IEC104", Type: types.Type_NC_IEC104, Description: "IEC 60870-5-104 control and information messages"},
	48898: {Name: "AMS", Type: types.Type_NC_AMS, Description: "AMS/ADS over TCP"},
}

// tpktPrefix is a carrier probe only. No application record is emitted on its evidence.
func tpktPrefix(c *core.ConversationInfo) bool {
	for _, fragments := range []core.DataFragments{c.ClientData, c.ServerData} {
		var h [7]byte
		n := 0
		for _, fragment := range fragments {
			if s, ok := fragment.(*core.StreamData); ok && n > 0 && (s.SkippedBytes != 0 || s.DiscardedBytes != 0) {
				break
			}
			n += copy(h[n:], fragment.Raw())
			if n == len(h) {
				break
			}
		}
		if n == len(h) && h[0] == 3 && h[1] == 0 && h[4] >= 2 && int(binary.BigEndian.Uint16(h[2:4])) >= 5+int(h[4]) {
			switch h[5] & 0xf0 {
			case 0xe0, 0xd0, 0xf0:
				return true
			}
		}
	}
	return false
}

// ObserveIndustrial reports whether it also ran the selected primary decoder.
func ObserveIndustrial(c *core.ConversationInfo, primary string) bool {
	if primary != "" && primary != "S7Comm" && primary != "IEC62351" {
		return false
	}
	port := c.ServerPort
	if otStreams[port] == nil {
		port = c.ClientPort
	}
	if primary == "S7Comm" || (otStreams[port] == nil && (otStreams[102].Writer != nil || s7comm.Decoder.Writer != nil) && tpktPrefix(c)) {
		port = 102
	}
	d := otStreams[port]
	if d == nil {
		return false
	}
	handleS7 := port == 102 && configuredDecoder("S7Comm") && s7comm.Decoder.Writer != nil
	handleSecurity := port == 2404 && configuredDecoder("IEC62351") && iec62351.Decoder.Writer != nil
	if d.Writer == nil && !handleS7 && !handleSecurity {
		return false
	}
	split, _, _ := layers.OTStreamDecoder(layers.TCPPort(port))
	limit := map[int32]int{102: 65535, 2404: 255, 48898: (16 << 20) + 6}[port]
	var iso [2]otframe.ISO
	var s7 [2]s7comm.Assembly
	var security [2]iec62351.IEC104Assembly
	owned := primary == "S7Comm" && handleS7
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
			if handleS7 {
				s7[f.Side].Observe(c, u, primary == "S7Comm")
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
			if handleSecurity {
				if sec := security[f.Side].Record(&p, f); sec != nil {
					if primary == "IEC62351" {
						owned = true
					}
					if err := iec62351.Decoder.Writer.Write(sec); err != nil {
						c.FragmentError = err
					} else {
						atomic.AddInt64(&iec62351.Decoder.NumRecordsWritten, 1)
					}
				}
			}
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
		security[f.Side] = iec62351.IEC104Assembly{}
		if handleS7 {
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
	return owned
}
