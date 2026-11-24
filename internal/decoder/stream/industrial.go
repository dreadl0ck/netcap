package stream

import (
	"github.com/dreadl0ck/netcap/internal/decoder"
	"github.com/dreadl0ck/netcap/internal/decoder/core"
	"github.com/dreadl0ck/netcap/types"
	"github.com/gogo/protobuf/proto"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"sync/atomic"
)

var otStreams = map[int32]*decoder.AbstractDecoder{
	102:   {Name: "MMS", Type: types.Type_NC_MMS, Description: "Manufacturing Message Specification over ISO presentation"},
	2404:  {Name: "IEC104", Type: types.Type_NC_IEC104, Description: "IEC 60870-5-104 control and information messages"},
	48898: {Name: "AMS", Type: types.Type_NC_AMS, Description: "AMS/ADS over TCP"},
}

// These observers share ports with existing decoders (notably IEC62351 and S7).
func ObserveIndustrial(c *core.ConversationInfo) {
	port := c.ServerPort
	d := otStreams[port]
	if d == nil {
		port = c.ClientPort
		d = otStreams[port]
	}
	if d == nil || d.Writer == nil {
		return
	}
	split, lt, _ := layers.OTStreamDecoder(layers.TCPPort(port))
	type half struct {
		buf   []byte
		start int64
		cotp  layers.COTPAssembler
		lost  bool
	}
	var halves [2]half
	for f := range c.Fragments() {
		i := 0
		if core.FromServer(f) {
			i = 1
		}
		h := &halves[i]
		s, ok := f.(*core.StreamData)
		if !ok {
			continue
		}
		if s.SkippedBytes != 0 || s.DiscardedBytes > 0 {
			*h = half{}
		}
		if h.lost {
			continue
		}
		data := f.Raw()
		ts := f.CaptureInfo().Timestamp.UnixNano()
		src, dst, sp, dp := c.Endpoints(f)
		ctx := &types.PacketContext{SrcIP: src, DstIP: dst, SrcPort: sp, DstPort: dp, NetworkScope: c.NetworkScope, CommunityID: c.CommunityID}
		for len(data) > 0 {
			if len(h.buf) == 0 {
				h.start = ts
			}
			n := min(len(data), 1<<20-len(h.buf))
			if n == 0 {
				h.lost = true
				h.buf = nil
				break
			}
			h.buf = append(h.buf, data[:n]...)
			data = data[n:]
			for len(h.buf) > 0 {
				adv, tok, err := split(h.buf, false)
				if err != nil {
					h.lost = true
					h.buf = nil
					break
				}
				if adv == 0 {
					break
				}
				if tok != nil {
					msg := industrialPDU(lt, tok, &h.cotp, h.start, ctx)
					if msg != nil {
						if err := d.Writer.Write(msg); err != nil {
							c.FragmentError = err
							return
						}
						atomic.AddInt64(&d.NumRecordsWritten, 1)
					}
				}
				h.buf = h.buf[adv:]
				h.start = ts
			}
			if h.lost {
				break
			}
		}
	}
}

func industrialPDU(lt gopacket.LayerType, b []byte, cotp *layers.COTPAssembler, ts int64, ctx *types.PacketContext) proto.Message {
	switch lt {
	case layers.LayerTypeIEC104:
		var p layers.IEC104
		if p.DecodeFromBytes(b, gopacket.NilDecodeFeedback) != nil || p.Faults != 0 || p.Skipped != 0 {
			return nil
		}
		r := &types.IEC104{Timestamp: ts, Context: ctx, Format: p.Format.String(), SendSequence: uint32(p.SendSeq), ReceiveSequence: uint32(p.RecvSeq), TypeID: uint32(p.ASDU.TypeID), CommonAddress: uint32(p.ASDU.CommonAddr), Cause: uint32(p.ASDU.Cause), ObjectCount: uint32(p.ASDU.NumObjects)}
		if p.UFunction != 0 {
			r.UFunction = p.UFunction.String()
		}
		return r
	case layers.LayerTypeEtherCATAMSTCP:
		var p layers.EtherCATAMSTCP
		if p.DecodeFromBytes(b, gopacket.NilDecodeFeedback) != nil || len(p.PDUs) != 1 {
			return nil
		}
		v := p.PDUs[0]
		if v.Truncated {
			return nil
		}
		r := &types.AMS{Timestamp: ts, Context: ctx, Command: v.Command.String(), Length: v.Length}
		if a := v.AMS; a != nil {
			r.ADSCommand = a.Command.String()
			r.InvokeID = a.InvokeID
			r.ErrorCode = uint32(a.ErrorCode)
			r.TargetNetID = a.TargetNetID.String()
			r.SourceNetID = a.SourceNetID.String()
		}
		return r
	case layers.LayerTypeTPKT:
		var t layers.TPKT
		var c layers.COTP
		if t.DecodeFromBytes(b, gopacket.NilDecodeFeedback) != nil || c.DecodeFromBytes(t.Payload, gopacket.NilDecodeFeedback) != nil {
			cotp.Reset()
			return nil
		}
		body, next, err := cotp.Feed(&c)
		if err != nil || next != layers.LayerTypeISOSession {
			return nil
		}
		p := gopacket.NewPacket(body, next, gopacket.Default)
		m, ok := p.Layer(layers.LayerTypeMMS).(*layers.MMS)
		if !ok {
			return nil
		}
		r := &types.MMS{Timestamp: ts, Context: ctx, PDUType: m.Type.String(), InvokeID: m.InvokeID}
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
		}
		return r
	}
	return nil
}
