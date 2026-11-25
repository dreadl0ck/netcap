package s7comm

import (
	"github.com/dreadl0ck/netcap/internal/decoder/core"
	"github.com/dreadl0ck/netcap/internal/decoder/stream/otframe"
	"github.com/dreadl0ck/netcap/types"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"sync/atomic"
)

type Assembly struct {
	ud          layers.S7CommUDAssembler
	plus        layers.S7CommPlusAssembler
	first       map[[3]byte]int64
	plusStart   int64
	plusPending bool
	uncertain   bool
}

func writeS7(c *core.ConversationInfo, f otframe.Frame, r *types.S7Comm) {
	if Decoder.Writer == nil {
		return
	}
	r.Timestamp = r.Assembly.FirstTimestamp
	r.SrcIP, r.DstIP = f.Context.SrcIP, f.Context.DstIP
	r.SrcPort, r.DstPort = f.Context.SrcPort, f.Context.DstPort
	r.CommunityID = c.CommunityID
	if err := Decoder.Writer.Write(r); err != nil {
		c.FragmentError = err
	} else {
		atomic.AddInt64(&Decoder.NumRecordsWritten, 1)
	}
}
func (s *Assembly) Reset(c *core.ConversationInfo, f otframe.Frame, reason string) {
	mark := func(at int64) {
		writeS7(c, f, &types.S7Comm{Assembly: &types.OTAssembly{Status: "incomplete", Reason: reason, FirstTimestamp: at}})
	}
	if s.plusPending {
		mark(s.plusStart)
	}
	for _, at := range s.first {
		mark(at)
	}
	*s = Assembly{uncertain: reason != "EOF"}
}
func (s *Assembly) Observe(conv *core.ConversationInfo, u otframe.TSDU, setup bool) {
	r := &types.S7Comm{TPKTVersion: 3, TPKTLength: int32(u.WireSize), COTPLength: int32(u.Carrier.Length), COTPPDUType: int32(u.Carrier.Type), COTPPDUTypeName: getCOTPPDUTypeName(int(u.Carrier.Type)), COTPLastDataUnit: u.Carrier.EOT, COTPTPDUNumber: int32(u.Carrier.TPDUNumber), Assembly: &types.OTAssembly{Status: "complete", FirstTimestamp: u.At, Pieces: u.Pieces}}
	switch u.Type {
	case gopacket.LayerTypeZero:
	case layers.LayerTypeS7Comm:
		var p layers.S7Comm
		if err := p.DecodeFromBytes(u.Data, gopacket.NilDecodeFeedback); err != nil {
			r.Assembly.Status, r.Assembly.Reason = "malformed", err.Error()
			break
		}
		reader := s7commReader{}
		reader.parseS7Comm(r, u.Data)
		if p.Userdata != nil {
			v := p.Userdata
			k := [3]byte{byte(v.Type), v.Sequence, v.DataUnitRef}
			if s.first == nil {
				s.first = make(map[[3]byte]int64)
			}
			first, ok := s.first[k]
			if !ok {
				first = u.At
			}
			joined, err := s.ud.Feed(&p)
			r.Assembly.FirstTimestamp = first
			switch {
			case err != nil:
				r.Assembly.Status, r.Assembly.Reason = "incomplete", err.Error()
				delete(s.first, k)
			case joined == nil:
				r.Assembly.Status = "pending"
				s.first[k] = first
			default:
				delete(s.first, k)
				if joined.Fragments > 0 {
					r.Assembly.Pieces = uint32(joined.Fragments)
				}
				if joined.DecodeErr != nil {
					r.Assembly.Status, r.Assembly.Reason = "incomplete", joined.DecodeErr.Error()
				} else if joined.SZL != nil {
					r.SZLID, r.SZLIndex, r.SZLRecords = uint32(joined.SZL.ID), uint32(joined.SZL.Index), uint32(joined.SZL.RecordCount)
				}
				if s.uncertain && joined.Fragments > 0 && !ok {
					r.Assembly.Status = "incomplete"
				}
			}
		}
	case layers.LayerTypeS7CommPlus:
		var p layers.S7CommPlus
		r.ProtocolId = 0x72
		r.MessageTypeName = "S7Comm Plus"
		r.PayloadObscured = true
		r.IsSecurityRelevant = true
		if err := p.DecodeFromBytes(u.Data, gopacket.NilDecodeFeedback); err != nil {
			r.Assembly.Status, r.Assembly.Reason = "malformed", err.Error()
			break
		}
		r.MessageType = int32(p.Version)
		if !s.plusPending {
			s.plusStart = u.At
		}
		joined, err := s.plus.Feed(&p)
		r.Assembly.FirstTimestamp = s.plusStart
		s.plusPending = joined == nil && err == nil
		switch {
		case err != nil:
			r.Assembly.Status, r.Assembly.Reason = "incomplete", err.Error()
		case joined == nil:
			r.Assembly.Status = "pending"
		default:
			r.Assembly.Pieces = uint32(joined.Frames)
			if joined.HasDataHeader {
				r.S7PlusOpcode = int32(joined.Opcode)
				r.S7PlusOpcodeName = joined.Opcode.String()
				r.S7PlusFunction = int32(joined.Function)
				r.PayloadObscured = false
				r.DataLength = int32(len(joined.Data))
			}
		}
	default:
		return
	}
	if u.Type == gopacket.LayerTypeZero {
		if !setup || u.Carrier.Type == layers.COTPTypeDT {
			return
		}
		s.Reset(conv, u.Frame, "COTP connection boundary")
		s.uncertain = false
	}
	writeS7(conv, u.Frame, r)
}
