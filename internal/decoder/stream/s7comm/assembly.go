package s7comm

import (
	"slices"
	"sync/atomic"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"

	"github.com/dreadl0ck/netcap/internal/decoder/core"
	"github.com/dreadl0ck/netcap/internal/decoder/stream/otframe"
	"github.com/dreadl0ck/netcap/types"
)

type unitStart struct {
	at              int64
	ref, group, sub byte
	dropped         bool
}

func (s unitStart) continuedBy(v *layers.S7CommUserdata) bool {
	if s.group != byte(v.FunctionGroup) || s.sub != byte(v.Subfunction) || len(v.Data) < 2 {
		return false
	}
	return v.FunctionGroup == layers.S7CommGroupNCProgramming || v.Fragmented() && s.ref == v.DataUnitRef
}

type Assembly struct {
	ud   layers.S7CommUDAssembler
	plus layers.S7CommPlusAssembler
	// Match the upstream assembler's slots, including replacement on ref or service change.
	first       map[[2]byte]unitStart
	plusStart   int64
	plusPending bool
	plusDropped bool
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
	starts := make([]int64, 0, len(s.first))
	for _, start := range s.first {
		if !start.dropped {
			starts = append(starts, start.at)
		}
	}
	slices.Sort(starts)
	for _, at := range starts {
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
			k := [2]byte{byte(v.Type), v.Sequence}
			if s.first == nil {
				s.first = make(map[[2]byte]unitStart)
			}
			first, ok := s.first[k]
			start := unitStart{at: u.At, ref: v.DataUnitRef, group: byte(v.FunctionGroup), sub: byte(v.Subfunction)}
			// NC programming increments the data unit reference, including across zero.
			if ok && !first.continuedBy(v) {
				if !first.dropped {
					writeS7(conv, u.Frame, &types.S7Comm{Assembly: &types.OTAssembly{Status: "incomplete", Reason: "userdata transfer replaced", FirstTimestamp: first.at}})
				}
				ok = false
			}
			if !ok {
				first = start
			}
			joined, err := s.ud.Feed(&p)
			r.Assembly.FirstTimestamp = first.at
			switch {
			case err != nil:
				r.Assembly.Status, r.Assembly.Reason = "incomplete", err.Error()
				if v.LastDataUnit != 0 {
					first.dropped = true
					s.first[k] = first
				} else {
					delete(s.first, k)
				}
			case joined == nil:
				if first.dropped {
					if v.LastDataUnit == 0 {
						delete(s.first, k)
					}
					return
				}
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
		if p.Version == layers.S7CommPlusKeepAlive {
			// An independent event does not finish or retimestamp an open PDU.
			r.MessageTypeName = "S7Comm Plus system event"
			writeS7(conv, u.Frame, r)
			return
		}
		if !s.plusPending {
			s.plusStart = u.At
		}
		joined, err := s.plus.Feed(&p)
		r.Assembly.FirstTimestamp = s.plusStart
		if s.plusDropped {
			s.plusDropped = !p.HasTrailer
			return
		}
		s.plusPending = joined == nil && err == nil
		switch {
		case err != nil:
			s.plusDropped = !p.HasTrailer
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
		if u.Carrier.Type == layers.COTPTypeDT {
			return
		}
		switch u.Carrier.Type {
		case layers.COTPTypeCR, layers.COTPTypeCC, layers.COTPTypeDR, layers.COTPTypeDC:
			s.Reset(conv, u.Frame, "COTP connection boundary")
			s.uncertain = false
		}
		if !setup {
			return
		}
		r.COTPDestRef, r.COTPSrcRef, r.COTPClass = int32(u.Carrier.DstRef), int32(u.Carrier.SrcRef), int32(u.Carrier.Class)
	}
	writeS7(conv, u.Frame, r)
}
