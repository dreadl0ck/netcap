package bacnetip

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"

	"github.com/dreadl0ck/netcap/internal/bacnet"
	"github.com/dreadl0ck/netcap/types"
)

// Assembly belongs to a capture (or one decrypted WebSocket), never a process.
type Assembly struct {
	pending   map[segmentKey]*segment
	nextSweep int64
}
type segmentKey struct {
	route, src, dst string
	invoke          uint8
	typ             layers.BACnetPDUType
	service         layers.BACnetConfirmedService
}
type segment struct {
	join        layers.BACnetSegmentAssembler
	first, last int64
	pieces      uint32
	initial     *types.BACnetIP
	next        uint8
	held        [256]bool
	zero        [sha256.Size]byte
}

// Track distinct pieces in the same modulo-256 receive window as the assembler.
func (v *segment) observe(seq uint8) bool {
	if seq-v.next > 127 || v.held[seq] {
		return false
	}
	v.pieces++
	v.held[seq] = true
	for v.held[v.next] {
		v.held[v.next] = false
		v.next++
	}
	return true
}

func (v *segment) incomplete(reason string) *types.BACnetIP {
	r := *v.initial
	r.Assembly = &types.OTAssembly{Status: "incomplete", Reason: reason, FirstTimestamp: v.first, Pieces: v.pieces}
	return &r
}

func (s *Assembly) Flush(before int64, all bool, emit func(*types.BACnetIP)) {
	for k, v := range s.pending {
		if !all && v.last >= before {
			continue
		}
		delete(s.pending, k)
		reason := "idle expiry"
		if all {
			reason = "EOF"
		}
		emit(v.incomplete(reason))
	}
}

// Decode takes a decoded BVLC, MS/TP or SC envelope; route distinguishes both outer peers.
func (s *Assembly) Decode(p gopacket.Packet, route, carrier string, ctx *types.PacketContext, at int64, payload bool, emit func(*types.BACnetIP)) *types.BACnetIP {
	r := &types.BACnetIP{Timestamp: at, Carrier: carrier, CommunityID: ctx.CommunityID, SrcIP: ctx.SrcIP, DstIP: ctx.DstIP, SrcPort: ctx.SrcPort, DstPort: ctx.DstPort, LinkSource: ctx.SrcMAC, LinkDestination: ctx.DstMAC, Assembly: &types.OTAssembly{Status: "complete", FirstTimestamp: at, Pieces: 1}}
	var src, dst string
	r.NetworkScope = ctx.NetworkScope
	switch {
	case p.Layer(layers.LayerTypeBVLC) != nil:
		b := p.Layer(layers.LayerTypeBVLC).(*layers.BVLC)
		r.BVLCType, r.BVLCFunction, r.BVLCLength, r.BVLCFunctionName = int32(b.Type), int32(b.Function), int32(b.Length), GetBVLCFunctionName(uint8(b.Function))
		if b.Function == BVLCForwardedNPDU {
			src = b.Address.String()
		}
	case p.Layer(layers.LayerTypeBVLC6) != nil:
		b := p.Layer(layers.LayerTypeBVLC6).(*layers.BVLC6)
		r.BVLCType, r.BVLCFunction, r.BVLCLength, r.BVLCFunctionName = int32(b.Type), int32(b.Function), int32(b.Length), b.Function.String()
		src, dst = fmt.Sprintf("%x", b.SourceVMAC), fmt.Sprintf("%x", b.DestinationVMAC)
	case p.Layer(layers.LayerTypeBACnetMSTP) != nil:
		b := p.Layer(layers.LayerTypeBACnetMSTP).(*layers.BACnetMSTP)
		if !b.HeaderCRCValid || !b.DataCRCValid || b.NextLayerType() != layers.LayerTypeBACnetNPDU {
			return nil
		}
		src, dst = fmt.Sprint(b.Source), fmt.Sprint(b.Destination)
		r.LinkSource, r.LinkDestination = src, dst
	case p.Layer(layers.LayerTypeBACnetSC) != nil:
		b := p.Layer(layers.LayerTypeBACnetSC).(*layers.BACnetSC)
		r.BVLCFunction, r.BVLCFunctionName, r.SCMessageID = int32(b.Function), b.Function.String(), uint32(b.MessageID)
		src, dst = fmt.Sprintf("%x", b.OriginVMAC), fmt.Sprintf("%x", b.DestinationVMAC)
		r.LinkSource, r.LinkDestination = src, dst
	default:
		return nil
	}
	if n, ok := p.Layer(layers.LayerTypeBACnetNPDU).(*layers.BACnetNPDU); ok {
		r.NPDUVersion, r.NPDUControl, r.NPDUPriority = int32(n.Version), int32(n.Control), int32(n.Control.Priority())
		r.NPDUExpectsReply, r.NPDUNetworkLayerMsg = n.Control.ExpectingReply(), n.Control.NetworkMessage()
		r.SNET, r.DNET, r.HopCount = int32(n.SNET), int32(n.DNET), int32(n.HopCount)
		r.SADR, r.DADR = hex.EncodeToString(n.SADR), hex.EncodeToString(n.DADR)
		if n.Control.NetworkMessage() {
			r.NetworkMessageType = int32(n.MessageType)
			r.NetworkMessageTypeName = getNetworkMessageTypeName(uint8(n.MessageType))
		}
		if payload {
			r.Payload = append(bytes.Clone(n.LayerContents()), n.LayerPayload()...)
		}
		if n.Control.HasSource() {
			src += fmt.Sprintf("/%d:%x", n.SNET, n.SADR)
		}
		if n.Control.HasDestination() {
			dst += fmt.Sprintf("/%d:%x", n.DNET, n.DADR)
		}
	}
	if err := p.ErrorLayer(); err != nil {
		r.Assembly.Status, r.Assembly.Reason = "malformed", err.Error().Error()
		r.ParseQualifications = []string{r.Assembly.Reason}
		return r
	}
	a, ok := p.Layer(layers.LayerTypeBACnetAPDU).(*layers.BACnetAPDU)
	if !ok {
		return r
	}
	mapAPDU(r, a)
	if a.Segmented {
		r.SegmentedMessage = 1
		k := segmentKey{route, src, dst, a.InvokeID, a.PDUType, a.ConfirmedService}
		v := s.pending[k]
		if v != nil && a.SequenceNumber == 0 && -v.next > 127 && sha256.Sum256(a.Parameters) != v.zero {
			emit(v.incomplete("invoke ID reused"))
			delete(s.pending, k)
			v = nil
		}
		if v == nil {
			if a.SequenceNumber != 0 {
				r.Assembly.Status, r.Assembly.Reason = "incomplete", "missing initial segment"
				return r
			}
			if len(s.pending) >= 64 {
				r.Assembly.Status, r.Assembly.Reason = "limited", "BACnet pending limit"
				return r
			}
			if s.pending == nil {
				s.pending = make(map[segmentKey]*segment)
			}
			copy := *r
			copy.Payload = nil
			v = &segment{first: at, initial: &copy, join: layers.BACnetSegmentAssembler{MaxSize: 256 << 10, MaxPending: 1}}
			s.pending[k] = v
		}
		v.last = at
		accepted := v.observe(a.SequenceNumber)
		if accepted && a.SequenceNumber == 0 {
			v.zero = sha256.Sum256(a.Parameters)
		}
		r.Assembly.FirstTimestamp, r.Assembly.Pieces = v.first, v.pieces
		if !accepted {
			r.Assembly.Status = "duplicate"
			return r
		}
		whole, err := v.join.Add(nil, a)
		if err != nil {
			delete(s.pending, k)
			r.Assembly.Status, r.Assembly.Reason = "incomplete", err.Error()
			return r
		}
		if whole == nil {
			r.Assembly.Status = "pending"
			return r
		}
		delete(s.pending, k)
		a = whole
		r.Timestamp = v.first
	}
	// Reuse the same property/object projection as the legacy BACnet/IP reader.
	saved := r.SegmentedMessage
	seq, more, win := r.SequenceNumber, r.MoreFollows, r.ProposedWindowSize
	if app, err := bacnet.ParseApplication(append(bytes.Clone(a.Contents), a.Parameters...)); err == nil {
		projectApplication(r, app)
	} else {
		r.Assembly.Status, r.Assembly.Reason = "malformed", err.Error()
	}
	r.SegmentedMessage, r.SequenceNumber, r.MoreFollows, r.ProposedWindowSize = saved, seq, more, win
	return r
}

func mapAPDU(r *types.BACnetIP, a *layers.BACnetAPDU) {
	r.APDUType, r.APDUTypeName = int32(a.PDUType), getAPDUTypeName(uint8(a.PDUType))
	r.InvokeID, r.SequenceNumber, r.ProposedWindowSize = int32(a.InvokeID), int32(a.SequenceNumber), int32(a.WindowSize)
	r.MoreFollows, r.SegmentedResponseAccepted = a.MoreFollows, a.SegmentedResponseAccepted
	r.IsConfirmed = a.PDUType == layers.BACnetPDUConfirmedRequest
	switch a.PDUType {
	case layers.BACnetPDUUnconfirmedRequest:
		r.ServiceChoice = int32(a.UnconfirmedService)
		r.ServiceName = getUnconfirmedServiceName(uint8(a.UnconfirmedService))
	case layers.BACnetPDUConfirmedRequest, layers.BACnetPDUSimpleACK, layers.BACnetPDUComplexACK, layers.BACnetPDUError:
		r.ServiceChoice = int32(a.ConfirmedService)
		r.ServiceName = getConfirmedServiceName(uint8(a.ConfirmedService))
	}
}
func (s *Assembly) Advance(at int64, emit func(*types.BACnetIP)) {
	if at >= s.nextSweep {
		s.Flush(at-int64(30*time.Second), false, emit)
		s.nextSweep = at + int64(time.Second)
	}
}
