package iec62351

import (
	"math"
	"strconv"

	"github.com/gopacket/gopacket/layers"

	"github.com/dreadl0ck/netcap/internal/decoder/stream/otframe"
	"github.com/dreadl0ck/netcap/types"
)

// IEC104Assembly follows security-body segments within one TCP direction.
type IEC104Assembly struct {
	join   layers.IEC104SecurityAssembler
	typ    layers.IEC104TypeID
	addr   uint16
	origin uint8
	first  int64
}

func securityType(t layers.IEC104TypeID) bool {
	return (t >= layers.IEC104TypeAuthChallenge && t <= layers.IEC104TypeAuthError) || (t >= layers.IEC104TypeUserStatusChange && t <= layers.IEC104TypeUpdateKeyConfirm)
}

func (s *IEC104Assembly) Record(p *layers.IEC104, f otframe.Frame) *types.IEC62351 {
	a := &p.ASDU
	t := a.TypeID
	if p.Format != layers.IEC104FormatI || p.Faults != 0 || !securityType(t) {
		return nil
	}
	r := &types.IEC62351{Timestamp: f.At, SrcIP: f.Context.SrcIP, DstIP: f.Context.DstIP, SrcPort: f.Context.SrcPort, DstPort: f.Context.DstPort, CommunityID: f.Context.CommunityID, UnderlyingProtocol: ProtocolIEC104, SecurityVersion: 5, MessageType: int32(t), MessageTypeName: t.String(), IsSecurityRelevant: true, AuditEventOutcome: OutcomeUnknown}
	v := a.Security
	if t >= layers.IEC104TypeUserStatusChange {
		r.ProtocolContext = "security type identified; body not decoded"
		return r
	}
	if !v.Decoded {
		if v.First {
			s.typ, s.addr, s.origin, s.first = t, a.CommonAddr, a.Originator, f.At
		}
		if s.typ != t || s.addr != a.CommonAddr || s.origin != a.Originator {
			r.ProtocolContext = "incomplete security body"
			return r
		}
		body, err := s.join.Add(&v)
		if err != nil {
			*s = IEC104Assembly{}
			r.ProtocolContext = err.Error()
			return r
		}
		if body == nil {
			r.ProtocolContext = "security fragment pending"
			return r
		}
		r.Timestamp = s.first
		_, err = v.DecodeBody(t, body, layers.IEC104ASDUOptions{})
		*s = IEC104Assembly{}
		if err != nil {
			r.ProtocolContext = "invalid security body"
			return r
		}
	} else if t == s.typ && a.CommonAddr == s.addr && a.Originator == s.origin {
		*s = IEC104Assembly{}
	}
	r.EventSequenceNumber = int64(v.Sequence)
	if v.Sequence <= math.MaxInt32 {
		r.ChallengeSequence = int32(v.Sequence)
	}
	r.UserIdentity = strconv.FormatUint(uint64(v.User), 10)
	switch t {
	case layers.IEC104TypeAuthChallenge, layers.IEC104TypeAuthReply, layers.IEC104TypeAuthAggressive:
		r.IsAuthenticationEvent = true
		r.AuditEventType = AuditEventAuthentication
		r.IsRequest = t == layers.IEC104TypeAuthChallenge
	case layers.IEC104TypeAuthError:
		r.IsSecurityAlert = true
		r.ErrorCode = int32(v.ErrorCode)
		r.AuditEventType = AuditEventSecurityAlert
		r.AuditEventOutcome = OutcomeFailure
	default:
		r.IsKeyManagementEvent = true
		r.AuditEventType = AuditEventKeyManagement
		r.IsRequest = t == layers.IEC104TypeKeyStatusRequest
	}
	return r
}
