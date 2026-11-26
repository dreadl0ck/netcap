package opcua

import (
	"bytes"
	"errors"
	"sort"
	"sync/atomic"

	"github.com/dreadl0ck/netcap/internal/decoder/config"
	"github.com/dreadl0ck/netcap/internal/decoder/core"
	"github.com/dreadl0ck/netcap/internal/decoder/stream/otframe"
	"github.com/dreadl0ck/netcap/types"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

type opcuaReader struct{ conversation *core.ConversationInfo }

func (*opcuaReader) New(c *core.ConversationInfo) core.StreamDecoderInterface { return &opcuaReader{c} }
func (*opcuaReader) SupportsFragmentSource() bool                             { return true }

type chunkKey struct {
	typ              layers.OPCUAMessageType
	channel, request uint32
}
type chunkSeries struct {
	at     int64
	count  uint32
	credit int64
}
type halfChannel struct {
	join      layers.OPCUAChunkAssembler
	series    map[chunkKey]chunkSeries
	uncertain bool
}

func (o *opcuaReader) Decode() {
	if Decoder.Writer == nil {
		return
	}
	o.walk(func(r *types.OPCUA) {
		if err := Decoder.Writer.Write(r); err != nil {
			o.conversation.FragmentError = err
		} else {
			atomic.AddInt64(&Decoder.NumRecordsWritten, 1)
		}
	})
}
func (o *opcuaReader) walk(emit func(*types.OPCUA)) {
	c := o.conversation
	var sides [2]halfChannel
	reset := func(f otframe.Frame, why string) {
		s := &sides[f.Side]
		var records []*types.OPCUA
		for k, series := range s.series {
			c.StateBudget.Release(series.credit)
			r := uaRecord(f)
			r.MessageType = k.typ.String()
			r.RequestId = k.request
			r.SecureChannelId = k.channel
			r.Timestamp = series.at
			r.Assembly = &types.OTAssembly{Status: "incomplete", Reason: why, FirstTimestamp: series.at, Pieces: series.count}
			records = append(records, r)
		}
		sort.Slice(records, func(i, j int) bool {
			a, b := records[i], records[j]
			if a.Timestamp != b.Timestamp {
				return a.Timestamp < b.Timestamp
			}
			if a.SecureChannelId != b.SecureChannelId {
				return a.SecureChannelId < b.SecureChannelId
			}
			if a.RequestId != b.RequestId {
				return a.RequestId < b.RequestId
			}
			return a.MessageType < b.MessageType
		})
		for _, r := range records {
			emit(r)
		}
		if len(records) == 0 && why != "EOF" && why != "capture gap" {
			r := uaRecord(f)
			r.Assembly.Status, r.Assembly.Reason = "incomplete", why
			emit(r)
		}
		*s = halfChannel{uncertain: true}
	}
	defer func() {
		for _, s := range sides {
			for _, p := range s.series {
				c.StateBudget.Release(p.credit)
			}
		}
	}()
	otframe.Walk(c, layers.ScanOPCUA, 16<<20, func(f otframe.Frame) {
		s := &sides[f.Side]
		r := uaRecord(f)
		var p layers.OPCUA
		err := p.DecodeFromBytes(f.Data, gopacket.NilDecodeFeedback)
		r.MessageType, r.ChunkType, r.MessageSize = string(f.Data[:3]), string(f.Data[3:4]), int32(len(f.Data))
		if err != nil {
			reset(f, "invalid chunk")
			return
		}
		r.SecureChannelId = p.SecureChannelID
		r.SecurityPolicyUri = p.SecurityHeader.SecurityPolicyURI
		if p.MessageType == layers.OPCUAMessageOpenSecureChannel {
			s.uncertain = false
		}
		secure := p.MessageType == layers.OPCUAMessageSecure || p.MessageType == layers.OPCUAMessageCloseSecureChannel
		if secure {
			if _, known := s.join.SecurityPolicyURI(); !known || s.uncertain {
				r.Assembly.Status, r.Assembly.Reason = "opaque", "channel policy not observed"
				emit(r)
				return
			}
		}
		key := chunkKey{p.MessageType, p.SecureChannelID, p.RequestID}
		series, exists := s.series[key]
		if !exists {
			series.at = f.At
		}
		series.count++
		if p.ChunkType == layers.OPCUAChunkIntermediate && !p.Encrypted {
			if !exists && len(s.series) >= 8 {
				reset(f, "pending channel limit")
				return
			}
			n := int64(len(p.Body))
			if !c.StateBudget.TryReserve(n) {
				reset(f, "chunk budget")
				return
			}
			series.credit += n
			if s.series == nil {
				s.series = make(map[chunkKey]chunkSeries)
			}
			s.series[key] = series
		}
		v, err := s.join.Add(&p)
		r.Assembly.FirstTimestamp, r.Assembly.Pieces = series.at, series.count
		closeSeries := func() {
			if retained, ok := s.series[key]; ok {
				delete(s.series, key)
				c.StateBudget.Release(retained.credit)
			}
		}
		if err != nil {
			if errors.Is(err, layers.ErrOPCUAChunkLost) {
				closeSeries()
				r.Timestamp, r.RequestId, r.SequenceNumber = series.at, p.RequestID, p.SequenceNumber
				r.Assembly.Status, r.Assembly.Reason = "incomplete", err.Error()
				emit(r)
				return
			}
			reset(f, err.Error())
			return
		}
		if v == nil {
			r.RequestId, r.SequenceNumber = p.RequestID, p.SequenceNumber
			r.Assembly.Status = "pending"
			emit(r)
			return
		}
		if v.Encrypted {
			r.Assembly.Status = "opaque"
		} else if v.ChunkType == layers.OPCUAChunkAbort {
			r.Timestamp, r.RequestId, r.SequenceNumber = series.at, v.RequestID, v.SequenceNumber
			r.Assembly.Status = "aborted"
			r.ErrorCode, r.ErrorReason = uint32(v.Error.Error), v.Error.Reason
		} else {
			mapMessage(r, v)
			r.Timestamp = series.at
		}
		closeSeries()
		emit(r)
	}, reset)
}
func uaRecord(f otframe.Frame) *types.OPCUA {
	return &types.OPCUA{Timestamp: f.At, SrcIP: f.Context.SrcIP, DstIP: f.Context.DstIP, SrcPort: f.Context.SrcPort, DstPort: f.Context.DstPort, CommunityID: f.Context.CommunityID, Assembly: &types.OTAssembly{Status: "complete", FirstTimestamp: f.At, Pieces: 1}}
}
func mapMessage(r *types.OPCUA, p *layers.OPCUA) {
	limits := p.Acknowledge
	if p.MessageType == layers.OPCUAMessageHello {
		limits = p.Hello.OPCUAConnectionLimits
		r.EndpointUrl = p.Hello.EndpointURL
	}
	if p.MessageType == layers.OPCUAMessageReverseHello {
		r.EndpointUrl = p.ReverseHello.EndpointURL
	}
	r.ReceiveBufferSize, r.SendBufferSize, r.ProtocolVersion, r.MaxChunkCount, r.MaxMessageSize = int32(limits.ReceiveBufferSize), int32(limits.SendBufferSize), int32(limits.ProtocolVersion), int32(limits.MaxChunkCount), int32(limits.MaxMessageSize)
	r.ErrorReason, r.ErrorCode = p.Error.Reason, uint32(p.Error.Error)
	r.RequestId, r.SequenceNumber = p.RequestID, p.SequenceNumber
	if config.Instance != nil && config.Instance.IncludePayloads {
		r.Payload = bytes.Clone(p.Body)
	}
	v := p.Service
	if v == nil {
		return
	}
	r.ServiceName, r.ServiceNodeId, r.IsRequest = v.ID.String(), v.TypeID.String(), v.ID.IsRequest()
	if h := v.RequestHeader; h != nil {
		r.AuthenticationToken, r.RequestHandle = h.AuthenticationToken.String(), h.RequestHandle
	}
	if h := v.ResponseHeader; h != nil {
		r.RequestHandle, r.StatusCode, r.StatusCodeName = h.RequestHandle, uint32(h.ServiceResult), h.ServiceResult.String()
	}
	if h := v.OpenSecureChannelRequest; h != nil {
		r.SecurityMode = h.SecurityMode.String()
	}
	if h := v.CreateSessionResponse; h != nil {
		r.SessionId = h.SessionID.String()
	}
	switch v.ID {
	case layers.OPCUAServiceWriteRequest, layers.OPCUAServiceHistoryUpdateRequest, layers.OPCUAServiceCallRequest, layers.OPCUAServiceAddNodesRequest, layers.OPCUAServiceDeleteNodesRequest, layers.OPCUAServiceAddReferencesRequest, layers.OPCUAServiceDeleteReferencesRequest:
		r.IsCriticalOperation = true
	case layers.OPCUAServiceOpenSecureChannelRequest, layers.OPCUAServiceCloseSecureChannelRequest, layers.OPCUAServiceCreateSessionRequest, layers.OPCUAServiceActivateSessionRequest, layers.OPCUAServiceCloseSessionRequest, layers.OPCUAServiceRegisterServerRequest, layers.OPCUAServiceRegisterServer2Request:
		r.IsSecurityRelevant = true
	}
}
