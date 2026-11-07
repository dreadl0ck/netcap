package rtp

import (
	"encoding/binary"
	"sync/atomic"

	"github.com/dreadl0ck/netcap/internal/decoder"
	"github.com/dreadl0ck/netcap/internal/decoder/core"
	"github.com/dreadl0ck/netcap/internal/sipaudit"
	"github.com/dreadl0ck/netcap/types"
)

var Decoder = &decoder.StreamDecoder{
	Type: types.Type_NC_RTP, Name: "RTP", Description: "SIP/SDP associated RTP metadata",
	Typ: core.UDP, Specificity: core.SpecificityValidated, Factory: &reader{},
	// The selector calls Matches with endpoints and capture time. Bytes alone
	// cannot distinguish RTP from arbitrary UDP with the version bits set.
	CanDecode: func(_, _ []byte) bool { return false },
}
var EventDecoder = &decoder.AbstractDecoder{Type: types.Type_NC_DTMF, Name: "DTMF", Description: "RFC 4733 completed telephone events"}

func parse(data []byte) (*types.RTP, []byte) {
	if len(data) < 12 || data[0]>>6 != 2 || (data[1] >= 192 && data[1] <= 223) {
		return nil, nil
	}
	cc := int(data[0] & 15)
	off := 12 + 4*cc
	if off > len(data) {
		return nil, nil
	}
	r := &types.RTP{SSRC: binary.BigEndian.Uint32(data[8:12]), Sequence: uint32(binary.BigEndian.Uint16(data[2:4])),
		MediaTimestamp: binary.BigEndian.Uint32(data[4:8]), PayloadType: uint32(data[1] & 127), Marker: data[1]&128 != 0}
	for i := 0; i < cc; i++ {
		r.CSRC = append(r.CSRC, binary.BigEndian.Uint32(data[12+4*i:]))
	}
	if data[0]&16 != 0 {
		if off+4 > len(data) {
			return nil, nil
		}
		r.ExtensionProfile = uint32(binary.BigEndian.Uint16(data[off:]))
		r.ExtensionLength = uint32(binary.BigEndian.Uint16(data[off+2:])) * 4
		off += 4 + int(r.ExtensionLength)
		if off > len(data) {
			return nil, nil
		}
	}
	end := len(data)
	if data[0]&32 != 0 {
		padding := int(data[end-1])
		if padding == 0 || padding > end-off {
			return nil, nil
		}
		end -= padding
		r.PaddingLength = uint32(padding)
	}
	if end <= off {
		return nil, nil
	}
	r.PayloadLength = uint32(end - off)
	return r, data[off:end]
}

func Matches(c *core.ConversationInfo) bool {
	if c == nil {
		return false
	}
	for _, f := range c.Data {
		if r, _ := parse(f.Raw()); r != nil {
			src, dst, sp, dp := c.Endpoints(f)
			if _, _, ok := sipaudit.Media.Lookup(src, dst, sp, dp, r.PayloadType, core.FragmentTime(f)); ok {
				return true
			}
		}
	}
	return false
}

type reader struct{ conversation *core.ConversationInfo }

func (*reader) New(c *core.ConversationInfo) core.StreamDecoderInterface { return &reader{c} }
func (r *reader) Decode() {
	r.decode(func(m *types.RTP) {
		if Decoder.Writer != nil && Decoder.Writer.Write(m) == nil {
			atomic.AddInt64(&Decoder.NumRecordsWritten, 1)
		}
	}, func(m *types.DTMF) {
		if EventDecoder.Writer != nil && EventDecoder.Writer.Write(m) == nil {
			atomic.AddInt64(&EventDecoder.NumRecordsWritten, 1)
		}
	})
}

func (r *reader) decode(emit func(*types.RTP), event func(*types.DTMF)) {
	type source struct {
		call   string
		server bool
		ssrc   uint32
	}
	type highWater struct {
		sequence, timestamp int64
		at                  int64
	}
	type eventKey struct {
		source    source
		timestamp int64
		event     uint32
	}
	states := map[source]highWater{}
	ends := map[eventKey]int64{}
	for _, f := range r.conversation.Data {
		m, payload := parse(f.Raw())
		if m == nil {
			continue
		}
		m.Timestamp = core.FragmentTime(f)
		m.SrcIP, m.DstIP, m.SrcPort, m.DstPort = r.conversation.Endpoints(f)
		id, codec, ok := sipaudit.Media.Lookup(m.SrcIP, m.DstIP, m.SrcPort, m.DstPort, m.PayloadType, m.Timestamp)
		if !ok {
			continue
		}
		m.CallID, m.Encoding, m.ClockRate, m.CommunityID = id, codec.Encoding, codec.Rate, r.conversation.CommunityID
		for k, old := range states {
			if m.Timestamp-old.at > 120e9 {
				delete(states, k)
			}
		}
		key := source{id, core.FromServer(f), m.SSRC}
		s, exists := states[key]
		if exists && m.Timestamp-s.at > 120e9 {
			exists = false
		}
		if !exists {
			if len(states) >= 64 {
				continue
			}
			s = highWater{int64(m.Sequence), int64(m.MediaTimestamp), m.Timestamp}
		}
		m.ExtendedSequence = s.sequence + int64(int16(uint16(m.Sequence)-uint16(s.sequence)))
		m.ExtendedTimestamp = s.timestamp + int64(int32(m.MediaTimestamp-uint32(s.timestamp)))
		m.Reordered = m.ExtendedSequence < s.sequence
		s.sequence, s.timestamp, s.at = max(s.sequence, m.ExtendedSequence), max(s.timestamp, m.ExtendedTimestamp), max(s.at, m.Timestamp)
		states[key] = s
		emit(m)
		if codec.Encoding != "telephone-event" || len(payload) != 4 || payload[1]&64 != 0 || payload[1]&128 == 0 || !codec.AllowsEvent(uint32(payload[0])) {
			continue
		}
		duration := uint32(binary.BigEndian.Uint16(payload[2:]))
		if duration == 0 {
			continue
		}
		for k, at := range ends {
			if m.Timestamp-at > 120e9 {
				delete(ends, k)
			}
		}
		ek := eventKey{key, m.ExtendedTimestamp, uint32(payload[0])}
		if _, seen := ends[ek]; seen {
			continue
		}
		if len(ends) >= 4096 {
			continue
		}
		ends[ek] = m.Timestamp
		event(&types.DTMF{Timestamp: m.Timestamp, SrcIP: m.SrcIP, DstIP: m.DstIP, SrcPort: m.SrcPort, DstPort: m.DstPort,
			CommunityID: m.CommunityID, CallID: id, SSRC: m.SSRC, MediaTimestamp: m.MediaTimestamp, ExtendedTimestamp: m.ExtendedTimestamp,
			Event: uint32(payload[0]), Digit: string("0123456789*#ABCD"[payload[0]]), Volume: uint32(payload[1] & 63), Duration: duration, ClockRate: codec.Rate, PayloadType: m.PayloadType})
	}
}
