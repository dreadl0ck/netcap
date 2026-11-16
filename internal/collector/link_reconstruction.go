package collector

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"sort"
	"strconv"
	"time"

	"github.com/dreadl0ck/netcap/internal/linkaudit"
	"github.com/dreadl0ck/netcap/internal/packetview"
	"github.com/dreadl0ck/netcap/types"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

const linkStateLimit = 8 << 20
const linkAssemblyLimit = 1024

type linkHealth struct {
	LimitBytes, AssemblyLimit                                    uint64
	Started, Completed, Incomplete, MissingStart, SequenceErrors uint64
	DerivedPackets, BufferedBytes, PeakBytes                     uint64
	BudgetExceeded                                               bool
}

func (r *linkReconstructor) reconstructTS(data []byte, f *linkaudit.LinkFrame, ci gopacket.CaptureInfo, scope string, refs []*types.CapturePacketRef, ranges []*types.LinkSourceRange, completed time.Time) []gopacket.Packet {
	count, _ := strconv.Atoi(f.Fields["ts_packets"])
	deleted, _ := strconv.Atoi(f.Fields["deleted_null_packets"])
	hdm := f.Fields["header_deletion"] == "true"
	if count < 1 || count > 16 || deleted < 0 || deleted > 128 {
		return nil
	}
	children := make([]gopacket.Packet, 0, count+deleted)
	for i := 0; i < deleted; i++ {
		null := bytes.Repeat([]byte{0xff}, 188)
		copy(null, []byte{0x47, 0x1f, 0xff, 0x10, 0})
		children = append(children, derivedLinkPacket(null, captureBusDecoder(243), ci, scope, refs, nil, i, "alp-ts-null-restored", completed, []string{"null-packet-header-and-filler"}))
	}
	var header [4]byte
	offset := 0
	for i := 0; i < count; i++ {
		ts := make([]byte, 188)
		synthesized := []string{"TS-sync-byte"}
		n := 187
		if i == 0 || !hdm {
			ts[0] = 0x47
			copy(ts[1:], data[offset:offset+187])
			copy(header[:], ts[:4])
		} else {
			n = 184
			header[3] = (header[3] & 0xf0) | ((header[3] + 1) & 15)
			copy(ts, header[:])
			copy(ts[4:], data[offset:offset+184])
			synthesized = append(synthesized, "TS-common-header-and-continuity-counter")
		}
		part := []*types.LinkSourceRange{{CaptureOrdinal: refs[0].Ordinal, Offset: ranges[0].Offset + uint32(offset), Length: uint32(n)}}
		p := derivedLinkPacket(ts, captureBusDecoder(243), ci, scope, refs, part, deleted+i, "alp-ts-restored", completed, synthesized)
		if p.ErrorLayer() != nil {
			f.Qualifications = append(f.Qualifications, "invalid-ALP-TS-component")
			return nil
		}
		children = append(children, p)
		offset += n
	}
	r.health.DerivedPackets += uint64(len(children))
	markLinkDecoded(f, "MPEG-2-TS")
	return children
}

type alpAssembly struct {
	data     []byte
	refs     []*types.CapturePacketRef
	ranges   []*types.LinkSourceRange
	first    gopacket.CaptureInfo
	last     time.Time
	ordinal  uint64
	next     uint8
	lastSize int
	credit   uint64
}

type linkReconstructor struct {
	assemblies map[string]*alpAssembly
	watermark  time.Time
	health     linkHealth
	err        error
	events     []gopacket.Packet
}

func (r *linkReconstructor) remove(key string, incomplete bool, reason ...string) {
	if a := r.assemblies[key]; a != nil {
		r.health.BufferedBytes -= a.credit
		delete(r.assemblies, key)
		if incomplete {
			r.health.Incomplete++
			why := "incomplete"
			if len(reason) > 0 {
				why = reason[0]
			}
			frame := busFrame(289, "ATSC ALP reconstruction")
			frame.Fields["network_scope"], frame.Fields["reason"] = key, why
			frame.Qualifications = []string{"ALP-reconstruction-incomplete"}
			p := derivedLinkPacket(nil, gopacket.DecodeFunc(func(_ []byte, b gopacket.PacketBuilder) error { b.AddLayer(frame); return nil }), a.first, key, a.refs, a.ranges, 0, "alp-incomplete", r.watermark, nil)
			r.events = append(r.events, p)
		}
	}
}

func (r *linkReconstructor) finish() {
	keys := make([]string, 0, len(r.assemblies))
	for key := range r.assemblies {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		r.remove(key, true, "capture-end")
	}
}

func (r *linkReconstructor) drainEvents() []gopacket.Packet {
	out := r.events
	r.events = nil
	return out
}

func (r *linkReconstructor) reserve(n uint64) bool {
	if n > linkStateLimit-r.health.BufferedBytes {
		r.err = fmt.Errorf("link reconstruction state budget exceeded: limit=%d", linkStateLimit)
		r.health.BudgetExceeded = true
		return false
	}
	r.health.BufferedBytes += n
	r.health.PeakBytes = max(r.health.PeakBytes, r.health.BufferedBytes)
	return true
}

func linkRef(p gopacket.Packet, ordinal uint64) *types.CapturePacketRef {
	ci := p.Metadata().CaptureInfo
	return &types.CapturePacketRef{Ordinal: ordinal, Timestamp: ci.Timestamp.UnixNano(), CaptureLength: int32(ci.CaptureLength), WireLength: int32(ci.Length), InterfaceIndex: int32(ci.InterfaceIndex), TimestampUnavailable: packetview.TimeUnavailable(ci)}
}

func linkCaptureContext(ci gopacket.CaptureInfo, ctx *packetview.Context) gopacket.CaptureInfo {
	ancillary := make([]any, 0, len(ci.AncillaryData)+1)
	for _, item := range ci.AncillaryData {
		if _, old := item.(*packetview.Context); !old {
			ancillary = append(ancillary, item)
		}
	}
	ci.AncillaryData = append(ancillary, ctx)
	return ci
}

func linkEvidence(p gopacket.Packet, f *linkaudit.LinkFrame, ordinal uint64) gopacket.Packet {
	view := gopacket.NewPacket(p.Data(), gopacket.DecodeFunc(func(_ []byte, b gopacket.PacketBuilder) error {
		for _, layer := range p.Layers() {
			b.AddLayer(layer)
			if layer == f {
				break
			}
		}
		return nil
	}), gopacket.NoCopy)
	scope := f.Fields["network_scope"]
	if scope == "" {
		scope = packetview.Scope(p)
	}
	view.Metadata().CaptureInfo = linkCaptureContext(p.Metadata().CaptureInfo, &packetview.Context{Scope: scope, Status: "alp-source", Packets: []*types.CapturePacketRef{linkRef(p, ordinal)}})
	return view
}

func markLinkDecoded(f *linkaudit.LinkFrame, protocol string) {
	f.PayloadProtocol = protocol
	qualifications := make([]string, 0, len(f.Qualifications))
	for _, q := range f.Qualifications {
		if q != "upper-layer-not-decoded" {
			qualifications = append(qualifications, q)
		}
	}
	f.Qualifications = qualifications
}

func derivedLinkPacket(data []byte, decoder gopacket.Decoder, ci gopacket.CaptureInfo, scope string, refs []*types.CapturePacketRef, ranges []*types.LinkSourceRange, child int, status string, completed time.Time, synthesized []string) gopacket.Packet {
	p := gopacket.NewPacket(data, decoder, gopacket.Default)
	ci.CaptureLength, ci.Length = len(data), len(data)
	transform := &types.LinkTransformation{Protocol: "atsc-alp", ChildOrdinal: uint32(child), Sources: ranges, Synthesized: synthesized, DecodedLength: uint32(len(data)), Status: status}
	ctx := &packetview.Context{Scope: scope, Packets: refs, Status: status, CompletedAt: completed, LinkTransformations: []*types.LinkTransformation{transform}}
	ci = linkCaptureContext(ci, ctx)
	p.Metadata().CaptureInfo = ci
	return p
}

func (r *linkReconstructor) advance(p gopacket.Packet, ordinal uint64) {
	ci := p.Metadata().CaptureInfo
	if !packetview.TimeUnavailable(ci) && ci.Timestamp.After(r.watermark) {
		r.watermark = ci.Timestamp
	}
	var expired []string
	for key, a := range r.assemblies {
		if (!a.last.IsZero() && a.last.Add(30*time.Second).Before(r.watermark)) || (ordinal >= a.ordinal && ordinal-a.ordinal > 4096) {
			expired = append(expired, key)
		}
	}
	sort.Strings(expired)
	for _, key := range expired {
		r.remove(key, true, "expiry")
	}
}

func (r *linkReconstructor) process(p gopacket.Packet, f *linkaudit.LinkFrame, ordinal uint64) []gopacket.Packet {
	if r.assemblies == nil {
		r.assemblies = map[string]*alpAssembly{}
	}
	r.health.LimitBytes, r.health.AssemblyLimit = linkStateLimit, linkAssemblyLimit
	ci := p.Metadata().CaptureInfo
	f.Fields["capture_ordinal"] = strconv.FormatUint(ordinal, 10)
	r.advance(p, ordinal)
	if r.err != nil {
		f.Qualifications = append(f.Qualifications, "link-reconstruction-budget-exceeded")
		return nil
	}
	a := f.ALP
	if a == nil || p.ErrorLayer() != nil {
		return nil
	}
	scope := packetview.Scope(p) + "/alp"
	if a.PLPPresent {
		scope += "/plp:" + strconv.Itoa(int(a.PLP))
	}
	if a.SIDPresent {
		scope += "/sid:" + strconv.Itoa(int(a.SID))
	} else {
		scope += "/sid:absent"
	}
	key := scope + "/type:" + strconv.Itoa(int(a.PacketType))
	if a.PacketType == 4 {
		for _, field := range []string{"signalling_type", "signalling_type_extension", "signalling_version", "signalling_format", "signalling_encoding"} {
			key += "/" + f.Fields[field]
		}
	}
	if a.PacketType == 6 {
		key += "/extended:" + f.Fields["extended_type"]
	}
	f.Fields["network_scope"] = scope
	payloadOffset := a.Offset
	for _, layer := range p.Layers() {
		if layer == f {
			break
		}
		payloadOffset += len(layer.LayerContents())
	}
	if payloadOffset < 0 || a.Length < 0 || payloadOffset > len(p.Data()) || a.Length > len(p.Data())-payloadOffset {
		return nil
	}
	data := p.Data()[payloadOffset : payloadOffset+a.Length]
	refs := []*types.CapturePacketRef{linkRef(p, ordinal)}
	ranges := []*types.LinkSourceRange{{CaptureOrdinal: ordinal, Offset: uint32(payloadOffset), Length: uint32(a.Length)}}
	status := "alp-decapsulated"
	if a.Segmented {
		if a.Sequence == 0 {
			r.remove(key, true, "new-start")
			if len(r.assemblies) >= linkAssemblyLimit {
				r.err = fmt.Errorf("link reconstruction assembly budget exceeded: limit=%d", linkAssemblyLimit)
				r.health.BudgetExceeded = true
				return nil
			}
			if !r.reserve(512) {
				return nil
			}
			r.assemblies[key] = &alpAssembly{first: ci, credit: 512}
			r.health.Started++
		}
		state := r.assemblies[key]
		if state == nil {
			r.health.MissingStart++
			f.Qualifications = append(f.Qualifications, "ALP-segment-missing-start")
			return nil
		}
		if a.Sequence != state.next {
			if state.next > 0 && a.Sequence == state.next-1 && !a.Last && bytes.Equal(data, state.data[len(state.data)-state.lastSize:]) {
				f.Qualifications = append(f.Qualifications, "ALP-duplicate-segment-ignored")
				return nil
			}
			r.health.SequenceErrors++
			r.remove(key, true, "sequence-error")
			f.Qualifications = append(f.Qualifications, "ALP-segment-sequence-error")
			return nil
		}
		if len(data) == 0 || len(data) > 65535-len(state.data) || (a.Sequence == 31 && !a.Last) {
			r.remove(key, true, "length-or-sequence-limit")
			f.Qualifications = append(f.Qualifications, "ALP-segment-length-or-sequence-limit")
			return nil
		}
		credit := uint64(len(data) + 256)
		if !r.reserve(credit) {
			return nil
		}
		state.credit += credit
		// Exact capacity keeps the retained-byte budget independent of append growth.
		next := make([]byte, len(state.data)+len(data))
		copy(next, state.data)
		copy(next[len(state.data):], data)
		state.data = next
		state.refs = append(state.refs, refs...)
		state.ranges = append(state.ranges, ranges...)
		state.lastSize = len(data)
		state.next++
		state.ordinal = ordinal
		if !packetview.TimeUnavailable(ci) && ci.Timestamp.After(state.last) {
			state.last = ci.Timestamp
		}
		if !a.Last {
			f.Qualifications = append(f.Qualifications, "ALP-segment-pending")
			return nil
		}
		data, refs, ranges = state.data, state.refs, state.ranges
		ci = state.first
		r.remove(key, false)
		r.health.Completed++
		status = "alp-reassembled"
	} else {
		r.remove(key, true, "whole-packet-interrupted-assembly")
	}
	f.Fields["reconstruction_status"] = status
	if a.PacketType == 4 {
		decodeALPSignalling(f, data, a.ComponentLengths)
		return nil
	}
	if a.PacketType == 7 {
		return r.reconstructTS(data, f, ci, scope, refs, ranges, p.Metadata().CaptureInfo.Timestamp)
	}
	if a.PacketType != 0 {
		return nil
	}
	lengths := a.ComponentLengths
	if len(lengths) == 0 {
		lengths = []int{len(data)}
	}
	children := make([]gopacket.Packet, 0, len(lengths))
	offset := 0
	for i, n := range lengths {
		if n < 20 || n > len(data)-offset || data[offset]>>4 != 4 || int(binary.BigEndian.Uint16(data[offset+2:])) != n {
			f.Qualifications = append(f.Qualifications, "invalid-ALP-IPv4-component")
			return nil
		}
		partRanges := ranges
		if len(lengths) > 1 {
			partRanges = []*types.LinkSourceRange{{CaptureOrdinal: ordinal, Offset: uint32(payloadOffset + offset), Length: uint32(n)}}
			status = "alp-concatenated"
		}
		children = append(children, derivedLinkPacket(data[offset:offset+n], layers.LayerTypeIPv4, ci, scope, refs, partRanges, i, status, p.Metadata().CaptureInfo.Timestamp, nil))
		offset += n
	}
	r.health.DerivedPackets += uint64(len(children))
	markLinkDecoded(f, "IPv4")
	return children
}
