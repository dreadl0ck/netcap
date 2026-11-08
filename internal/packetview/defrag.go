package packetview

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"sort"
	"time"

	"github.com/gopacket/gopacket"

	"github.com/dreadl0ck/netcap/types"
)

type Limits struct {
	MaxDatagrams, MaxBytes, MaxFragments, MaxDepth int
	Timeout                                        time.Duration
}

func DefaultLimits() Limits {
	return Limits{MaxDatagrams: 4096, MaxBytes: 32 << 20, MaxFragments: 128, MaxDepth: 8, Timeout: 30 * time.Second}
}

type Stats struct {
	Completed, Duplicates, Rejected, Expired, Incomplete, Limited, Malformed, DepthLimited uint64
	Datagrams, BufferedBytes                                                               int
}

type fragmentPiece struct {
	offset int
	data   []byte
	more   bool
}
type fragmentSet struct {
	pieces            []fragmentPiece
	header, signature []byte
	previousNext      int
	proto             byte
	end, size         int
	refs              []*types.CapturePacketRef
	ci                gopacket.CaptureInfo
	created, wall     time.Time
	closed            bool
}

type Processor struct {
	limits     Limits
	sets       map[string]*fragmentSet
	watermark  time.Time
	nextExpiry time.Time
	stats      Stats
}

func New(l Limits) *Processor {
	d := DefaultLimits()
	if l.MaxDatagrams <= 0 {
		l.MaxDatagrams = d.MaxDatagrams
	}
	if l.MaxBytes <= 0 {
		l.MaxBytes = d.MaxBytes
	}
	if l.MaxFragments <= 0 {
		l.MaxFragments = d.MaxFragments
	}
	if l.MaxDepth <= 0 {
		l.MaxDepth = d.MaxDepth
	}
	if l.Timeout <= 0 {
		l.Timeout = d.Timeout
	}
	// Hard ceilings also bound callers accidentally supplying unbounded limits.
	l.MaxDatagrams = min(l.MaxDatagrams, 65536)
	l.MaxBytes = min(l.MaxBytes, 256<<20)
	l.MaxFragments = min(l.MaxFragments, 1024)
	l.MaxDepth = min(l.MaxDepth, 16)
	return &Processor{limits: l, sets: make(map[string]*fragmentSet)}
}

func (p *Processor) Stats() Stats { s := p.stats; s.Datagrams = len(p.sets); return s }

// Reset releases both pending datagrams and duplicate/rejection tombstones.
// Cumulative counters survive shutdown for reporting.
func (p *Processor) Reset() {
	for _, f := range p.sets {
		if !f.closed {
			p.stats.Incomplete++
		}
	}
	clear(p.sets)
	p.watermark, p.nextExpiry = time.Time{}, time.Time{}
	p.stats.BufferedBytes = 0
}

func (p *Processor) expire(at time.Time, wall bool) {
	if !wall && (p.nextExpiry.IsZero() || at.Before(p.nextExpiry)) {
		return
	}
	if !wall {
		p.nextExpiry = time.Time{}
	}
	for k, f := range p.sets {
		start := f.created
		if wall {
			start = f.wall
		}
		if at.Sub(start) >= p.limits.Timeout {
			if !f.closed {
				p.stats.Expired++
			}
			p.stats.BufferedBytes -= f.size
			delete(p.sets, k)
		} else if !wall {
			due := f.created.Add(p.limits.Timeout)
			if p.nextExpiry.IsZero() || due.Before(p.nextExpiry) {
				p.nextExpiry = due
			}
		}
	}
}

// ExpireIdle is for live-capture maintenance; offline expiry uses capture time.
func (p *Processor) ExpireIdle(now time.Time) { p.expire(now, true) }

func (p *Processor) close(f *fragmentSet) {
	p.stats.BufferedBytes -= f.size
	f.pieces, f.header, f.signature, f.refs, f.ci.AncillaryData = nil, nil, nil, nil, nil
	f.size, f.closed = 0, true
}

func (p *Processor) reject(f *fragmentSet, limited bool) {
	p.stats.Rejected++
	if limited {
		p.stats.Limited++
	}
	p.close(f)
}

func fragmentKey(d *datagram, scope string) string {
	n := d.network.NetworkFlow()
	proto := int(d.proto)
	if d.v6 {
		proto = 0
	} // RFC 8200: a mismatched Next Header poisons the same set.
	return fmt.Sprintf("%s/%s>%s/%t/%d/%d", scope, n.Src(), n.Dst(), d.v6, proto, d.id)
}

func reconstruct(header, payload []byte, v6 bool, previousNext int, proto byte) []byte {
	out := append(append([]byte(nil), header...), payload...)
	if v6 {
		out[previousNext] = proto
		binary.BigEndian.PutUint16(out[4:6], uint16(len(out)-40))
	} else {
		out[6], out[7], out[10], out[11] = 0, 0, 0, 0
		binary.BigEndian.PutUint16(out[2:4], uint16(len(out)))
		binary.BigEndian.PutUint16(out[10:12], gopacket.FoldChecksum(gopacket.ComputeChecksum(out[:len(header)], 0)))
	}
	return out
}

// defrag accepts exact duplicates but rejects every partial/conflicting overlap.
// Closed IDs stay quarantined until the absolute timeout, preventing duplicate
// transport emission and reconstruction from the tail of a rejected set.
func (p *Processor) defrag(d *datagram, c *Context, ci gopacket.CaptureInfo) ([]byte, *Context, gopacket.CaptureInfo, string) {
	if d.v6 && d.offset == 0 && !d.more {
		atomic := *c
		atomic.SyntheticNetwork = true
		return reconstruct(d.raw[:d.headerEnd], d.payload, true, d.previousNext, byte(d.proto)), &atomic, ci, "complete"
	}
	key := fragmentKey(d, c.Scope)
	f := p.sets[key]
	if f == nil {
		if len(p.sets) >= p.limits.MaxDatagrams {
			p.stats.Limited++
			return nil, c, ci, "fragment-rejected"
		}
		f = &fragmentSet{created: p.watermark, wall: time.Now(), end: -1, proto: byte(d.proto)}
		p.sets[key] = f
		due := f.created.Add(p.limits.Timeout)
		if p.nextExpiry.IsZero() || due.Before(p.nextExpiry) {
			p.nextExpiry = due
		}
	}
	if f.closed {
		p.stats.Duplicates++
		return nil, c, ci, "fragment-rejected"
	}
	end := d.offset + len(d.payload)
	maxPayload := 65535 - 20
	if d.v6 {
		maxPayload = 65535 - (d.headerEnd - 40)
	}
	invalid := len(d.payload) == 0 || end > maxPayload || (d.more && len(d.payload)%8 != 0) || f.proto != byte(d.proto)
	if f.end >= 0 && (end > f.end || (!d.more && end != f.end) || (d.more && end >= f.end)) {
		invalid = true
	}
	if !d.more {
		for _, piece := range f.pieces {
			if piece.offset+len(piece.data) > end || (piece.more && piece.offset+len(piece.data) >= end) {
				invalid = true
			}
		}
	}
	if invalid {
		p.reject(f, false)
		return nil, c, ci, "fragment-rejected"
	}
	var signature []byte
	if d.v6 {
		signature = append([]byte(nil), d.raw[:d.headerEnd]...)
		signature[4], signature[5], signature[7] = 0, 0, 0
		if f.signature != nil && !bytes.Equal(f.signature, signature) {
			p.reject(f, false)
			return nil, c, ci, "fragment-rejected"
		}
	}
	duplicate := false
	for _, piece := range f.pieces {
		if d.offset < piece.offset+len(piece.data) && end > piece.offset {
			if d.offset == piece.offset && end == piece.offset+len(piece.data) && d.more == piece.more && bytes.Equal(d.payload, piece.data) {
				duplicate = true
				break
			}
			p.reject(f, false)
			return nil, c, ci, "fragment-rejected"
		}
	}
	// Every retained provenance ref is budgeted; duplicates cannot grow a set forever.
	need := len(c.Packets) * 64
	if !duplicate {
		need += len(d.payload)
	}
	if d.offset == 0 && f.header == nil {
		need += d.headerEnd
	}
	if f.signature == nil {
		need += len(signature)
	}
	if len(f.refs)+len(c.Packets) > p.limits.MaxFragments || p.stats.BufferedBytes+need > p.limits.MaxBytes {
		p.reject(f, true)
		return nil, c, ci, "fragment-rejected"
	}
	f.size += need
	p.stats.BufferedBytes += need
	f.refs = append(f.refs, c.Packets...)
	if f.signature == nil {
		f.signature = signature
	}
	if d.offset == 0 && f.header == nil {
		f.header, f.previousNext, f.ci = append([]byte(nil), d.raw[:d.headerEnd]...), d.previousNext, ci
		f.ci.AncillaryData = append([]any(nil), ci.AncillaryData...)
	}
	if duplicate {
		p.stats.Duplicates++
	} else {
		f.pieces = append(f.pieces, fragmentPiece{d.offset, append([]byte(nil), d.payload...), d.more})
		sort.Slice(f.pieces, func(i, j int) bool { return f.pieces[i].offset < f.pieces[j].offset })
	}
	if !d.more {
		f.end = end
	}
	if f.header == nil || f.end < 0 {
		return nil, c, ci, "fragment-pending"
	}
	n := 0
	for _, piece := range f.pieces {
		if piece.offset != n {
			return nil, c, ci, "fragment-pending"
		}
		n += len(piece.data)
	}
	if n != f.end {
		return nil, c, ci, "fragment-pending"
	}
	if (!d.v6 && n+len(f.header) > 65535) || (d.v6 && n+len(f.header)-40 > 65535) {
		p.reject(f, false)
		return nil, c, ci, "fragment-rejected"
	}
	payload := make([]byte, n)
	for _, piece := range f.pieces {
		copy(payload[piece.offset:], piece.data)
	}
	out := reconstruct(f.header, payload, d.v6, f.previousNext, f.proto)
	context := *c
	// Nested reconstruction inherits the completing outer datagram's admission time.
	if !c.Reassembled {
		context.CompletedAt = ci.Timestamp
	}
	context.Packets, context.Reassembled, context.SyntheticNetwork = f.refs, true, true
	sort.Slice(context.Packets, func(i, j int) bool { return context.Packets[i].Ordinal < context.Packets[j].Ordinal })
	ci = f.ci
	// Timestamp the observation at its earliest captured constituent, including epoch zero.
	first := context.Packets[0].Timestamp
	for _, r := range context.Packets {
		first = min(first, r.Timestamp)
	}
	ci.Timestamp = time.Unix(0, first)
	p.close(f)
	p.stats.Completed++
	return out, &context, ci, "complete"
}
