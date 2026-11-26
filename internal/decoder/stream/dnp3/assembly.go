package dnp3

import (
	"bytes"
	"cmp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"

	"github.com/dreadl0ck/netcap/types"
)

type linkAssembly struct {
	join        layers.DNP3Assembler
	start, last int64
	previous    []byte
	transport   *types.DNP3
	message     [2]*types.DNP3 // solicited and unsolicited
}
type linkAssemblies map[[3]int32]*linkAssembly

// Keep only attribution for a pending transfer, never the decoded point data.
func pendingLink(r *types.DNP3) *types.DNP3 {
	return &types.DNP3{Timestamp: r.Timestamp, SrcIP: r.SrcIP, DstIP: r.DstIP, SrcPort: r.SrcPort, DstPort: r.DstPort, Source: r.Source, Destination: r.Destination, CommunityID: r.CommunityID, IsMaster: r.IsMaster, ParseStatus: statusLost, CorrelationStatus: corrNotApplicable, Assembly: &types.OTAssembly{FirstTimestamp: r.Timestamp, Status: "incomplete"}}
}

func endLink(r *types.DNP3, why string, emit func(*types.DNP3)) {
	if r != nil {
		r.ParseError, r.Assembly.Reason = why, why
		emit(r)
	}
}

func (s *linkAssembly) end(why string, emit func(*types.DNP3)) {
	endLink(s.transport, why, emit)
	for _, r := range s.message {
		endLink(r, why, emit)
	}
}

func (m linkAssemblies) flush(before int64, all bool, why string, emit func(*types.DNP3)) {
	var rows []*types.DNP3
	for k, s := range m {
		if all || s.last < before {
			s.end(why, func(r *types.DNP3) { rows = append(rows, r) })
			delete(m, k)
		}
	}
	slices.SortFunc(rows, func(a, b *types.DNP3) int {
		if v := cmp.Compare(a.Timestamp, b.Timestamp); v != 0 {
			return v
		}
		return strings.Compare(a.String(), b.String())
	})
	for _, r := range rows {
		emit(r)
	}
}

// Link CRC failures remain visible; their payload never contributes to an application record.
func (d *dnp3Reader) assembledFrame(states *linkAssemblies, wire []byte, at int64, server, oriented bool, emit func(*types.DNP3)) *types.DNP3 {
	r, user := d.parseLinkFrame(wire, at, server, oriented)
	key := [3]int32{r.Source, r.Destination, r.Control >> 7}
	if user == nil {
		if s := (*states)[key]; s != nil && r.ParseStatus == statusMalformed {
			s.end(r.ParseError, emit)
			delete(*states, key)
		}
		return r
	}
	seq := user[0]
	r.TransportFIR, r.TransportFIN, r.TransportSeq = seq&64 != 0, seq&128 != 0, int32(seq&63)
	if *states == nil {
		*states = make(linkAssemblies)
	}
	s := (*states)[key]
	if s != nil && (at-s.last > int64(30*time.Second) || at < s.last) {
		s.end("capture time discontinuity or idle expiry", emit)
		delete(*states, key)
		s = nil
	}
	if s == nil {
		if len(*states) >= 64 {
			states.flush(at-int64(30*time.Second), false, "idle expiry", emit)
		}
		if len(*states) >= 64 {
			r.ParseStatus, r.ParseError = statusLost, "transport assembly limit"
			return r
		}
		s = &linkAssembly{start: at, join: layers.DNP3Assembler{MaxFragment: 65535, MaxStreams: 1, MaxMessage: 16}}
		(*states)[key] = s
	}
	if len(s.previous) > 0 && bytes.Equal(s.previous, user) {
		return nil
	}
	s.last = at
	if r.TransportFIR {
		endLink(s.transport, "transport fragment replaced", emit)
		s.transport = nil
		s.start = at
	}
	if r.TransportFIN {
		s.previous = nil
	} else {
		s.previous = bytes.Clone(user)
	}
	var p layers.DNP3
	_ = p.DecodeFromBytes(wire, gopacket.NilDecodeFeedback)
	frag, err := s.join.Add(&p)
	r.Assembly = &types.OTAssembly{FirstTimestamp: s.start, Status: "pending"}
	if err != nil {
		for _, msg := range s.message {
			endLink(msg, "transport loss", emit)
		}
		delete(*states, key)
		r.Assembly.Status, r.Assembly.Reason = "incomplete", err.Error()
		r.ParseStatus, r.ParseError = statusLost, err.Error()
		return r
	}
	if frag == nil {
		if s.transport == nil {
			s.transport = pendingLink(r)
		}
		s.transport.Assembly.Pieces++
		r.ParseStatus, r.ParseError = statusUnsupported, "transport fragment pending"
		return r
	}
	s.transport = nil
	r.Timestamp = s.start
	r.Assembly.Pieces = uint32(frag.Segments)
	r.Assembly.Status = "complete"
	d.parseApplicationLayer(r, append([]byte{seq | 0xc0}, frag.Data...))
	r.TransportFIR, r.TransportFIN = seq&64 != 0, seq&128 != 0
	r.ApplicationFragments = uint32(len(frag.Message))
	if frag.Err != nil {
		r.Assembly.Status, r.Assembly.Reason = "incomplete", frag.Err.Error()
	}
	if frag.Application != nil {
		r.DecodedPoints = points(frag.Application)
	}
	if a := frag.Application; a != nil {
		i := 0
		if a.Control.UNS {
			i = 1
		}
		if a.Control.FIR {
			endLink(s.message[i], "application message replaced", emit)
			s.message[i] = nil
		}
		if frag.Err == nil && !a.Control.FIN {
			if s.message[i] == nil {
				s.message[i] = pendingLink(r)
			}
			s.message[i].Assembly.Pieces += r.Assembly.Pieces
			r.Assembly.Status = "pending"
		} else {
			if m := s.message[i]; m != nil {
				r.Assembly.FirstTimestamp = m.Timestamp
				r.Assembly.Pieces += m.Assembly.Pieces
			}
			s.message[i] = nil
		}
	}
	if s.message[0] == nil && s.message[1] == nil {
		delete(*states, key)
	}
	return r
}

func points(app *layers.DNP3Application) (out []*types.DNP3Point) {
	for _, h := range app.Objects {
		n := len(h.Objects)
		if h.BitsPerObject > 0 {
			n = int(min(h.Count, uint64(len(h.Data)*8/int(h.BitsPerObject))))
		}
		for i := 0; i < n && len(out) < 4096; i++ {
			v, err := h.Value(i)
			if err != nil {
				continue
			}
			var text string
			switch x := v.(type) {
			case layers.DNP3Binary:
				text = strconv.FormatBool(x.State)
			case layers.DNP3Analog:
				text = strconv.FormatFloat(x.Value, 'g', -1, 64)
			case layers.DNP3Counter:
				text = strconv.FormatUint(uint64(x.Value), 10)
			default:
				continue
			}
			idx := h.Start + uint32(i)
			if i < len(h.Objects) {
				idx = h.Objects[i].Index
			}
			out = append(out, &types.DNP3Point{Group: uint32(h.Group), Variation: uint32(h.Variation), Index: idx, Value: text})
		}
	}
	return out
}
