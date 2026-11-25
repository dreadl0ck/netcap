package dnp3

import (
	"bytes"
	"github.com/dreadl0ck/netcap/types"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"strconv"
	"time"
)

type linkAssembly struct {
	join        layers.DNP3Assembler
	start, last int64
	previous    []byte
}
type linkAssemblies map[[3]int32]*linkAssembly

// Link CRC failures remain visible; their payload never contributes to an application record.
func (d *dnp3Reader) assembledFrame(states *linkAssemblies, wire []byte, at int64, server, oriented bool) *types.DNP3 {
	r, user := d.parseLinkFrame(wire, at, server, oriented)
	key := [3]int32{r.Source, r.Destination, r.Control >> 7}
	if user == nil {
		delete(*states, key)
		return r
	}
	seq := user[0]
	r.TransportFIR, r.TransportFIN, r.TransportSeq = seq&64 != 0, seq&128 != 0, int32(seq&63)
	if *states == nil {
		*states = make(linkAssemblies)
	}
	s := (*states)[key]
	if s != nil && (at-s.last > int64(30*time.Second) || at < s.last) {
		delete(*states, key)
		s = nil
	}
	if s == nil {
		if len(*states) >= 64 {
			for k, v := range *states {
				if at-v.last > int64(30*time.Second) {
					delete(*states, k)
				}
			}
		}
		if len(*states) >= 64 {
			r.ParseStatus, r.ParseError = statusLost, "transport assembly limit"
			return r
		}
		s = &linkAssembly{join: layers.DNP3Assembler{MaxFragment: 65535, MaxStreams: 1, MaxMessage: 16}}
		(*states)[key] = s
	}
	if len(s.previous) > 0 && bytes.Equal(s.previous, user) {
		return nil
	}
	s.last = at
	if r.TransportFIR {
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
		delete(*states, key)
		r.Assembly.Status, r.Assembly.Reason = "incomplete", err.Error()
		r.ParseStatus, r.ParseError = statusLost, err.Error()
		return r
	}
	if frag == nil {
		r.ParseStatus, r.ParseError = statusUnsupported, "transport fragment pending"
		return r
	}
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
	if frag.Err == nil && frag.Application != nil && !frag.Application.Control.FIN {
		r.Assembly.Status = "pending"
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
