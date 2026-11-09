package packetview

import (
	"strconv"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"

	"github.com/dreadl0ck/netcap/types"
)

// Result separates original header evidence from the one datagram eligible for
// application dispatch. Original owns pooled memory until all views are consumed.
type Result struct {
	Original gopacket.Packet
	Evidence []gopacket.Packet
	Packet   gopacket.Packet
	Opaque   gopacket.Packet // unresolved tunnel: network Connection only, never transport dispatch
	Status   string
}

func (p *Processor) Process(original gopacket.Packet, ordinal uint64) Result {
	r := Result{Original: original, Status: "complete"}
	ci := original.Metadata().CaptureInfo
	if ci.Timestamp.After(p.watermark) {
		p.watermark = ci.Timestamp
	}
	p.expire(p.watermark, false)
	nl := original.NetworkLayer()
	if nl == nil {
		r.Packet = original
		return r
	}
	if nl.LayerType() != layers.LayerTypeIPv4 && nl.LayerType() != layers.LayerTypeIPv6 {
		r.Packet = original
		return r
	}
	var link []gopacket.Layer
	offset := 0
	for _, l := range original.Layers() {
		if l == nl {
			break
		}
		link = append(link, l)
		offset += len(l.LayerContents())
	}
	c := &Context{Scope: "if:" + strconv.Itoa(ci.InterfaceIndex) + vlanScope(link), Status: "complete",
		Packets: []*types.CapturePacketRef{{Ordinal: ordinal, Timestamp: ci.Timestamp.UnixNano(), CaptureLength: int32(ci.CaptureLength), WireLength: int32(ci.Length), InterfaceIndex: int32(ci.InterfaceIndex)}}}
	// Network layer contents/payload form a contiguous range in the captured data.
	if offset > len(original.Data()) {
		r.Status = "malformed"
		return r
	}
	raw := original.Data()[offset:]
	for depth := 0; ; depth++ {
		d, err := parseIP(raw)
		if err != nil {
			p.stats.Malformed++
			r.Status = "malformed"
			// Keep original malformed headers; never dispatch a partial transport.
			if len(r.Evidence) == 0 {
				failed := *c
				failed.Status = r.Status
				r.Evidence = append(r.Evidence, attach(malformedEvidence(original), ci, &failed))
			}
			r.Opaque = r.Evidence[len(r.Evidence)-1]
			return r
		}
		if d.fragment {
			if d.truncated {
				p.stats.Malformed++
				r.Status = "malformed"
				failed := *c
				failed.Status = r.Status
				r.Evidence = append(r.Evidence, attach(levelPacket(d, link, nil, false), ci, &failed))
				return r
			}
			fragment := *c
			data, next, nextCI, status := p.defrag(d, c, ci)
			fragment.Status = status
			r.Evidence = append(r.Evidence, attach(levelPacket(d, link, nil, false), ci, &fragment))
			if data == nil {
				r.Status = status
				if status == "fragment-rejected" || status == "ipv4-checksum-rejected" {
					r.Opaque = r.Evidence[len(r.Evidence)-1]
				}
				return r
			}
			raw, c, ci = data, next, nextCI
			d, err = parseIP(raw)
			if err != nil || d.fragment {
				p.stats.Malformed++
				r.Status = "malformed"
				return r
			}
		}
		t, payload, protocol, extra, err := tunnel(d)
		if t == nil {
			if len(c.Tunnels) == 0 && !c.Reassembled && !d.fragment && original.Layer(layers.LayerTypeIPv6Fragment) == nil {
				// Keep the capture representation on the ordinary, single-IP path.
				r.Packet = attach(original, ci, c)
				return r
			}
			r.Packet = attach(levelPacket(d, link, nil, true), ci, c)
			return r
		}
		outer := *c
		if d.truncated {
			err = errMalformed
		}
		if err != nil {
			outer.Status = "malformed"
		}
		r.Evidence = append(r.Evidence, attach(levelPacket(d, link, extra, false), ci, &outer))
		if err != nil {
			p.stats.Malformed++
			r.Status = "malformed"
			r.Opaque = r.Evidence[len(r.Evidence)-1]
			return r
		}
		if depth >= p.limits.MaxDepth {
			p.stats.DepthLimited++
			r.Status = "depth-limit"
			outer.Status = r.Status
			r.Opaque = r.Evidence[len(r.Evidence)-1]
			return r
		}
		raw, link, err = innerLink(payload, protocol)
		if err != nil {
			p.stats.Malformed++
			r.Status = "malformed"
			outer.Status = r.Status
			r.Opaque = r.Evidence[len(r.Evidence)-1]
			return r
		}
		next := *c
		next.SyntheticNetwork = false
		next.Tunnels = append(append([]*types.Encapsulation(nil), c.Tunnels...), t)
		next.Scope += tunnelScope(t) + vlanScope(link)
		c = &next
	}
}
