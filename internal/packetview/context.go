// Package packetview supplies bounded, scope-preserving inner datagram views.
// A Processor is owned by the collector's serialized admission path.
package packetview

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"strconv"
	"strings"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"

	"github.com/dreadl0ck/netcap/types"
)

// Context is immutable after dispatch and survives TCP/UDP capture-info copies.
type Context struct {
	Scope            string
	Tunnels          []*types.Encapsulation
	Packets          []*types.CapturePacketRef
	Reassembled      bool
	Status           string
	SyntheticNetwork bool // its original fragment headers were already audited
}

func FromCapture(ci gopacket.CaptureInfo) *Context {
	for _, a := range ci.AncillaryData {
		if c, ok := a.(*Context); ok {
			return c
		}
	}
	return nil
}

func Scope(p gopacket.Packet) string {
	if c := FromCapture(p.Metadata().CaptureInfo); c != nil {
		return c.Scope
	}
	s := "if:" + strconv.Itoa(p.Metadata().InterfaceIndex)
	for _, l := range p.Layers() {
		if v, ok := l.(*layers.Dot1Q); ok {
			s += fmt.Sprintf("/vlan:%d", v.VLANIdentifier)
		}
	}
	return s
}

func ScopeHash(p gopacket.Packet) uint64 {
	s := Scope(p)
	if s == "if:0" {
		return 0
	}
	h := sha256.Sum256([]byte(s))
	return binary.BigEndian.Uint64(h[:8])
}

// ScopeFlow supplies an opaque, direction-independent third reassembly key.
// Network endpoints remain unmodified for checksums and application attribution.
func ScopeFlow(ci gopacket.CaptureInfo) gopacket.Flow {
	s := "if:" + strconv.Itoa(ci.InterfaceIndex)
	if c := FromCapture(ci); c != nil {
		s = c.Scope
	}
	if s == "if:0" {
		return gopacket.Flow{}
	}
	h := sha256.Sum256([]byte(s))
	return gopacket.NewFlow(0, h[:16], h[16:])
}

// ScopeInterface fits the existing host/detection scope schema without changing it.
func ScopeInterface(p gopacket.Packet, base string) string {
	if c := FromCapture(p.Metadata().CaptureInfo); c != nil && len(c.Tunnels) > 0 {
		h := sha256.Sum256([]byte(c.Scope))
		return fmt.Sprintf("%s@tunnel:%x", base, h[:16])
	}
	if i := p.Metadata().InterfaceIndex; i != 0 {
		return fmt.Sprintf("%s#%d", base, i)
	}
	return base
}

func FillContext(dst *types.PacketContext, p gopacket.Packet) {
	dst.NetworkScope = Scope(p)
	if c := FromCapture(p.Metadata().CaptureInfo); c != nil {
		dst.Encapsulations, dst.CapturePackets = c.Tunnels, c.Packets
		dst.ReassembledIP, dst.Normalization = c.Reassembled, c.Status
	}
}

// Accounting attributes original wire packets to a completed datagram once.
func Accounting(p gopacket.Packet) (count, bytes, first, last int64) {
	ci := p.Metadata().CaptureInfo
	count, bytes, first, last = 1, int64(ci.Length), ci.Timestamp.UnixNano(), ci.Timestamp.UnixNano()
	if c := FromCapture(ci); c != nil && len(c.Packets) > 0 {
		count, bytes = int64(len(c.Packets)), 0
		first, last = c.Packets[0].Timestamp, c.Packets[0].Timestamp
		for _, r := range c.Packets {
			bytes += int64(r.WireLength)
			first, last = min(first, r.Timestamp), max(last, r.Timestamp)
		}
	}
	return
}

func tunnelScope(t *types.Encapsulation) string {
	a, b := t.SrcIP, t.DstIP
	if a > b {
		a, b = b, a
	}
	// UDP source ports are VTEP entropy, not tunnel identity. Keep them in evidence.
	port := max(t.SrcPort, t.DstPort)
	if t.Protocol == "vxlan" {
		port = 4789
	}
	if t.Protocol == "geneve" {
		port = 6081
	}
	return fmt.Sprintf("/%s:%s,%s:%d:%t:%d:%d:%d", t.Protocol, a, b, port, t.KeyPresent, t.GREKey, t.Identifier, t.VLAN)
}

func attach(p gopacket.Packet, ci gopacket.CaptureInfo, c *Context) gopacket.Packet {
	ci.AncillaryData = append(append([]any(nil), ci.AncillaryData...), c)
	// Replace any earlier normalization stamp after defragmenting a nested tunnel.
	for i := 0; i < len(ci.AncillaryData)-1; i++ {
		if _, ok := ci.AncillaryData[i].(*Context); ok {
			ci.AncillaryData = append(ci.AncillaryData[:i], ci.AncillaryData[i+1:]...)
			i--
		}
	}
	p.Metadata().CaptureInfo = ci
	return p
}

func vlanScope(ls []gopacket.Layer) string {
	var b strings.Builder
	for _, l := range ls {
		if v, ok := l.(*layers.Dot1Q); ok {
			fmt.Fprintf(&b, "/vlan:%d", v.VLANIdentifier)
		}
	}
	return b.String()
}
