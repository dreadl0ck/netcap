package collector

import (
	"fmt"
	"strconv"
	"time"

	"github.com/dreadl0ck/netcap/internal/linkaudit"
	"github.com/dreadl0ck/netcap/internal/packetview"
	"github.com/dreadl0ck/netcap/types"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

type ax25Mode struct {
	mode, pending int
	proposer      string
	ordinal       uint64
	stamp         time.Time
	refs          []*types.CapturePacketRef
}

func (r *linkReconstructor) expireAX25(ordinal uint64) {
	for key, state := range r.ax25Modes {
		if !state.stamp.IsZero() && state.stamp.Add(time.Minute).Before(r.watermark) || ordinal >= state.ordinal && ordinal-state.ordinal > 65536 {
			delete(r.ax25Modes, key)
			r.health.BufferedBytes -= 512
		}
	}
}

func (r *linkReconstructor) processAX25(p gopacket.Packet, f *linkaudit.LinkFrame, ordinal uint64) []gopacket.Packet {
	r.health.LimitBytes, r.health.AssemblyLimit = linkStateLimit, linkAssemblyLimit
	if r.err != nil {
		return nil
	}
	left, right := f.Source, f.Destination
	if left > right {
		left, right = right, left
	}
	scope := packetview.Scope(p) + "/ax25:" + left + "," + right
	f.Fields["network_scope"] = scope
	offset, err := strconv.Atoi(f.Fields["control_offset"])
	if err != nil {
		return nil
	}
	base := 0
	for _, layer := range p.Layers() {
		if layer == f {
			break
		}
		base += len(layer.LayerContents())
	}
	offset += base
	if offset >= len(p.Data()) {
		return nil
	}
	data := p.Data()
	control := data[offset]
	kind := control & 0xef
	if r.ax25Modes == nil {
		r.ax25Modes = map[string]*ax25Mode{}
	}
	state := r.ax25Modes[scope]
	if kind == 0x2f || kind == 0x6f {
		if state == nil {
			if len(r.ax25Modes) >= 4096 || !r.reserve(512) {
				r.err = fmt.Errorf("AX.25 mode/state budget exceeded")
				r.health.BudgetExceeded = true
				return nil
			}
			state = &ax25Mode{}
			r.ax25Modes[scope] = state
		}
		state.mode = 0
		state.pending = 8
		if kind == 0x6f {
			state.pending = 128
		}
		state.proposer = f.Source
		state.refs = []*types.CapturePacketRef{linkRef(p, ordinal)}
		state.ordinal = ordinal
		state.stamp = p.Metadata().Timestamp
		f.Fields["mode_negotiation"] = "proposed"
		return nil
	}
	if kind == 0x43 || kind == 0x0f {
		if state != nil {
			delete(r.ax25Modes, scope)
			r.health.BufferedBytes -= 512
		}
		return nil
	}
	if kind == 0x63 && state != nil && state.pending != 0 && state.proposer == f.Destination {
		state.mode, state.pending = state.pending, 0
		state.refs = append(state.refs, linkRef(p, ordinal))
		state.ordinal = ordinal
		state.stamp = p.Metadata().Timestamp
		f.Fields["modulus"] = strconv.Itoa(state.mode)
		f.Fields["mode_negotiation"] = "accepted"
		return nil
	}
	ui := kind == 3
	if !ui && control&3 != 0 && control&3 != 2 && control&3 != 1 {
		return nil
	}
	length := 1
	if !ui {
		if state == nil || state.mode == 0 {
			return nil
		}
		state.ordinal = ordinal
		state.stamp = p.Metadata().Timestamp
		f.Fields["modulus"] = strconv.Itoa(state.mode)
		if state.mode == 128 {
			length = 2
			if len(data)-offset < 2 {
				f.Qualifications = append(f.Qualifications, "short-AX25-extended-control")
				return nil
			}
			f.Fields["sequence_receive"] = strconv.Itoa(int(data[offset+1] >> 1))
			f.Fields["poll_final"] = strconv.FormatBool(data[offset+1]&1 != 0)
		} else {
			f.Fields["sequence_receive"] = strconv.Itoa(int(control >> 5))
			f.Fields["poll_final"] = strconv.FormatBool(control&16 != 0)
		}
		if control&1 == 0 {
			if state.mode == 128 {
				f.Fields["sequence_send"] = strconv.Itoa(int(control >> 1))
			} else {
				f.Fields["sequence_send"] = strconv.Itoa(int(control >> 1 & 7))
			}
		} else {
			f.Fields["supervisory"] = []string{"RR", "RNR", "REJ", "SREJ"}[control>>2&3]
			return nil
		}
	}
	pidOffset := offset + length
	if pidOffset >= len(data) {
		f.Qualifications = append(f.Qualifications, "AX25-PID-missing")
		return nil
	}
	pid := data[pidOffset]
	f.Fields["pid"] = fmt.Sprintf("0x%02x", pid)
	var decoder gopacket.Decoder
	protocol := ""
	switch pid {
	case 0xcc:
		decoder, protocol = layers.LayerTypeIPv4, "IPv4"
	case 0xcd:
		decoder, protocol = layers.LayerTypeARP, "ARP"
	default:
		f.Qualifications = append(f.Qualifications, "AX25-PID-not-decoded")
		return nil
	}
	refs := []*types.CapturePacketRef{linkRef(p, ordinal)}
	ranges := []*types.LinkSourceRange{{CaptureOrdinal: ordinal, Offset: uint32(base), Length: uint32(len(data) - base)}}
	if !ui {
		for _, ref := range state.refs {
			ranges = append(ranges, &types.LinkSourceRange{CaptureOrdinal: ref.Ordinal, Length: uint32(ref.CaptureLength), Purpose: "control-mode-negotiation"})
		}
	}
	child := derivedLinkPacket(data[pidOffset+1:], decoder, p.Metadata().CaptureInfo, scope, refs, ranges, 0, "ax25-decapsulated", p.Metadata().Timestamp, nil)
	ctx := packetview.FromCapture(child.Metadata().CaptureInfo)
	ctx.LinkTransformations[0].Protocol = "ax25"
	if child.Layer(layers.LayerTypeIPv4) == nil && child.Layer(layers.LayerTypeARP) == nil {
		f.Qualifications = append(f.Qualifications, "invalid-AX25-inner-packet")
		return nil
	}
	qualifications := f.Qualifications[:0]
	for _, q := range f.Qualifications {
		if q != "AX25-control-mode-not-inferred" {
			qualifications = append(qualifications, q)
		}
	}
	f.Qualifications = qualifications
	markLinkDecoded(f, protocol)
	r.health.DerivedPackets++
	return []gopacket.Packet{child}
}
