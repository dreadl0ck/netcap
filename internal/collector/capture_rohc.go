package collector

import (
	"bytes"
	"fmt"
	"strconv"
	"time"

	"github.com/dreadl0ck/netcap/internal/linkaudit"
	"github.com/dreadl0ck/netcap/internal/packetview"
	"github.com/dreadl0ck/netcap/internal/rohc"
	"github.com/dreadl0ck/netcap/types"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

type rohcChannel struct {
	description     rohc.Description
	states          map[byte]rohc.Context
	lastPacket      map[byte]*types.CapturePacketRef
	lastStamp       map[byte]time.Time
	refs            []*types.CapturePacketRef
	signature       []byte
	stamp           time.Time
	ordinal, credit uint64
	version         string
	conflict        bool
}

func (r *linkReconstructor) expireROHC(ordinal uint64) {
	for key, channel := range r.rohcChannels {
		if !channel.stamp.IsZero() && channel.stamp.Add(time.Minute).Before(r.watermark) || ordinal >= channel.ordinal && ordinal-channel.ordinal > 65536 {
			r.health.BufferedBytes -= channel.credit
			delete(r.rohcChannels, key)
		}
	}
}

func rdtSignature(d rohc.Description) []byte {
	out := []byte{d.PLP, d.MaxCID, d.Mode, d.Config}
	for _, entry := range d.Contexts {
		out = append(out, entry.ID, entry.Profile, byte(len(entry.Chain)))
		out = append(out, entry.Chain...)
	}
	return out
}

func (r *linkReconstructor) installROHC(p gopacket.Packet, f *linkaudit.LinkFrame, refs []*types.CapturePacketRef, ordinal uint64) {
	if r.rohcChannels == nil {
		r.rohcChannels = map[string]*rohcChannel{}
	}
	for _, description := range f.ALP.RDTs {
		key := packetview.Scope(p) + "/alp/plp:" + strconv.Itoa(int(description.PLP))
		signature := rdtSignature(description)
		if channel := r.rohcChannels[key]; channel != nil && !packetview.TimeUnavailable(p.Metadata().CaptureInfo) && p.Metadata().Timestamp.Before(channel.stamp) {
			f.Qualifications = append(f.Qualifications, "ROHC-late-description-not-applied")
			continue
		}
		if channel := r.rohcChannels[key]; channel != nil && channel.conflict && channel.version == f.Fields["signalling_version"] {
			f.Qualifications = append(f.Qualifications, "ROHC-RDT-version-conflict")
			continue
		}
		if channel := r.rohcChannels[key]; channel != nil && !channel.conflict && bytes.Equal(signature, channel.signature) {
			channel.refs = refs
			channel.ordinal = ordinal
			channel.stamp = p.Metadata().CaptureInfo.Timestamp
			channel.version = f.Fields["signalling_version"]
			continue
		}
		if channel := r.rohcChannels[key]; channel != nil && channel.version == f.Fields["signalling_version"] {
			channel.conflict = true
			channel.states = map[byte]rohc.Context{}
			f.Qualifications = append(f.Qualifications, "ROHC-RDT-version-conflict")
			continue
		}
		states, err := description.InitialStates()
		if err != nil {
			if old := r.rohcChannels[key]; old != nil {
				r.health.BufferedBytes -= old.credit
				delete(r.rohcChannels, key)
			}
			f.Qualifications = append(f.Qualifications, "unsupported-ROHC-RDT-chain: "+err.Error())
			continue
		}
		credit := uint64(65536 + len(signature))
		if old := r.rohcChannels[key]; old != nil {
			r.health.BufferedBytes -= old.credit
			delete(r.rohcChannels, key)
		}
		if !r.reserve(credit) {
			return
		}
		r.rohcChannels[key] = &rohcChannel{description: description, states: states, lastPacket: map[byte]*types.CapturePacketRef{}, lastStamp: map[byte]time.Time{}, refs: refs, signature: signature, credit: credit, ordinal: ordinal, stamp: p.Metadata().CaptureInfo.Timestamp, version: f.Fields["signalling_version"]}
	}
}

func (r *linkReconstructor) reconstructROHC(p gopacket.Packet, f *linkaudit.LinkFrame, data []byte, scope string, refs []*types.CapturePacketRef, ranges []*types.LinkSourceRange, ordinal uint64) []gopacket.Packet {
	if !f.ALP.PLPPresent {
		f.Qualifications = append(f.Qualifications, "ROHC-PLP-identity-unavailable")
		return nil
	}
	key := packetview.Scope(p) + "/alp/plp:" + strconv.Itoa(int(f.ALP.PLP))
	channel := r.rohcChannels[key]
	if channel == nil {
		f.Qualifications = append(f.Qualifications, "ROHC-description-unavailable")
		return nil
	}
	if channel.conflict {
		f.Qualifications = append(f.Qualifications, "ROHC-RDT-version-conflict")
		return nil
	}
	if !packetview.TimeUnavailable(p.Metadata().CaptureInfo) && p.Metadata().Timestamp.Before(channel.stamp) {
		f.Qualifications = append(f.Qualifications, "ROHC-late-packet-context-not-applied")
		return nil
	}
	lengths := f.ALP.ComponentLengths
	if len(lengths) == 0 {
		lengths = []int{len(data)}
	}
	offset := 0
	var children []gopacket.Packet
	for child, length := range lengths {
		if length <= 0 || length > len(data)-offset {
			return nil
		}
		wire := data[offset : offset+length]
		id, first, after, err := rohc.PacketCID(wire, channel.description.MaxCID > 15)
		if err != nil || id > channel.description.MaxCID {
			f.Qualifications = append(f.Qualifications, "invalid-ROHC-CID")
			offset += length
			continue
		}
		allowed := true
		for _, entry := range channel.description.Contexts {
			if entry.ID == id && entry.Profile != 2 {
				allowed = false
			}
		}
		if !allowed {
			f.Qualifications = append(f.Qualifications, "ROHC-profile-not-supported")
			offset += length
			continue
		}
		if !packetview.TimeUnavailable(p.Metadata().CaptureInfo) && p.Metadata().Timestamp.Before(channel.lastStamp[id]) {
			f.Qualifications = append(f.Qualifications, "ROHC-late-packet-context-not-applied")
			offset += length
			continue
		}
		updated, packet, err := rohc.DecodeUDP(channel.states[id], wire, first, after)
		if err != nil {
			f.Qualifications = append(f.Qualifications, "ROHC: "+err.Error())
			offset += length
			continue
		}
		prior := channel.lastPacket[id]
		channel.states[id] = updated
		channel.lastPacket[id] = refs[len(refs)-1]
		if !packetview.TimeUnavailable(p.Metadata().CaptureInfo) {
			channel.lastStamp[id] = p.Metadata().Timestamp
		}
		if len(packet) == 0 {
			offset += length
			continue
		}
		decoder := gopacket.Decoder(layers.LayerTypeIPv4)
		if packet[0]>>4 == 6 {
			decoder = layers.LayerTypeIPv6
		}
		sources := append([]*types.LinkSourceRange(nil), ranges...)
		if len(lengths) > 1 {
			sources = []*types.LinkSourceRange{{CaptureOrdinal: ordinal, Offset: ranges[0].Offset + uint32(offset), Length: uint32(length), Purpose: "compressed-payload"}}
		}
		for _, ref := range channel.refs {
			sources = append(sources, &types.LinkSourceRange{CaptureOrdinal: ref.Ordinal, Length: uint32(ref.CaptureLength), Purpose: "compression-context"})
		}
		if prior != nil && prior.Ordinal != ordinal {
			sources = append(sources, &types.LinkSourceRange{CaptureOrdinal: prior.Ordinal, Length: uint32(prior.CaptureLength), Purpose: "compression-context"})
		}
		derived := derivedLinkPacket(packet, decoder, p.Metadata().CaptureInfo, scope, refs, sources, child, "alp-rohc-udp", p.Metadata().Timestamp, []string{"IPv4-or-IPv6-and-UDP-headers-restored-from-ROHC"})
		ctx := packetview.FromCapture(derived.Metadata().CaptureInfo)
		ctx.LinkTransformations[0].Protocol = "rohc-udp"
		if derived.NetworkLayer() != nil {
			children = append(children, derived)
		} else {
			f.Qualifications = append(f.Qualifications, fmt.Sprintf("invalid-ROHC-expanded-IP-CID-%d", id))
		}
		offset += length
	}
	r.health.DerivedPackets += uint64(len(children))
	if len(children) > 0 {
		markLinkDecoded(f, "ROHC-UDP/IP")
	}
	return children
}
