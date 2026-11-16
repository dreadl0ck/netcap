package collector

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"sort"
	"strconv"
	"time"

	"github.com/dreadl0ck/netcap/internal/linkaudit"
	"github.com/dreadl0ck/netcap/internal/lowpan"
	"github.com/dreadl0ck/netcap/internal/packetview"
	"github.com/dreadl0ck/netcap/types"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

type lobacContext struct {
	prefix            netip.Prefix
	until, advertised time.Time
	ordinal           uint64
	conflict          bool
	ref               *types.CapturePacketRef
}
type lobacKey struct {
	scope string
	id    uint8
}

func (r *linkReconstructor) processLoBAC(p gopacket.Packet, f *linkaudit.LinkFrame, ordinal uint64) []gopacket.Packet {
	r.health.LimitBytes, r.health.AssemblyLimit = linkStateLimit, linkAssemblyLimit
	if r.err != nil || f.Fields["header_crc_valid"] != "true" || f.Fields["cobs_valid"] != "true" || f.Fields["data_crc32k_valid"] != "true" || len(f.Header) < 8 {
		return nil
	}
	scope := packetview.Scope(p) + "/mstp"
	f.Fields["network_scope"] = scope
	f.Fields["capture_ordinal"] = strconv.FormatUint(ordinal, 10)
	contexts := map[uint8]netip.Prefix{}
	ci := p.Metadata().CaptureInfo
	for key, entry := range r.lobacContexts {
		if key.scope == scope && !entry.conflict && (packetview.TimeUnavailable(ci) || entry.advertised.IsZero() || !ci.Timestamp.Before(entry.advertised)) {
			contexts[key.id] = entry.prefix
		}
	}
	if f.Header[4] == 255 {
		f.Qualifications = append(f.Qualifications, "invalid-6LoBAC-source-address")
		return nil
	}
	decoded, err := lowpan.Decode(f.Decoded, lowpan.Options{Source: uint16(f.Header[4]), Destination: uint16(f.Header[3]), Contexts: contexts})
	if err != nil {
		f.Qualifications = append(f.Qualifications, "6LoBAC: "+err.Error())
		return nil
	}
	if len(decoded.Packet) > 1500 {
		f.Qualifications = append(f.Qualifications, "6LoBAC-expanded-MTU-exceeded")
		return nil
	}
	base := 0
	for _, layer := range p.Layers() {
		if layer == f {
			break
		}
		base += len(layer.LayerContents())
	}
	length, err := parseLinkLength(f.Fields["declared_payload_length"])
	if err != nil {
		return nil
	}
	ranges := []*types.LinkSourceRange{{CaptureOrdinal: ordinal, Offset: uint32(base), Length: 8, Purpose: "link-header"}, {CaptureOrdinal: ordinal, Offset: uint32(base + 8), Length: uint32(length - 3), Purpose: "compressed-payload"}}
	refs := []*types.CapturePacketRef{linkRef(p, ordinal)}
	for _, id := range decoded.ContextIDs {
		entry := r.lobacContexts[lobacKey{scope: scope, id: id}]
		if entry.ref != nil {
			duplicate := false
			for _, source := range ranges {
				if source.CaptureOrdinal == entry.ref.Ordinal {
					duplicate = true
				}
			}
			if !duplicate {
				ranges = append(ranges, &types.LinkSourceRange{CaptureOrdinal: entry.ref.Ordinal, Length: uint32(entry.ref.CaptureLength), Purpose: "compression-context"})
			}
		}
	}
	child := derivedLinkPacket(decoded.Packet, layers.LayerTypeIPv6, ci, scope, refs, ranges, 0, "6lobac-iphc", ci.Timestamp, decoded.Synthesized)
	ctx := packetview.FromCapture(child.Metadata().CaptureInfo)
	ctx.LinkTransformations[0].Protocol = "6lobac-iphc"
	if child.Layer(layers.LayerTypeIPv6) == nil {
		f.Qualifications = append(f.Qualifications, "invalid-6LoBAC-expanded-IPv6")
		return nil
	}
	r.learnLoBACContexts(scope, decoded.Packet, ci, ordinal, f)
	markLinkDecoded(f, "IPv6")
	r.health.DerivedPackets++
	return []gopacket.Packet{child}
}

func parseLinkLength(value string) (int, error) {
	n := 0
	for _, ch := range value {
		if ch < '0' || ch > '9' || n > 65535 {
			return 0, fmt.Errorf("invalid link length")
		}
		n = n*10 + int(ch-'0')
	}
	if n < 5 || n > 2043 {
		return 0, fmt.Errorf("invalid link length")
	}
	return n, nil
}

func (r *linkReconstructor) expireLoBACContexts(ordinal uint64) {
	for key, entry := range r.lobacContexts {
		if (!entry.until.IsZero() && !r.watermark.Before(entry.until)) || ordinal >= entry.ordinal && ordinal-entry.ordinal > 65536 {
			delete(r.lobacContexts, key)
			r.health.BufferedBytes -= 512
		}
	}
}

func (r *linkReconstructor) learnLoBACContexts(scope string, data []byte, ci gopacket.CaptureInfo, ordinal uint64, f *linkaudit.LinkFrame) {
	if len(data) < 56 || data[7] != 255 {
		return
	}
	offset, next := 40, data[6]
	for depth := 0; next == 0 || next == 43 || next == 60; depth++ {
		if depth >= 8 || len(data)-offset < 2 {
			return
		}
		n := (int(data[offset+1]) + 1) * 8
		if n > len(data)-offset {
			return
		}
		next = data[offset]
		offset += n
	}
	if next != 58 || len(data)-offset < 16 || data[offset] != 134 || data[offset+1] != 0 {
		return
	}
	var src, dst [16]byte
	copy(src[:], data[8:24])
	copy(dst[:], data[24:40])
	if !netip.AddrFrom16(src).IsLinkLocalUnicast() || lowpan.Checksum(src, dst, 58, data[offset:]) != 0 {
		f.Qualifications = append(f.Qualifications, "6LoBAC-context-advertisement-check-failed")
		return
	}
	updates := map[uint8]lobacContext{}
	for offset := offset + 16; offset < len(data); {
		if len(data)-offset < 2 || data[offset+1] == 0 {
			f.Qualifications = append(f.Qualifications, "invalid-6LoBAC-ND-option")
			return
		}
		size := int(data[offset+1]) * 8
		if size > len(data)-offset {
			f.Qualifications = append(f.Qualifications, "truncated-6LoBAC-ND-option")
			return
		}
		option := data[offset : offset+size]
		offset += size
		if option[0] != 34 {
			continue
		}
		if size != 16 && size != 24 || int(option[2]) > 128 || (option[2] > 64) != (size == 24) {
			f.Qualifications = append(f.Qualifications, "invalid-6LoBAC-context-option")
			return
		}
		var prefix [16]byte
		copy(prefix[:], option[8:])
		id := option[3] & 15
		entry := lobacContext{prefix: netip.PrefixFrom(netip.AddrFrom16(prefix), int(option[2])).Masked(), ordinal: ordinal}
		if !packetview.TimeUnavailable(ci) {
			entry.advertised = ci.Timestamp
		}
		lifetime := binary.BigEndian.Uint16(option[6:8])
		if lifetime == 0 {
			entry.prefix = netip.Prefix{}
		} else if !packetview.TimeUnavailable(ci) {
			entry.until = ci.Timestamp.Add(time.Duration(lifetime) * time.Minute)
		}
		if prior, exists := updates[id]; exists && prior.prefix != entry.prefix {
			f.Qualifications = append(f.Qualifications, "conflicting-6LoBAC-context-options")
			return
		}
		updates[id] = entry
	}
	if r.lobacContexts == nil {
		r.lobacContexts = map[lobacKey]lobacContext{}
	}
	ids := make([]int, 0, len(updates))
	for id := range updates {
		ids = append(ids, int(id))
	}
	sort.Ints(ids)
	for _, value := range ids {
		id := uint8(value)
		entry := updates[id]
		key := lobacKey{scope: scope, id: id}
		prior, exists := r.lobacContexts[key]
		if exists && !entry.advertised.IsZero() && entry.advertised.Before(prior.advertised) {
			f.Qualifications = append(f.Qualifications, "late-6LoBAC-context-advertisement")
			continue
		}
		if !entry.until.IsZero() && !r.watermark.Before(entry.until) {
			f.Qualifications = append(f.Qualifications, "expired-6LoBAC-context-advertisement")
			continue
		}
		if !entry.prefix.IsValid() {
			if exists {
				delete(r.lobacContexts, key)
				r.health.BufferedBytes -= 512
			}
			continue
		}
		if exists && (prior.conflict || prior.prefix != entry.prefix) {
			prior.conflict = true
			r.lobacContexts[key] = prior
			f.Qualifications = append(f.Qualifications, "6LoBAC-context-conflict")
			continue
		}
		if !exists {
			if len(r.lobacContexts) >= 4096 {
				r.err = fmt.Errorf("6LoBAC context count limit exceeded")
				r.health.BudgetExceeded = true
				return
			}
			if !r.reserve(512) {
				return
			}
		}
		entry.ref = &types.CapturePacketRef{Ordinal: ordinal, Timestamp: ci.Timestamp.UnixNano(), CaptureLength: int32(ci.CaptureLength), WireLength: int32(ci.Length), InterfaceIndex: int32(ci.InterfaceIndex), TimestampUnavailable: packetview.TimeUnavailable(ci)}
		r.lobacContexts[key] = entry
	}
}
