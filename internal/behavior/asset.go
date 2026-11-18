package behavior

import (
	"encoding/json"
	"errors"
	"net"
	"net/netip"
	"sort"
)

type AssetRecord struct {
	ID                string      `json:"id"`
	Observation       Observation `json:"observation"`
	Label             *AssetLabel `json:"label,omitempty"`
	Direction         string      `json:"direction"`
	Prefixes          []string    `json:"prefixes,omitempty"`
	PrefixesTruncated bool        `json:"prefixesTruncated,omitempty"`
}

type AssetContext struct {
	Asset        string        `json:"asset"`
	Records      []AssetRecord `json:"records"`
	TotalRecords int           `json:"totalRecords"`
	Truncated    bool          `json:"truncated"`
}

// BuildAssetContext joins bindings only within their original network scope.
func BuildAssetContext(state Snapshot, asset string) (AssetContext, error) {
	if ip, err := netip.ParseAddr(asset); err == nil {
		asset = ip.String()
	} else if mac, err := net.ParseMAC(asset); err == nil {
		asset = mac.String()
	} else {
		return AssetContext{}, errors.New("asset must be an IP or MAC address")
	}
	result := AssetContext{Asset: asset, Records: []AssetRecord{}}
	related := make(map[string]map[string]bool)
	type assetPrefix struct {
		id         string
		cidr       netip.Prefix
		value      string
		provenance string
	}
	prefixes := make(map[string][]assetPrefix)
	for _, observation := range state.Observed {
		fact := observation.Fact
		if fact.Kind == "binding" && (fact.SrcIP == asset || fact.MAC == asset) {
			key := scopeKey(fact.Scope)
			if related[key] == nil {
				related[key] = make(map[string]bool)
			}
			related[key][fact.SrcIP], related[key][fact.MAC] = true, true
		}
	}
	for id, observation := range state.Observed {
		fact := observation.Fact
		key := scopeKey(fact.Scope)
		if fact.Kind == "binding" && related[key][fact.MAC] {
			related[key][fact.SrcIP] = true
		}
		if fact.Kind == "prefix" {
			if _, corrected := state.Corrections[id]; !corrected {
				if cidr, err := netip.ParsePrefix(fact.Value); err == nil {
					prefixes[key] = append(prefixes[key], assetPrefix{factID(fact), cidr, fact.Value, fact.Provenance})
				}
			}
		}
	}
	for key := range prefixes {
		rows := prefixes[key]
		sort.Slice(rows, func(i, j int) bool { return rows[i].id < rows[j].id })
	}
	const maxAssetRecords = 64
	type candidate struct {
		id      string
		labeled bool
	}
	candidates := make([]candidate, 0, maxAssetRecords)
	for id, observation := range state.Observed {
		fact := observation.Fact
		links := related[scopeKey(fact.Scope)]
		if fact.SrcIP == asset || fact.DstIP == asset || fact.MAC == asset || links[fact.SrcIP] || links[fact.DstIP] || links[fact.MAC] {
			result.TotalRecords++
			labeled := state.Labels[id].Name != ""
			i := sort.Search(len(candidates), func(i int) bool {
				other := candidates[i]
				if other.labeled != labeled {
					return labeled
				}
				return other.id >= id
			})
			if i == maxAssetRecords {
				continue
			}
			if len(candidates) < maxAssetRecords {
				candidates = append(candidates, candidate{})
			}
			copy(candidates[i+1:], candidates[i:])
			candidates[i] = candidate{id, labeled}
		}
	}
	bytes := 0
	for _, candidate := range candidates {
		id := candidate.id
		row := AssetRecord{ID: id, Observation: state.Observed[id], Direction: "unknown"}
		if label, ok := state.Labels[id]; ok {
			row.Label = &label
		}
		fact := row.Observation.Fact
		localSource, localTarget, known := false, false, false
		src, _ := netip.ParseAddr(fact.SrcIP)
		dst, _ := netip.ParseAddr(fact.DstIP)
		for _, prefix := range prefixes[scopeKey(fact.Scope)] {
			cidr := prefix.cidr
			known = known || cidr.Addr().BitLen() == src.BitLen() || cidr.Addr().BitLen() == dst.BitLen()
			localSource = localSource || cidr.Contains(src)
			localTarget = localTarget || cidr.Contains(dst)
			if len(row.Prefixes) < 8 {
				row.Prefixes = append(row.Prefixes, prefix.value+" ("+prefix.provenance+")")
			} else {
				row.PrefixesTruncated = true
			}
		}
		if known && src.IsValid() && dst.IsValid() && (fact.Kind == "edge" || fact.Kind == "service" || fact.Kind == "resolver" || fact.Kind == "geo") {
			switch {
			case localSource && localTarget:
				row.Direction = "internal"
			case localSource:
				row.Direction = "outbound"
			case localTarget:
				row.Direction = "inbound"
			default:
				row.Direction = "outside-prefixes"
			}
		}
		encoded, err := json.Marshal(row)
		if err != nil {
			return AssetContext{}, err
		}
		if bytes+len(encoded) > 240<<10 {
			break
		}
		bytes += len(encoded)
		result.Records = append(result.Records, row)
	}
	result.Truncated = len(result.Records) < result.TotalRecords
	return result, nil
}
