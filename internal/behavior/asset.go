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
	prefixes := make(map[string][]Fact)
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
				prefixes[key] = append(prefixes[key], fact)
			}
		}
	}
	for key := range prefixes {
		sort.Slice(prefixes[key], func(i, j int) bool { return factID(prefixes[key][i]) < factID(prefixes[key][j]) })
	}
	ids := make([]string, 0)
	for id, observation := range state.Observed {
		fact := observation.Fact
		links := related[scopeKey(fact.Scope)]
		if fact.SrcIP == asset || fact.DstIP == asset || fact.MAC == asset || links[fact.SrcIP] || links[fact.DstIP] || links[fact.MAC] {
			ids = append(ids, id)
		}
	}
	sort.Slice(ids, func(i, j int) bool {
		a, b := state.Labels[ids[i]].Name != "", state.Labels[ids[j]].Name != ""
		if a != b {
			return a
		}
		return ids[i] < ids[j]
	})
	result.TotalRecords = len(ids)
	bytes := 0
	for _, id := range ids {
		row := AssetRecord{ID: id, Observation: state.Observed[id], Direction: "unknown"}
		if label, ok := state.Labels[id]; ok {
			row.Label = &label
		}
		fact := row.Observation.Fact
		localSource, localTarget, known := false, false, false
		src, _ := netip.ParseAddr(fact.SrcIP)
		dst, _ := netip.ParseAddr(fact.DstIP)
		for _, prefix := range prefixes[scopeKey(fact.Scope)] {
			cidr, err := netip.ParsePrefix(prefix.Value)
			if err != nil {
				continue
			}
			known = known || cidr.Addr().BitLen() == src.BitLen() || cidr.Addr().BitLen() == dst.BitLen()
			localSource = localSource || cidr.Contains(src)
			localTarget = localTarget || cidr.Contains(dst)
			if len(row.Prefixes) < 8 {
				row.Prefixes = append(row.Prefixes, prefix.Value+" ("+prefix.Provenance+")")
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
		if len(result.Records) == 64 || bytes+len(encoded) > 240<<10 {
			result.Truncated = true
			break
		}
		bytes += len(encoded)
		result.Records = append(result.Records, row)
	}
	return result, nil
}
