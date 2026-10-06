package behavior

import (
	"crypto/sha256"
	"encoding/hex"
	"net/netip"
	"sort"
)

type TopologyNode struct {
	ID         string `json:"id"`
	Kind       string `json:"kind"`
	Name       string `json:"name"`
	Address    string `json:"address"`
	Scope      Scope  `json:"scope"`
	Provenance string `json:"provenance,omitempty"`
	FactID     string `json:"factId,omitempty"`
}

type TopologyLink struct {
	Source string `json:"source"`
	Target string `json:"target"`
	Kind   string `json:"kind"`
	FactID string `json:"factId,omitempty"`
}

type Topology struct {
	Nodes      []TopologyNode `json:"nodes"`
	Links      []TopologyLink `json:"links"`
	TotalNodes int            `json:"totalNodes"`
	TotalLinks int            `json:"totalLinks"`
	Truncated  bool           `json:"truncated"`
}

func topologyID(scope Scope, kind, address string) string {
	hash := sha256.Sum256([]byte(scopeKey(scope) + "|" + kind + "|" + address))
	return hex.EncodeToString(hash[:])
}

// BuildTopology keeps routed IP hosts separate from directly observed MAC devices.
func BuildTopology(snapshot Snapshot, maxNodes int, scopeFilter string) Topology {
	if maxNodes < 1 || maxNodes > 200 {
		maxNodes = 100
	}
	nodes := make(map[string]TopologyNode)
	links := make(map[string]TopologyLink)
	addNode := func(fact Fact, kind, address, id string) string {
		key := topologyID(fact.Scope, kind, address)
		name := address
		if label, ok := snapshot.Labels[id]; ok {
			name = label.Name
		}
		node, exists := nodes[key]
		if !exists || node.Name == node.Address {
			nodes[key] = TopologyNode{ID: key, Kind: kind, Name: name, Address: address, Scope: fact.Scope, Provenance: fact.Provenance, FactID: id}
		}
		return key
	}
	addLink := func(source, target, kind, id string) {
		links[source+"|"+target+"|"+kind] = TopologyLink{Source: source, Target: target, Kind: kind, FactID: id}
	}
	ids := make([]string, 0, len(snapshot.Observed))
	for id := range snapshot.Observed {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		fact := snapshot.Observed[id].Fact
		if _, corrected := snapshot.Corrections[id]; corrected {
			continue
		}
		if scopeFilter != "" && scopeKey(fact.Scope) != scopeFilter {
			continue
		}
		switch fact.Kind {
		case "device":
			addNode(fact, "device", fact.MAC, id)
		case "binding":
			host := addNode(fact, "host", fact.SrcIP, id)
			device := addNode(fact, "device", fact.MAC, id)
			addLink(host, device, "observed binding", id)
		case "prefix":
			addNode(fact, "subnet", fact.Value, id)
		case "edge", "service", "resolver":
			source := addNode(fact, "host", fact.SrcIP, id)
			target := addNode(fact, "host", fact.DstIP, id)
			addLink(source, target, "observed communication", id)
		}
	}
	result := Topology{TotalNodes: len(nodes), TotalLinks: len(links), Nodes: []TopologyNode{}, Links: []TopologyLink{}}
	keys := make([]string, 0, len(nodes))
	for key := range nodes {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	if len(keys) > maxNodes {
		keys = keys[:maxNodes]
		result.Truncated = true
	}
	selected := make(map[string]bool, len(keys))
	for _, key := range keys {
		result.Nodes = append(result.Nodes, nodes[key])
		selected[key] = true
	}
	for _, host := range result.Nodes {
		if host.Kind != "host" {
			continue
		}
		ip, err := netip.ParseAddr(host.Address)
		if err != nil {
			continue
		}
		for _, subnet := range result.Nodes {
			if subnet.Kind != "subnet" || !sameScope(subnet.Scope, host.Scope) {
				continue
			}
			if prefix, err := netip.ParsePrefix(subnet.Address); err == nil && prefix.Contains(ip) {
				addLink(host.ID, subnet.ID, "prefix membership", subnet.FactID)
			}
		}
	}
	result.TotalLinks = len(links)
	keys = keys[:0]
	for key, link := range links {
		if selected[link.Source] && selected[link.Target] {
			keys = append(keys, key)
		}
	}
	sort.Strings(keys)
	if len(keys) > 1000 {
		keys = keys[:1000]
		result.Truncated = true
	}
	for _, key := range keys {
		result.Links = append(result.Links, links[key])
	}
	return result
}
