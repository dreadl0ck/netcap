package evidence

import "sort"

const MaxCommunityScopes = 32768

// FlowScope is packet-derived scope within this capture's RunID namespace.
type FlowScope struct {
	Sensor         string   `json:"sensor"`
	InterfaceIndex int      `json:"interfaceIndex"`
	VLANs          []uint16 `json:"vlans"`
}

type CommunityScope struct {
	CommunityID string    `json:"communityId"`
	Scope       FlowScope `json:"scope"`
	Ambiguous   bool      `json:"ambiguous"`
}

type ScopeLedger struct {
	Schema   int              `json:"schema"`
	Complete bool             `json:"complete"`
	Overflow uint64           `json:"overflow"`
	Entries  []CommunityScope `json:"entries"`
}

// ObserveScope runs at serialized packet ingress, before worker ownership.
// A Community ID observed in multiple scopes never becomes unambiguous again.
func (c *Capture) ObserveScope(cid string, iface int, vlans []uint16) {
	if cid == "" {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	// The compatible Rust offline BPF reader loses source interface IDs.
	// Withhold qualification in both engines rather than claim equivalent scope.
	if c.manifest.Config.Kind == "file" && c.manifest.Config.BPF != "" {
		return
	}
	if c.scopes == nil {
		c.scopes = make(map[string]CommunityScope)
	}
	scope := FlowScope{Sensor: "local", InterfaceIndex: iface, VLANs: append([]uint16{}, vlans...)}
	if previous, ok := c.scopes[cid]; ok {
		if !sameScope(previous.Scope, scope) {
			previous.Ambiguous = true
			c.scopes[cid] = previous
		}
		return
	}
	if len(c.scopes) >= MaxCommunityScopes {
		c.scopeOverflow++
		return
	}
	c.scopes[cid] = CommunityScope{CommunityID: cid, Scope: scope}
}

func sameScope(a, b FlowScope) bool {
	if a.Sensor != b.Sensor || a.InterfaceIndex != b.InterfaceIndex || len(a.VLANs) != len(b.VLANs) {
		return false
	}
	for i := range a.VLANs {
		if a.VLANs[i] != b.VLANs[i] {
			return false
		}
	}
	return true
}

func (c *Capture) scopeSnapshot() ScopeLedger {
	l := ScopeLedger{Schema: 1, Complete: c.closed && c.manifest.Status != "error", Overflow: c.scopeOverflow, Entries: []CommunityScope{}}
	for _, entry := range c.scopes {
		l.Entries = append(l.Entries, entry)
	}
	sort.Slice(l.Entries, func(i, j int) bool { return l.Entries[i].CommunityID < l.Entries[j].CommunityID })
	return l
}
