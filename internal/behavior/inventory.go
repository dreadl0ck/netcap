package behavior

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"time"
)

func (e *Engine) EditInventory(edit InventoryEdit) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed {
		return os.ErrClosed
	}
	if e.err != nil {
		return e.err
	}
	if edit.Version != e.state.Version {
		return errors.New("baseline version changed; refresh before editing inventory")
	}
	if edit.Reason == "" || len(edit.Reason) > 1024 || len(edit.Name) > 128 || len(edit.Role) > 128 || len(edit.Notes) > 1024 || len(e.state.Decisions) >= 1000 {
		return errors.New("invalid inventory edit or decision limit reached")
	}
	observation, ok := e.state.Observed[edit.ID]
	if !ok {
		return fmt.Errorf("unknown inventory fact %s", edit.ID)
	}
	data, err := json.Marshal(e.state)
	if err != nil {
		return err
	}
	var next Snapshot
	if err := json.Unmarshal(data, &next); err != nil {
		return err
	}
	action := "label"
	if edit.Prefix != "" {
		if observation.Fact.Kind != "prefix" {
			return errors.New("prefix correction requires a subnet fact")
		}
		fact := observation.Fact
		fact.Value, fact.Provenance = edit.Prefix, "configured"
		if err := fact.normalize(); err != nil {
			return err
		}
		id := factID(fact)
		if id != edit.ID && len(next.Observed) >= next.MaxFacts {
			return errors.New("inventory fact limit reached")
		}
		next.Corrections[edit.ID] = fact
		for original, previous := range next.Corrections {
			if factID(previous) == edit.ID {
				next.Corrections[original] = fact
			}
		}
		next.Suppressed[edit.ID] = edit.Reason
		next.Observed[id] = Observation{Fact: fact, FirstSeen: observation.FirstSeen, LastSeen: observation.LastSeen, Samples: observation.Samples}
		if _, approved := next.Approved[edit.ID]; approved {
			delete(next.Approved, edit.ID)
			next.Approved[id] = fact
		}
		action = "correct-prefix"
	} else {
		if _, exists := next.Labels[edit.ID]; !exists && edit.Name != "" && len(next.Labels) >= next.MaxFacts {
			return errors.New("asset label limit reached")
		}
		if edit.Name == "" {
			delete(next.Labels, edit.ID)
		} else {
			next.Labels[edit.ID] = AssetLabel{Fact: observation.Fact, Name: edit.Name, Role: edit.Role, Notes: edit.Notes}
		}
	}
	next.Version++
	next.BaselineID = baselineStateID(next.Approved, next.ApprovedRates)
	next.Decisions = append(next.Decisions, Decision{At: time.Now().UnixNano(), Action: action, Reason: edit.Reason, Version: next.Version, BaselineID: next.BaselineID, IDs: []string{edit.ID}})
	if err := writeSnapshot(e.config.Path, next); err != nil {
		return err
	}
	e.state = next
	e.rebuildIndexes()
	return nil
}

func bindingKey(fact Fact) string { return scopeKey(fact.Scope) + "|" + fact.SrcIP }

func (e *Engine) observeLease(ns int64, fact Fact) {
	if fact.LeaseSeconds == 0 || fact.DstIP == "" {
		return
	}
	key := bindingKey(fact)
	if previous, ok := e.state.Leases[key]; ok && previous.At > ns {
		return
	}
	if len(e.state.Leases) >= e.config.MaxFacts {
		for id, lease := range e.state.Leases {
			if lease.Expires < ns {
				delete(e.state.Leases, id)
			}
		}
		if _, exists := e.state.Leases[key]; !exists && len(e.state.Leases) >= e.config.MaxFacts {
			e.state.WindowOverflow++
			return
		}
	}
	seconds := fact.LeaseSeconds
	if seconds > 7*24*3600 {
		seconds = 7 * 24 * 3600
	}
	e.state.Leases[key] = Lease{Fact: fact, At: ns, Expires: ns + int64(seconds)*int64(time.Second)}
}

func (e *Engine) trustedLease(ns int64, fact Fact) (Lease, bool) {
	lease, ok := e.state.Leases[bindingKey(fact)]
	if !ok || lease.At > ns || lease.Expires < ns {
		return Lease{}, false
	}
	if e.trustedDHCP[scopeKey(fact.Scope)+"|"+lease.Fact.DstIP] {
		return lease, true
	}
	return Lease{}, false
}

func (e *Engine) leaseMatches(ns int64, fact Fact) bool {
	lease, ok := e.trustedLease(ns, fact)
	return ok && lease.Fact.MAC == fact.MAC
}
func (e *Engine) leaseConflict(ns int64, fact Fact) bool {
	lease, ok := e.trustedLease(ns, fact)
	return ok && fact.Provenance == "arp" && lease.Fact.MAC != fact.MAC
}
