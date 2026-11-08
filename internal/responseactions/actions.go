package responseactions

import (
	"encoding/json"
	"net/netip"

	"github.com/dreadl0ck/netcap/internal/enforcer"
	"github.com/dreadl0ck/netcap/internal/policy"
)

func intentAction(i policy.Intent) enforcer.Action {
	if i.Kind == "block_source" {
		return enforcer.Action{}
	}
	return enforcer.Action{Kind: enforcer.ActionKind(i.Kind), Profile: i.Profile, Flow: i.Flow}
}

func actionKey(i policy.Intent) string { b, _ := json.Marshal(intentAction(i)); return string(b) }

func admittedAction(i policy.Intent, d destination, flow *enforcer.Flow) bool {
	if i.Kind == "notify" {
		return d.notification && i.Profile == "" && i.Flow == (enforcer.Flow{})
	}
	if d.notification {
		return false
	}
	for _, service := range d.protectedServices {
		if service == (enforcer.Service{Protocol: d.network.Protocol, Port: d.network.Port}) && (i.Kind == string(enforcer.BlockSource) || i.Kind == string(enforcer.DropFlow) || i.Kind == string(enforcer.RejectFlow)) {
			return false
		}
	}
	switch enforcer.ActionKind(i.Kind) {
	case enforcer.DropFlow, enforcer.RejectFlow:
		if i.Target != "source" || flow == nil || *flow != i.Flow || i.Profile != "" || d.network.Hook == "prerouting" {
			return false
		}
		a, err := netip.ParseAddr(i.Flow.Destination)
		p, _ := netip.ParsePrefix(d.network.DestinationCIDR)
		return err == nil && a.String() == i.Flow.Destination && !a.Is4In6() && a.Zone() == "" && p.Contains(a) && i.Flow.Protocol == d.network.Protocol && i.Flow.DestinationPort == d.network.Port && i.Flow.SourcePort != 0
	case enforcer.BlockSource:
		return i.Profile == "" && i.Flow == (enforcer.Flow{}) && d.network.Hook != "prerouting"
	case enforcer.Quarantine, enforcer.RateSource, enforcer.RedirectSource:
		p, ok := d.profiles[i.Profile]
		return ok && p.Kind == enforcer.ActionKind(i.Kind) && i.Flow == (enforcer.Flow{})
	default:
		return false
	}
}

// BatchStatus distinguishes admission from delivery. Effects execute independently
// in winning-rule declaration order; failures do not roll back preceding effects.
func BatchStatus(receipts []Receipt) string {
	if len(receipts) == 0 {
		return "none"
	}
	applied, failed, pending, simulated := 0, 0, 0, 0
	for _, r := range receipts {
		switch r.Status {
		case "applied", "notified":
			applied++
		case "failed", "dropped":
			failed++
		case "simulated":
			simulated++
		default:
			pending++
		}
	}
	if pending > 0 {
		return "pending"
	}
	if failed == 0 {
		if simulated == len(receipts) {
			return "simulated"
		}
		if simulated != 0 {
			return "partial-simulated"
		}
		return "applied"
	}
	if applied == 0 {
		return "failed"
	}
	return "partial-failed"
}

// Batch returns latest delivery receipts for up to MaxEffects winning-rule IDs.
// Missing/evicted IDs are unknown, never proof that every effect succeeded.
func (b *Broker) Batch(ids []string) (string, []Receipt) {
	if len(ids) > policy.MaxEffects {
		return "invalid", nil
	}
	latest := map[string]Receipt{}
	for _, r := range b.Receipts() {
		latest[r.ID] = r
	}
	result := make([]Receipt, 0, len(ids))
	for _, id := range ids {
		r, ok := latest[id]
		if !ok {
			return "unknown", nil
		}
		result = append(result, r)
	}
	return BatchStatus(result), result
}
