package policy

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/netip"
	"time"

	"github.com/dreadl0ck/netcap/internal/enforcer"
)

const MaxEffects = 8
const MaxEffectTTL = 15 * time.Minute

type Effect struct {
	Profile  string `json:"profile,omitempty" yaml:"profile,omitempty"`
	Kind     string `json:"kind" yaml:"kind"`
	Duration string `json:"duration" yaml:"duration"`
	Target   string `json:"target" yaml:"target"`
	Scope    string `json:"scope" yaml:"scope"`
}

// Intent is inert data. Only a trusted-source broker may dispatch it.
type Intent struct {
	Profile   string        `json:"profile,omitempty"`
	Flow      enforcer.Flow `json:"flow,omitempty"`
	ID        string        `json:"id"`
	Kind      string        `json:"kind"`
	Target    string        `json:"target"`
	Source    string        `json:"source"`
	Scope     string        `json:"scope"`
	Revision  string        `json:"revision"`
	RuleID    string        `json:"rule_id"`
	TTL       time.Duration `json:"ttl"`
	IssuedAt  time.Time     `json:"issued_at"`
	ExpiresAt time.Time     `json:"expires_at"`
}

// IntentID excludes timestamps so repeated matches do not renew an active lease.
func IntentID(i Intent) string {
	values := []string{i.Revision, i.RuleID, i.Kind, i.Target, i.Source, i.Scope, i.TTL.String()}
	if i.Profile != "" || i.Flow != (enforcer.Flow{}) {
		flow, _ := json.Marshal(i.Flow)
		values = append(values, i.Profile, string(flow))
	}
	b, _ := json.Marshal(values)
	h := sha256.Sum256(b)
	return "ra_" + hex.EncodeToString(h[:20])
}

func validateEffects(effects []Effect, admitted bool) error {
	if len(effects) > MaxEffects {
		return errors.New("policy: too many effects")
	}
	if len(effects) > 0 && !admitted {
		return errors.New("policy: response effects require explicit admission")
	}
	seen := make(map[Effect]bool)
	for _, e := range effects {
		d, err := time.ParseDuration(e.Duration)
		if !validEffectShape(e) || (e.Target != "client" && e.Target != "source") || !validID.MatchString(e.Scope) || err != nil || d < time.Second || d > MaxEffectTTL || d%time.Second != 0 || seen[e] {
			return errors.New("policy: invalid or duplicate response effect (TTL must be whole seconds 1s..15m)")
		}
		seen[e] = true
	}
	return nil
}

func validEffectShape(e Effect) bool {
	switch enforcer.ActionKind(e.Kind) {
	case enforcer.BlockSource:
		return e.Profile == ""
	case enforcer.DropFlow, enforcer.RejectFlow:
		return e.Profile == "" && e.Target == "source"
	case enforcer.Quarantine, enforcer.RateSource, enforcer.RedirectSource:
		return validID.MatchString(e.Profile) && len(e.Profile) <= 48
	case "notify":
		return e.Profile == ""
	default:
		return false // app reject, request rates and proactive termination are not kernel effects.
	}
}

func EventFlow(e Event) (enforcer.Flow, error) {
	n := e.Network
	a, err := netip.ParseAddr(n.DstIP)
	if err != nil || a.String() != n.DstIP || a.Is4In6() || a.Zone() != "" || !a.IsGlobalUnicast() || n.SrcPort < 1 || n.SrcPort > 65535 || n.DstPort < 1 || n.DstPort > 65535 || (n.Transport != "tcp" && n.Transport != "udp") {
		return enforcer.Flow{}, errors.New("policy: flow effect requires a canonical ingress five-tuple")
	}
	return enforcer.Flow{Destination: n.DstIP, Protocol: n.Transport, SourcePort: uint16(n.SrcPort), DestinationPort: uint16(n.DstPort)}, nil
}

func makeIntents(effects []Effect, e Event, d Decision, now time.Time) ([]Intent, error) {
	var result []Intent
	for _, effect := range effects {
		source := e.ClientIP
		if effect.Target == "source" {
			source = e.Network.SrcIP
		}
		a, err := netip.ParseAddr(source)
		if err != nil || a.Zone() != "" || a.Is4In6() || !a.IsGlobalUnicast() || a.String() != source {
			return nil, errors.New("policy: effect requires a canonical unicast source")
		}
		ttl, _ := time.ParseDuration(effect.Duration)
		i := Intent{Kind: effect.Kind, Target: effect.Target, Source: source, Scope: effect.Scope, Revision: d.Revision, RuleID: d.RuleID, TTL: ttl, IssuedAt: now.UTC(), ExpiresAt: now.UTC().Add(ttl)}
		i.Profile = effect.Profile
		if effect.Kind == string(enforcer.DropFlow) || effect.Kind == string(enforcer.RejectFlow) {
			i.Flow, err = EventFlow(e)
			if err != nil {
				return nil, err
			}
		}
		i.ID = IntentID(i)
		result = append(result, i)
	}
	return result, nil
}
