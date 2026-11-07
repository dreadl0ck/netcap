package policy

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/netip"
	"time"
)

const MaxEffects = 8
const MaxEffectTTL = 15 * time.Minute

type Effect struct {
	Kind     string `json:"kind" yaml:"kind"`
	Duration string `json:"duration" yaml:"duration"`
	Target   string `json:"target" yaml:"target"`
	Scope    string `json:"scope" yaml:"scope"`
}

// Intent is inert data. Only a trusted-source broker may dispatch it.
type Intent struct {
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
	b, _ := json.Marshal([]string{i.Revision, i.RuleID, i.Kind, i.Target, i.Source, i.Scope, i.TTL.String()})
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
		if e.Kind != "block_source" || (e.Target != "client" && e.Target != "source") || !validID.MatchString(e.Scope) || err != nil || d < time.Second || d > MaxEffectTTL || d%time.Second != 0 || seen[e] {
			return errors.New("policy: invalid or duplicate response effect (TTL must be whole seconds 1s..15m)")
		}
		seen[e] = true
	}
	return nil
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
		i.ID = IntentID(i)
		result = append(result, i)
	}
	return result, nil
}
