package responseactions

import (
	"errors"

	"github.com/dreadl0ck/netcap/internal/enforcer"
	"github.com/dreadl0ck/netcap/internal/policy"
)

type PolicyEvaluator interface {
	Evaluate(policy.Event) (policy.Decision, error)
}

// SourceResolver is a trusted integration boundary, not policy configuration.
// It must authorize each target from ingress attribution (socket peer, validated
// proxy chain, or packet tuple). Returning event headers/Attributes is unsafe.
type SourceResolver func(policy.Event, string) (string, bool)

type Evaluator struct {
	Policy PolicyEvaluator
	Broker *Broker
	Source SourceResolver
	Flow   func(policy.Event) (enforcer.Flow, bool)
	// Replay prevents dispatch even when wrapping an enforce-mode policy.
	Replay bool
}

// RequiresBody preserves dependency discovery through the dispatch wrapper.
// Evaluators without metadata conservatively require bodies in known phases.
func (e *Evaluator) RequiresBody(phase string) bool {
	if e == nil || e.Policy == nil || (phase != "request" && phase != "response") {
		return false
	}
	if p, ok := e.Policy.(interface{ RequiresBody(string) bool }); ok {
		return p.RequiresBody(phase)
	}
	return true
}

func (e *Evaluator) Evaluate(event policy.Event) (policy.Decision, error) {
	if e.Policy == nil {
		return policy.Decision{}, errors.New("responseactions: missing evaluator")
	}
	d, err := e.Policy.Evaluate(event)
	if err != nil {
		return d, err
	}
	if d.Monitor || e.Replay {
		d.Effects = nil
		return d, nil
	}
	if len(d.Effects) > policy.MaxEffects || (len(d.Effects) > 0 && d.Verdict != "allow" && d.Verdict != "deny") {
		return d, errors.New("responseactions: invalid effect decision")
	}
	for _, intent := range d.Effects {
		if intent.Revision != d.Revision || intent.RuleID != d.RuleID {
			return d, errors.New("responseactions: effect decision mismatch")
		}
	}
	for _, intent := range d.Effects {
		if e.Broker == nil {
			return d, errors.New("responseactions: effects require broker")
		}
		var source string
		if e.Source != nil {
			if v, ok := e.Source(event, intent.Target); ok {
				source = v
			}
		}
		var flow *enforcer.Flow
		if e.Flow != nil {
			if f, ok := e.Flow(event); ok {
				flow = &f
			}
		}
		e.Broker.SubmitFlow(intent, source, flow)
	}
	return d, nil
}
