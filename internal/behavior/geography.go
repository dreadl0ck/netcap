package behavior

import "strings"

func (e *Engine) checkGeography(ns int64, id string, fact Fact) error {
	if e.approvedSource(fact.SrcIP) {
		return nil
	}
	if _, suppressed := e.state.Suppressed[id]; suppressed {
		return nil
	}
	parts := strings.Split(fact.Value, "|")
	if len(parts) != 2 {
		return nil
	}
	for _, country := range e.state.Policy.DeniedCountries {
		if country == parts[0] {
			return e.emitCorrelation(ns, "policy.geographic-country", id, fact, "destination country outside configured deny policy; location is context, not proof of maliciousness", 1, nil, "")
		}
	}
	for _, asn := range e.state.Policy.DeniedASNs {
		if asn == parts[1] {
			return e.emitCorrelation(ns, "policy.geographic-asn", id, fact, "destination ASN outside configured deny policy", 1, nil, "")
		}
	}
	return nil
}
