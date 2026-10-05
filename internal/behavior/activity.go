package behavior

import (
	"container/heap"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/netip"
	"sort"
	"strconv"
)

func validatePolicy(policy Policy) error {
	if policy.RateWindows < 2 || policy.RateWindows > 1000000 || policy.RateMultiplier < 1 || policy.RateMultiplier > 100 || math.IsNaN(policy.RateMultiplier) {
		return errors.New("invalid rate policy")
	}
	if len(policy.DeniedCountries) > 256 || len(policy.DeniedASNs) > 256 {
		return errors.New("geographic policy exceeds limits")
	}
	for _, country := range policy.DeniedCountries {
		if len(country) != 2 || country[0] < 'A' || country[0] > 'Z' || country[1] < 'A' || country[1] > 'Z' {
			return errors.New("country policy requires uppercase ISO codes")
		}
	}
	for _, asn := range policy.DeniedASNs {
		if value, err := strconv.ParseUint(asn, 10, 32); err != nil || value == 0 {
			return errors.New("ASN policy requires positive decimal identifiers")
		}
	}
	if policy.WindowNS < 1e9 || policy.WindowNS > 24*3600*1e9 || policy.Fanout < 2 || policy.Fanout > 10000 || policy.RDPAttempts < 2 || policy.RDPAttempts > 10000 || len(policy.ApprovedSources) > 256 {
		return errors.New("invalid behavioral detector policy")
	}
	for _, source := range policy.ApprovedSources {
		if _, err := netip.ParsePrefix(source); err != nil {
			if _, err := netip.ParseAddr(source); err != nil {
				return fmt.Errorf("invalid approved source %q", source)
			}
		}
	}
	return nil
}

func activityKey(fact Fact) string {
	data, _ := json.Marshal(fact)
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:])
}

type expiration struct {
	key string
	at  int64
}
type activityIndex []expiration

func (h activityIndex) Len() int { return len(h) }
func (h activityIndex) Less(i, j int) bool {
	return h[i].at < h[j].at || (h[i].at == h[j].at && h[i].key < h[j].key)
}
func (h activityIndex) Swap(i, j int)   { h[i], h[j] = h[j], h[i] }
func (h *activityIndex) Push(value any) { *h = append(*h, value.(expiration)) }
func (h *activityIndex) Pop() any {
	old := *h
	value := old[len(old)-1]
	*h = old[:len(old)-1]
	return value
}
func newActivityIndex(events map[string]Activity) *activityIndex {
	h := &activityIndex{}
	for key, event := range events {
		*h = append(*h, expiration{key: key, at: event.At})
	}
	heap.Init(h)
	return h
}

func (e *Engine) expireActivity(ns int64) {
	cutoff := ns - e.state.Policy.WindowNS
	for e.activity.Len() > 0 && (*e.activity)[0].at < cutoff {
		event := heap.Pop(e.activity).(expiration)
		fact := e.state.Activity[event.key].Fact
		delete(e.bySource[sourceKey(fact)], event.key)
		if len(e.bySource[sourceKey(fact)]) == 0 {
			delete(e.bySource, sourceKey(fact))
		}
		delete(e.incoming[incomingKey(fact)], event.key)
		if len(e.incoming[incomingKey(fact)]) == 0 {
			delete(e.incoming, incomingKey(fact))
		}
		delete(e.state.Activity, event.key)
	}
}

func (e *Engine) isInternal(scope Scope, ip string) bool {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return false
	}
	key := scopeKey(scope)
	if e.localIPs[key][addr] {
		return true
	}
	for _, prefix := range e.networks[key] {
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}

func (e *Engine) approvedSource(ip string) bool {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return false
	}
	for _, value := range e.state.Policy.ApprovedSources {
		if prefix, err := netip.ParsePrefix(value); err == nil && prefix.Contains(addr) {
			return true
		}
		if allowed, err := netip.ParseAddr(value); err == nil && allowed == addr {
			return true
		}
	}
	return false
}

func (e *Engine) observeActivity(ns int64, id string, fact Fact) error {
	if ns < e.state.Watermark-e.state.Policy.WindowNS {
		return nil
	}
	key := activityKey(fact)
	if _, exists := e.state.Activity[key]; exists {
		return nil
	}
	if len(e.state.Activity) >= e.config.MaxFacts {
		e.state.WindowOverflow++
		return nil
	}
	e.state.Activity[key] = Activity{Fact: fact, At: ns}
	e.indexActivity(key, e.state.Activity[key])
	heap.Push(e.activity, expiration{key: key, at: ns})
	if e.state.Mode != Monitoring || e.approvedSource(fact.SrcIP) || !e.isInternal(fact.Scope, fact.SrcIP) || !e.isInternal(fact.Scope, fact.DstIP) {
		return nil
	}
	if _, suppressed := e.state.Suppressed[id]; suppressed {
		return nil
	}
	var related []Fact
	destinations := make(map[string]bool)
	attempts := 0
	var pivots []Fact
	for _, event := range e.bySource[sourceKey(fact)] {
		prior := event.Fact
		if !sameScope(prior.Scope, fact.Scope) || event.At > ns {
			continue
		}
		if prior.SrcIP == fact.SrcIP && prior.Port == fact.Port && prior.Protocol == fact.Protocol && e.isInternal(prior.Scope, prior.DstIP) {
			attempts++
			destinations[prior.DstIP] = true
			related = append(related, prior)
		}
	}
	for _, event := range e.incoming[scopeKey(fact.Scope)+"|"+fact.SrcIP] {
		prior := event.Fact
		if prior.SrcIP != fact.DstIP && prior.SrcIP != fact.SrcIP && e.isInternal(prior.Scope, prior.SrcIP) && event.At < ns && (prior.Port == 22 || prior.Port == 3389 || prior.Port == 445) {
			pivots = append(pivots, prior)
		}
	}
	sort.Slice(related, func(i, j int) bool { return activityKey(related[i]) < activityKey(related[j]) })
	sort.Slice(pivots, func(i, j int) bool { return activityKey(pivots[i]) < activityKey(pivots[j]) })
	if len(related) > 16 {
		related = related[:16]
	}
	if fact.Port == 445 && len(destinations) >= e.state.Policy.Fanout {
		if err := e.emitCorrelation(ns, "lateral.smb-fanout", id, fact, "internal SMB fan-out below configured threshold", len(destinations), related, "T1046"); err != nil {
			return err
		}
	}
	if fact.Port == 3389 && attempts >= e.state.Policy.RDPAttempts {
		if err := e.emitCorrelation(ns, "lateral.rdp-attempts", id, fact, "connection attempts below configured threshold; authentication outcome unavailable", attempts, related, "T1021.001"); err != nil {
			return err
		}
	}
	if fact.Port == 22 {
		if _, known := e.state.Approved[id]; !known {
			if err := e.emitCorrelation(ns, "lateral.new-ssh-edge", id, fact, "internal SSH relationship present in approved baseline", 1, []Fact{fact}, "T1021.004"); err != nil {
				return err
			}
		}
	}
	_, known := e.state.Approved[id]
	if !known && len(pivots) > 0 && (fact.Port == 22 || fact.Port == 3389 || fact.Port == 445) {
		return e.emitCorrelation(ns, "lateral.pivot-sequence", id, fact, "no novel A→B→C administrative connection sequence; inference, not proof of compromise", len(pivots), []Fact{pivots[0], fact}, "T1021")
	}
	return nil
}

func scopeKey(scope Scope) string { data, _ := json.Marshal(scope); return string(data) }
func sourceKey(fact Fact) string {
	return fmt.Sprintf("%s|%s|%s|%d", scopeKey(fact.Scope), fact.SrcIP, fact.Protocol, fact.Port)
}
func incomingKey(fact Fact) string { return scopeKey(fact.Scope) + "|" + fact.DstIP }

func (e *Engine) indexActivity(key string, event Activity) {
	source, incoming := sourceKey(event.Fact), incomingKey(event.Fact)
	if e.bySource[source] == nil {
		e.bySource[source] = make(map[string]Activity)
	}
	if e.incoming[incoming] == nil {
		e.incoming[incoming] = make(map[string]Activity)
	}
	e.bySource[source][key], e.incoming[incoming][key] = event, event
}

func (e *Engine) indexLocal(fact Fact) {
	key := scopeKey(fact.Scope)
	if fact.Kind == "binding" {
		if addr, err := netip.ParseAddr(fact.SrcIP); err == nil {
			if e.localIPs[key] == nil {
				e.localIPs[key] = make(map[netip.Addr]bool)
			}
			e.localIPs[key][addr] = true
		}
	}
	if fact.Kind == "prefix" {
		if prefix, err := netip.ParsePrefix(fact.Value); err == nil {
			for _, known := range e.networks[key] {
				if known == prefix {
					return
				}
			}
			e.networks[key] = append(e.networks[key], prefix)
		}
	}
}

func (e *Engine) rebuildIndexes() {
	e.bySource = make(map[string]map[string]Activity)
	e.incoming = make(map[string]map[string]Activity)
	e.localIPs = make(map[string]map[netip.Addr]bool)
	e.networks = make(map[string][]netip.Prefix)
	for key, event := range e.state.Activity {
		e.indexActivity(key, event)
	}
	for _, observation := range e.state.Observed {
		e.indexLocal(observation.Fact)
	}
	for _, prefix := range e.prefixes {
		e.indexLocal(prefix)
	}
}

func (e *Engine) emitCorrelation(ns int64, detector, id string, fact Fact, expected string, count int, related []Fact, mitre string) error {
	// Detector keys are bounded by the retained fact set, not arbitrary flow tokens.
	key := detector + ":" + id
	if previous, exists := e.recent[key]; exists && ns-previous < int64(e.config.DedupWindow) {
		return nil
	}
	evidence := Evidence{Schema: SchemaVersion, Detector: detector, FactID: id, Observed: fact, Expected: expected, Version: e.state.Version, BaselineID: e.state.BaselineID,
		Count: count, WindowNS: e.state.Policy.WindowNS, Related: related}
	if err := e.writeEvidence(ns, evidence, "medium", mitre); err != nil {
		return err
	}
	e.recent[key] = ns
	return nil
}
