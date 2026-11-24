package rules

import (
	"encoding/json"
	"sort"

	"github.com/dreadl0ck/netcap/types"
)

// maxThresholdValues bounds the distinct values an alert lists.
const maxThresholdValues = 64

// thresholdHit is what a count or cardinality rule counted when it fired.
// A rule without a threshold fires with an empty hit.
type thresholdHit struct {
	count       int
	first, last int64
	group       map[string]string
	values      []string // distinct values, oldest first
	total       int      // distinct values before the cap
}

func distinctHit(src string, values map[string]int64) *thresholdHit {
	ordered := make([]string, 0, len(values))
	for value := range values {
		ordered = append(ordered, value)
	}
	sort.Slice(ordered, func(i, j int) bool {
		if values[ordered[i]] != values[ordered[j]] {
			return values[ordered[i]] < values[ordered[j]]
		}
		return ordered[i] < ordered[j]
	})
	hit := &thresholdHit{count: len(ordered), total: len(ordered), group: map[string]string{"SrcIP": src}}
	if len(ordered) > 0 {
		hit.first, hit.last = values[ordered[0]], values[ordered[len(ordered)-1]]
	}
	hit.values = ordered[:min(len(ordered), maxThresholdValues)]
	return hit
}

func groupValues(record types.AuditRecord, rule *Rule) map[string]string {
	group := make(map[string]string, len(rule.GroupBy))
	for _, field := range rule.GroupBy {
		group[field] = extractStringField(record, field)
	}
	return group
}

// annotate records the counted window on the alert: Count, FirstSeen and
// LastSeen, the group in AggregateKey, and the distinct values as Examples.
func (h *thresholdHit) annotate(rule *Rule, alert *types.Alert) {
	if h == nil || alert == nil || h.count == 0 {
		return
	}
	alert.Count, alert.FirstSeen, alert.LastSeen = uint64(h.count), h.first, h.last
	key := map[string]any{"rule": rule.Name}
	if len(h.group) > 0 {
		key["group"] = h.group
	}
	if wire, err := json.Marshal(key); err == nil {
		alert.AggregateKey = string(wire)
	}
	alert.Examples = nil
	for _, value := range h.values {
		wire, err := json.Marshal(map[string]string{rule.DistinctField: value})
		if err == nil {
			alert.Examples = append(alert.Examples, string(wire))
		}
	}
	if h.total > len(h.values) {
		wire, _ := json.Marshal(map[string]int{"omittedDistinctValues": h.total - len(h.values)})
		alert.Examples = append(alert.Examples, string(wire))
	}
	if rule.ThresholdWindow > 0 && alert.ThresholdWindow == 0 {
		alert.ThresholdWindow = int32(rule.ThresholdWindow)
	}
}

// Boolean forms for callers that only need to know whether a rule fired.
func (e *Engine) checkThreshold(rule *Rule, record types.AuditRecord) bool {
	return e.checkThresholdHit(rule, record) != nil
}

func (e *Engine) checkDistinctThreshold(rule *Rule, record types.AuditRecord) bool {
	return e.checkDistinctThresholdHit(rule, record) != nil
}

func (e *Engine) groupedThreshold(rule *Rule, record types.AuditRecord) bool {
	return e.groupedThresholdHit(rule, record) != nil
}

func (e *Engine) scopedThreshold(scope string, rule *Rule, record types.AuditRecord) (bool, error) {
	hit, err := e.scopedThresholdHit(scope, rule, record)
	return hit != nil, err
}
