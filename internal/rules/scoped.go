package rules

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"time"

	"github.com/dreadl0ck/netcap/internal/filter"
	"github.com/dreadl0ck/netcap/internal/netio"
	"github.com/dreadl0ck/netcap/types"
)

var ErrStateCapacity = errors.New("scoped rule state capacity reached")

const maxScopedGroups = 10000
const maxScopedEntries = 100000

type scopedCount struct {
	scope        string
	last, window int64
	matches      []int64
}
type scopedJoin struct {
	scope      string
	at, window int64
	evidence   string
}

func scopedKey(scope, name, key string) string {
	b, _ := json.Marshal([3]string{scope, name, key})
	return string(b)
}

func requireScope(scope string, record types.AuditRecord) error {
	if scope == "" || len(scope) > 256 || record.Time() <= 0 {
		return errors.New("scoped rules require capture/source scope and positive capture timestamp")
	}
	return nil
}

func (e *Engine) scopedThreshold(scope string, rule *Rule, record types.AuditRecord) (bool, error) {
	if err := requireScope(scope, record); err != nil {
		return false, err
	}
	group, ok := sequenceKey(record, rule.GroupBy)
	if !ok {
		return false, nil
	}
	if len(group) > 4096 {
		return false, ErrStateCapacity
	}
	now := record.Time()
	window := int64(rule.ThresholdWindow) * int64(time.Second)
	if window == 0 {
		window = int64(time.Minute)
	}
	key := scopedKey(scope, rule.Name, group)
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.scopedCounts == nil {
		e.scopedCounts = make(map[string]*scopedCount)
	}
	for k, t := range e.scopedCounts {
		if t.scope == scope && now >= t.last && now-t.last > t.window {
			e.scopedEntries -= len(t.matches)
			delete(e.scopedCounts, k)
		}
	}
	t := e.scopedCounts[key]
	if t == nil {
		if len(e.scopedCounts)+len(e.scopedJoins) >= maxScopedGroups {
			return false, ErrStateCapacity
		}
		t = &scopedCount{scope: scope, window: window}
		e.scopedCounts[key] = t
	}
	if now < t.last {
		return false, errors.New("scoped thresholds require ordered capture time; use OrderedStream")
	}
	kept := t.matches[:0]
	for _, at := range t.matches {
		if now-at <= window {
			kept = append(kept, at)
		} else {
			e.scopedEntries--
		}
	}
	t.matches = kept
	if e.scopedEntries >= maxScopedEntries {
		return false, ErrStateCapacity
	}
	t.last = now
	t.matches = append(t.matches, now)
	e.scopedEntries++
	if len(t.matches) >= rule.Threshold {
		e.scopedEntries -= len(t.matches)
		delete(e.scopedCounts, key)
		return true, nil
	}
	return false, nil
}

func validateJoinFields(fields []string, typ types.Type, after []string, afterType types.Type) error {
	if err := validateGroupFields(after, afterType); err != nil {
		return err
	}
	a, b := reflect.ValueOf(netio.InitRecord(typ)).Elem(), reflect.ValueOf(netio.InitRecord(afterType)).Elem()
	for i, name := range fields {
		if a.FieldByName(name).Kind() != b.FieldByName(after[i]).Kind() {
			return fmt.Errorf("join key types differ at %s/%s", name, after[i])
		}
	}
	return nil
}

// Only exact configured keys join. A tuple or account name is not silently
// promoted to a session/transaction identity by the engine.
func (e *Engine) crossSequence(scope string, rule *Rule, record types.AuditRecord) (bool, []string, error) {
	seq := rule.Sequence
	afterType, _ := parseRecordType(seq.AfterType)
	targetType, _ := parseRecordType(rule.Type)
	if record.NetcapType() != afterType && record.NetcapType() != targetType {
		return false, nil, nil
	}
	if err := requireScope(scope, record); err != nil {
		return false, nil, err
	}
	fields := seq.GroupBy
	if record.NetcapType() == afterType {
		fields = seq.AfterGroupBy
	}
	group, ok := sequenceKey(record, fields)
	if !ok {
		return false, nil, nil
	}
	if len(group) > 4096 {
		return false, nil, ErrStateCapacity
	}
	key := scopedKey(scope, rule.Name, group)
	now := record.Time()
	window := seq.window().Nanoseconds()
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.scopedJoins == nil {
		e.scopedJoins = make(map[string]*scopedJoin)
	}
	// Use each rule's own window; never expire another rule using this window.
	for k, t := range e.scopedJoins {
		if t.scope == scope && now >= t.at && now-t.at > t.window {
			delete(e.scopedJoins, k)
		}
	}
	previous := e.scopedJoins[key]
	satisfied := record.NetcapType() == targetType && previous != nil && previous.at <= now && now-previous.at <= window
	var refs []string
	if satisfied {
		refs = []string{previous.evidence, recordEvidence(record)}
	}
	if record.NetcapType() == afterType {
		match, err := filter.EvaluateExpression(seq.compiledAfter, record)
		if err != nil {
			return false, nil, err
		}
		if match {
			if previous == nil && len(e.scopedCounts)+len(e.scopedJoins) >= maxScopedGroups {
				return false, nil, ErrStateCapacity
			}
			if previous == nil || now >= previous.at {
				e.scopedJoins[key] = &scopedJoin{scope: scope, at: now, window: window, evidence: recordEvidence(record)}
			}
		}
	}
	return satisfied, refs, nil
}

func recordEvidence(record types.AuditRecord) string {
	b, _ := json.Marshal(record)
	hash := sha256.Sum256(b)
	return record.NetcapType().String() + ":" + hex.EncodeToString(hash[:])
}

func joinEvidence(scope string, refs []string) string {
	b, _ := json.Marshal(map[string]any{"netcapJoin": map[string]any{"version": 1, "scope": scope, "contributors": refs}})
	return string(b)
}

func scopedProjection(record types.AuditRecord) string {
	b, _ := json.Marshal(struct {
		Timestamp   int64  `json:"Timestamp"`
		Type        string `json:"Type"`
		SrcIP       string `json:"SrcIP"`
		DstIP       string `json:"DstIP"`
		CommunityID string `json:"CommunityID,omitempty"`
	}{record.Time(), record.NetcapType().String(), record.Src(), record.Dst(), extractStringField(record, "CommunityID")})
	return string(b)
}
