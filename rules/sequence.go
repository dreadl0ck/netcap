package rules

import (
	"fmt"
	"reflect"
	"strconv"
	"strings"
	"sync"

	"github.com/dreadl0ck/netcap/internal/filter"
	netio "github.com/dreadl0ck/netcap/io"
	"github.com/dreadl0ck/netcap/types"
)

// validateGroupFields rejects group keys the engine could never build, which
// would otherwise disable the rule with no error and no alert.
func validateGroupFields(fields []string, recordType types.Type) error {
	record := netio.InitRecord(recordType)
	if record == nil {
		return fmt.Errorf("unsupported record type: %s", recordType.String())
	}
	value := reflect.ValueOf(record)
	if value.Kind() == reflect.Pointer {
		value = value.Elem()
	}
	for _, name := range fields {
		field := value.FieldByName(name)
		if !field.IsValid() {
			return fmt.Errorf("sequence group_by field %q does not exist on %s", name, recordType.String())
		}
		switch field.Kind() {
		case reflect.String,
			reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
			reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		default:
			return fmt.Errorf("sequence group_by field %q is a %s, which cannot form a group key", name, field.Kind())
		}
	}
	return nil
}

// sequenceTracker remembers when each group last produced a record matching a
// rule's After expression. seen[groupKey] = lastSeenNanos.
type sequenceTracker struct {
	seen      map[string]int64
	evalCount uint64
	mu        sync.Mutex
}

// sequenceSweepInterval controls how often expired groups are reclaimed.
const sequenceSweepInterval = 1024

// maxSequenceGroups bounds memory when a rule groups on a high-cardinality
// field. Once reached, expired groups are reclaimed and the tracker is cleared
// if it is still over the cap.
const maxSequenceGroups = 100000

// checkSequence reports whether an earlier record satisfying rule.Sequence.After
// was observed for this record's group within the window, and records the
// current record when it matches After.
//
// The lookup happens before the observation is stored, so a single record can
// never satisfy its own precondition.
func (e *Engine) checkSequence(rule *Rule, record types.AuditRecord) (bool, error) {
	seq := rule.Sequence

	if seq.compiledAfter == nil {
		// An uncompiled precondition would otherwise disable the rule silently.
		return false, fmt.Errorf("sequence for rule %s is not compiled", rule.Name)
	}

	key, ok := sequenceKey(record, seq.GroupBy)
	if !ok {
		// A record missing any group field cannot be related to another.
		return false, nil
	}

	isAfter, err := filter.EvaluateExpression(seq.compiledAfter, record)
	if err != nil {
		return false, fmt.Errorf("failed to evaluate sequence for rule %s: %w", rule.Name, err)
	}

	e.mu.RLock()
	tracker, exists := e.sequenceTrackers[rule.Name]
	e.mu.RUnlock()
	if !exists {
		// Only the first record of a rule takes the exclusive lock; the gate
		// runs for every record of the type, matching or not.
		e.mu.Lock()
		if tracker, exists = e.sequenceTrackers[rule.Name]; !exists {
			tracker = &sequenceTracker{seen: make(map[string]int64)}
			e.sequenceTrackers[rule.Name] = tracker
		}
		e.mu.Unlock()
	}

	now := recordEvalTime(record)
	windowNanos := seq.window().Nanoseconds()

	tracker.mu.Lock()
	defer tracker.mu.Unlock()

	seenAt, found := tracker.seen[key]
	satisfied := found && now >= seenAt && now-seenAt <= windowNanos
	if found && now-seenAt > windowNanos {
		// Only drop genuinely expired observations. A record arriving out of
		// order is older than the stored one and must not evict it, or a later
		// in-order pair would be lost.
		delete(tracker.seen, key)
	}

	if isAfter && now >= tracker.seen[key] {
		tracker.seen[key] = now
		tracker.evalCount++
		if tracker.evalCount%sequenceSweepInterval == 0 || len(tracker.seen) > maxSequenceGroups {
			tracker.sweep(now, windowNanos)
		}
	}

	return satisfied, nil
}

// sweep removes groups whose observation has aged out of the window. When the
// tracker is still over the cap afterwards it is cleared, which costs a missed
// correlation rather than unbounded growth.
func (t *sequenceTracker) sweep(now, windowNanos int64) {
	for key, ts := range t.seen {
		if now-ts > windowNanos {
			delete(t.seen, key)
		}
	}
	if len(t.seen) > maxSequenceGroups {
		clear(t.seen)
	}
}

// sequenceKey builds the group key, reporting false if any field is missing or
// has an unsupported kind. Values are length-prefixed so that group keys cannot
// collide even when a string field contains the separator byte.
func sequenceKey(record types.AuditRecord, fields []string) (string, bool) {
	var b strings.Builder
	for _, field := range fields {
		value := extractStringField(record, field)
		if value == "" {
			return "", false
		}
		b.WriteString(strconv.Itoa(len(value)))
		b.WriteByte(':')
		b.WriteString(value)
	}
	return b.String(), true
}
