package rules

import (
	"container/list"
	"time"

	"github.com/dreadl0ck/netcap/types"
)

// maxDedupeKeys bounds each rule's dedupe_by state; evicting a key only lets
// that key alert again.
const maxDedupeKeys = 100_000

type dedupeState struct {
	seen map[string]*list.Element
	lru  *list.List // front is least recently alerted
}

type dedupeEntry struct {
	key string
	at  int64
}

// ruleDuplicate reports whether rule already alerted for this record's
// dedupe_by key within its window. Records missing a key field are not
// deduplicated.
func (e *Engine) ruleDuplicate(rule *Rule, record types.AuditRecord) bool {
	key, ok := sequenceKey(record, rule.DedupeBy)
	if !ok || len(key) > 4096 {
		return false
	}
	now := e.recordEvalTime(record)
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.dedupe == nil {
		e.dedupe = make(map[string]*dedupeState)
	}
	state := e.dedupe[rule.Name]
	if state == nil {
		state = &dedupeState{seen: make(map[string]*list.Element), lru: list.New()}
		e.dedupe[rule.Name] = state
	}
	if elem := state.seen[key]; elem != nil {
		entry := elem.Value.(*dedupeEntry)
		window := int64(rule.DedupeWindow) * int64(time.Second)
		if window == 0 || now >= entry.at && uint64(now)-uint64(entry.at) < uint64(window) || now < entry.at {
			return true
		}
		entry.at = now
		state.lru.MoveToBack(elem)
		return false
	}
	for len(state.seen) >= maxDedupeKeys {
		front := state.lru.Front()
		delete(state.seen, front.Value.(*dedupeEntry).key)
		state.lru.Remove(front)
	}
	state.seen[key] = state.lru.PushBack(&dedupeEntry{key: key, at: now})
	return false
}
