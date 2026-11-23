package rules

import (
	"container/list"
	"sort"
	"time"

	"github.com/dreadl0ck/netcap/types"
)

// Unscoped grouped thresholds keep the newest groups within fixed bounds.
// Evicting a group can only miss an alert; it never fails evaluation.
const (
	maxGroupedThresholdGroups  = 10_000
	maxGroupedThresholdMatches = 100_000
)

type groupedCount struct {
	key     string
	matches []int64
	elem    *list.Element
}

// groupedThresholds counts group_by threshold rules evaluated without a
// capture scope, such as embedded rules replayed over finished audits.
type groupedThresholds struct {
	groups    map[string]*groupedCount
	lru       *list.List // front is least recently matched
	entries   int
	evictions uint64
}

func (g *groupedThresholds) evictOldest() {
	front := g.lru.Front()
	if front == nil {
		return
	}
	count := front.Value.(*groupedCount)
	g.lru.Remove(front)
	delete(g.groups, count.key)
	g.entries -= len(count.matches)
	g.evictions++
}

// groupedThreshold counts a match for the record's group and reports whether
// the rule's threshold was reached within its window. Records with an empty
// group field are not counted.
func (e *Engine) groupedThreshold(rule *Rule, record types.AuditRecord) bool {
	group, ok := sequenceKey(record, rule.GroupBy)
	if !ok || len(group) > 4096 {
		return false
	}
	now := e.recordEvalTime(record)
	window := int64(rule.ThresholdWindow) * int64(time.Second)
	if window <= 0 {
		window = int64(time.Minute)
	}
	key := scopedKey("", rule.Name, group)

	e.mu.Lock()
	defer e.mu.Unlock()
	g := e.grouped
	if g == nil {
		g = &groupedThresholds{groups: make(map[string]*groupedCount), lru: list.New()}
		e.grouped = g
	}
	count := g.groups[key]
	if count == nil {
		for len(g.groups) >= maxGroupedThresholdGroups {
			g.evictOldest()
		}
		count = &groupedCount{key: key}
		count.elem = g.lru.PushBack(count)
		g.groups[key] = count
	} else {
		g.lru.MoveToBack(count.elem)
	}

	// Drop matches after now (out-of-order input) and outside the window.
	matches := count.matches
	before := len(matches)
	if n := len(matches); n > 0 && matches[n-1] > now {
		matches = matches[:sort.Search(n, func(i int) bool { return matches[i] > now })]
	}
	if len(matches) > 0 && uint64(now)-uint64(matches[0]) > uint64(window) {
		first := sort.Search(len(matches), func(i int) bool { return uint64(now)-uint64(matches[i]) <= uint64(window) })
		matches = matches[:copy(matches, matches[first:])]
	}
	count.matches = append(matches, now)
	g.entries += len(count.matches) - before

	if len(count.matches) >= rule.Threshold {
		g.lru.Remove(count.elem)
		delete(g.groups, key)
		g.entries -= len(count.matches)
		return true
	}
	for g.entries > maxGroupedThresholdMatches && g.lru.Len() > 1 {
		g.evictOldest()
	}
	return false
}

func groupedLen(g *groupedThresholds) int {
	if g == nil {
		return 0
	}
	return len(g.groups)
}

func groupedEvictions(g *groupedThresholds) uint64 {
	if g == nil {
		return 0
	}
	return g.evictions
}

// distinctEvictions sums source evictions across distinct trackers. Callers
// hold e.mu.
func (e *Engine) distinctEvictions() uint64 {
	var total uint64
	for _, tracker := range e.distinctTrackers {
		tracker.mu.Lock()
		total += tracker.evictions
		tracker.mu.Unlock()
	}
	return total
}
