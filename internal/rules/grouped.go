package rules

import (
	"container/list"
	"slices"
	"sort"
	"time"

	"github.com/dreadl0ck/netcap/types"
)

// Unscoped grouped thresholds keep the newest groups of each rule within fixed
// bounds, so one noisy rule cannot evict another rule's groups. Evicting a
// group can only miss an alert; it never fails evaluation.
const (
	maxGroupedThresholdGroups  = 10_000
	maxGroupedThresholdMatches = 100_000
	// Above this threshold a group counts matches in time buckets instead of
	// keeping one timestamp per match; the window edge is then exact to one
	// bucket, window/groupedBuckets.
	exactGroupedThreshold = 256
	groupedBuckets        = 64
)

type groupedBucket struct {
	start int64
	n     int
}

type groupedCount struct {
	key     string
	matches []int64 // sorted; exact counting
	buckets []groupedBucket
	total   int // matches held in buckets
	elem    *list.Element
}

func (c *groupedCount) entries() int { return len(c.matches) + len(c.buckets) }

// groupedThresholds holds one rule's group_by counts evaluated without a
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
	g.drop(front.Value.(*groupedCount))
	g.evictions++
}

func (g *groupedThresholds) drop(count *groupedCount) {
	g.lru.Remove(count.elem)
	delete(g.groups, count.key)
	g.entries -= count.entries()
}

// groupedThreshold counts a match for the record's group and reports whether
// the rule's threshold was reached within its window. Records with an empty
// group field are not counted.
func (e *Engine) groupedThreshold(rule *Rule, record types.AuditRecord) bool {
	group, ok := groupKey(record, rule)
	if !ok || len(group) > 4096 {
		return false
	}
	now := e.recordEvalTime(record)
	window := int64(rule.ThresholdWindow) * int64(time.Second)
	if window <= 0 {
		window = int64(time.Minute)
	}

	e.mu.Lock()
	defer e.mu.Unlock()
	if e.grouped == nil {
		e.grouped = make(map[string]*groupedThresholds)
	}
	g := e.grouped[rule.Name]
	if g == nil {
		g = &groupedThresholds{groups: make(map[string]*groupedCount), lru: list.New()}
		e.grouped[rule.Name] = g
	}
	count := g.groups[group]
	if count == nil {
		for len(g.groups) >= maxGroupedThresholdGroups {
			g.evictOldest()
		}
		count = &groupedCount{key: group}
		count.elem = g.lru.PushBack(count)
		g.groups[group] = count
	} else {
		g.lru.MoveToBack(count.elem)
	}

	before := count.entries()
	var reached bool
	if rule.Threshold > exactGroupedThreshold {
		reached = count.addBucketed(now, window, rule.Threshold)
	} else {
		reached = count.addExact(now, window, rule.Threshold)
	}
	g.entries += count.entries() - before
	if reached {
		g.drop(count)
		return true
	}
	for g.entries > maxGroupedThresholdMatches && g.lru.Len() > 1 {
		g.evictOldest()
	}
	return false
}

// The window ends at the newest match because capture workers deliver
// records out of timestamp order.
func (c *groupedCount) addExact(now, window int64, threshold int) bool {
	at := sort.Search(len(c.matches), func(i int) bool { return c.matches[i] > now })
	c.matches = slices.Insert(c.matches, at, now)
	latest := c.matches[len(c.matches)-1]
	first := sort.Search(len(c.matches), func(i int) bool { return uint64(latest)-uint64(c.matches[i]) <= uint64(window) })
	c.matches = c.matches[first:]
	return len(c.matches) >= threshold
}

func (c *groupedCount) addBucketed(now, window int64, threshold int) bool {
	width := max(window/groupedBuckets, 1)
	start := now - now%width
	if now < 0 && now%width != 0 {
		start -= width
	}
	at := sort.Search(len(c.buckets), func(i int) bool { return c.buckets[i].start >= start })
	if at < len(c.buckets) && c.buckets[at].start == start {
		c.buckets[at].n++
	} else {
		c.buckets = slices.Insert(c.buckets, at, groupedBucket{start: start, n: 1})
	}
	c.total++
	latest := c.buckets[len(c.buckets)-1].start
	first := 0
	for first < len(c.buckets) && uint64(latest)-uint64(c.buckets[first].start) > uint64(window) {
		c.total -= c.buckets[first].n
		first++
	}
	c.buckets = c.buckets[first:]
	return c.total >= threshold
}

func groupKey(record types.AuditRecord, rule *Rule) (string, bool) {
	key, ok := sequenceKey(record, rule.GroupBy)
	if ok && rule.FoldCase {
		key = foldASCII(key)
	}
	return key, ok
}

// foldASCII lowercases A-Z only. DNS names compare case-insensitively in
// ASCII (RFC 4343), and the length prefixes in the key stay valid.
func foldASCII(s string) string {
	for i := 0; i < len(s); i++ {
		if 'A' <= s[i] && s[i] <= 'Z' {
			b := []byte(s)
			for j := i; j < len(b); j++ {
				if 'A' <= b[j] && b[j] <= 'Z' {
					b[j] += 'a' - 'A'
				}
			}
			return string(b)
		}
	}
	return s
}

func groupedLen(groups map[string]*groupedThresholds) int {
	total := 0
	for _, g := range groups {
		total += len(g.groups)
	}
	return total
}

func groupedEvictions(groups map[string]*groupedThresholds) uint64 {
	var total uint64
	for _, g := range groups {
		total += g.evictions
	}
	return total
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
