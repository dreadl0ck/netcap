package policy

import (
	"errors"
	"time"
)

const (
	// Sliding event windows retain the nearest Count timestamps; distinct windows
	// retain every live value up to MaxDistinct and reject overflow without eviction.
	MaxMatches      = 10000
	MaxDistinct     = 256
	MaxStateEntries = 131072
	MaxStateBytes   = 64 << 20
	// Conservative charges include container overhead. Staged copies are charged
	// alongside live state; fixed counters and sequences need no entry storage.
	stateGroupBytes = 512
	stateEntryBytes = 128
)

var ErrStateClock = errors.New("policy: state clock moved backwards")

type windowState struct {
	stamps   []time.Time
	head     int
	distinct map[[32]byte]time.Time
	window   time.Duration
	sliding  bool
}

// StateStats contains counts only, never grouping values, hashes or timestamps.
type StateStats struct {
	Groups         int `json:"groups"`
	Entries        int `json:"entries"`
	AccountedBytes int `json:"accounted_bytes"`
}

func counterEntries(v counter) int {
	if v.history == nil {
		return 0
	}
	return len(v.history.stamps) + len(v.history.distinct)
}

func (c *Compiled) stateStats() StateStats {
	s := StateStats{Groups: len(c.groups)}
	for _, v := range c.groups {
		s.Entries += counterEntries(v)
	}
	s.AccountedBytes = s.Groups*stateGroupBytes + s.Entries*stateEntryBytes
	return s
}

func (c *Compiled) StateStats() StateStats {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.stateStats()
}

// Maintain expires idle state without requiring matching traffic. The host may
// call it periodically; Compiled starts no goroutines. Sliding lower boundaries
// are exclusive. Fixed distinct sets expire together at the original deadline.
func (c *Compiled) Maintain() (StateStats, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now()
	if now.Before(c.lastNow) {
		return c.stateStats(), ErrStateClock
	}
	c.pruneExpired(now)
	for key, v := range c.groups {
		h := v.history
		if h == nil || !h.sliding {
			continue
		}
		cutoff := now.Add(-h.window)
		if h.distinct != nil {
			keep := 0
			for _, stamp := range h.distinct {
				if stamp.After(cutoff) {
					keep++
				}
			}
			if keep != len(h.distinct) {
				compact := make(map[[32]byte]time.Time, keep)
				for value, stamp := range h.distinct {
					if stamp.After(cutoff) {
						compact[value] = stamp
					}
				}
				h.distinct = compact
				v.count = keep
			}
		} else {
			pruneRing(&v, cutoff)
		}
		c.groups[key] = v
	}
	c.lastNow = now
	return c.stateStats(), nil
}

func (c *Compiled) pruneExpired(now time.Time) {
	for key, v := range c.groups {
		if !now.Before(v.expires) {
			delete(c.groups, key)
		}
	}
}

type stateBudget struct {
	live                      StateStats
	stagedBytes, finalEntries int
}

func (b *stateBudget) reserve(old counter, entries int) error {
	final := b.finalEntries + entries - counterEntries(old)
	bytes := stateGroupBytes + entries*stateEntryBytes
	if final > MaxStateEntries || b.live.AccountedBytes+b.stagedBytes+bytes > MaxStateBytes {
		return ErrStateCapacity
	}
	b.finalEntries = final
	b.stagedBytes += bytes
	return nil
}

func thresholdWork(t *Threshold) uint64 {
	if t == nil {
		return 0
	}
	cost := uint64(len(t.GroupByFields) + 2)
	if t.Count > 1 {
		if t.Distinct != "" {
			cost += 4 * MaxDistinct
		} else if t.Mode == "sliding" {
			cost += uint64(2 * t.Count)
		}
	}
	return cost
}

func (c *Compiled) advanceThreshold(r compiledRule, e Event, now time.Time, updates map[[32]byte]counter, budget *stateBudget) (bool, error) {
	t := r.rule.Threshold
	var value [32]byte
	if t.Distinct != "" {
		var err error
		value, err = stateKey("distinct", t.Distinct, nil, e)
		if err != nil {
			return false, err
		}
	}
	key, token, err := stateKeyParts("threshold:"+r.rule.ID, t.GroupBy, t.GroupByFields, e)
	if err != nil {
		return false, err
	}
	if t.Count == 1 {
		return true, nil
	}
	old := c.groups[key]
	v := old
	if !now.Before(v.expires) {
		// Expired storage remains live until commit, but its entries are already
		// subtracted from the transaction's final-capacity accounting.
		old = counter{}
		v = counter{expires: now.Add(r.window)}
	}
	switch {
	case t.Distinct != "":
		v, err = distinctCounter(v, value, now, r.window, t.Mode == "sliding", budget, old)
	case t.Mode == "sliding":
		if err = budget.reserve(old, t.Count); err != nil {
			return false, err
		}
		h := &windowState{stamps: make([]time.Time, t.Count), window: r.window, sliding: true}
		if v.history != nil {
			copy(h.stamps, v.history.stamps)
			h.head = v.history.head
		}
		v.history = h
		pruneRing(&v, now.Add(-r.window))
		if v.count == t.Count {
			h.stamps[h.head] = time.Time{}
			h.head = (h.head + 1) % t.Count
			v.count--
		}
		h.stamps[(h.head+v.count)%t.Count] = now
		v.count++
		v.expires = now.Add(r.window)
	default:
		if v.count < t.Count {
			v.count++
		}
	}
	if err != nil {
		return false, err
	}
	v.ruleID, v.kind, v.token = r.rule.ID, stateThreshold, token
	updates[key] = v
	return v.count >= t.Count, nil
}

func pruneRing(v *counter, cutoff time.Time) {
	h := v.history
	for v.count > 0 && !h.stamps[h.head].After(cutoff) {
		h.stamps[h.head] = time.Time{}
		h.head = (h.head + 1) % len(h.stamps)
		v.count--
	}
}

func distinctCounter(v counter, value [32]byte, now time.Time, window time.Duration, sliding bool, budget *stateBudget, old counter) (counter, error) {
	cutoff := now.Add(-window)
	var previous map[[32]byte]time.Time
	if v.history != nil {
		previous = v.history.distinct
	}
	entries := 1
	for key, stamp := range previous {
		if key != value && (!sliding || stamp.After(cutoff)) {
			entries++
		}
	}
	if entries > MaxDistinct {
		return counter{}, ErrStateCapacity
	}
	if err := budget.reserve(old, entries); err != nil {
		return counter{}, err
	}
	values := make(map[[32]byte]time.Time, entries)
	for key, stamp := range previous {
		if !sliding || stamp.After(cutoff) {
			values[key] = stamp
		}
	}
	values[value] = now
	v.history = &windowState{distinct: values, window: window, sliding: sliding}
	v.count = len(values)
	if sliding {
		v.expires = now.Add(window)
	}
	return v, nil
}
