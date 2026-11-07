package policy

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"math"
	"sort"
	"time"
)

const MaxSnapshotBytes = 8 << 20
const stateThreshold byte = 1
const stateSequence byte = 2
const snapshotMagic = "NCPS\x00\x01"

var ErrSnapshot = errors.New("policy: invalid state snapshot")

func validStateTime(t time.Time) bool {
	return !t.Before(time.Unix(0, 1)) && !t.After(time.Unix(0, math.MaxInt64-int64(24*time.Hour)))
}

// Fork shares immutable programs and starts with empty revision-local state.
func (c *Compiled) Fork() *Compiled {
	return &Compiled{bundle: c.bundle, revision: c.revision, rules: c.rules, groups: make(map[[32]byte]counter), now: time.Now, phaseUnits: c.phaseUnits, options: c.options, bodyPhases: c.bodyPhases, programBytes: c.programBytes}
}

// ValidateEvent checks the bounded typed environment without advancing state.
func ValidateEvent(e Event) error {
	if e.Phase == "" {
		e.Phase = "request"
	}
	return validateEvent(e)
}

// StateDeadline is the latest live group expiry, or the last evaluation watermark
// for stateless policies. It permits reclamation without forgetting a live group.
func (c *Compiled) StateDeadline() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	latest := c.lastNow
	for _, v := range c.groups {
		if v.expires.After(latest) {
			latest = v.expires
		}
	}
	return latest
}

func (c *Compiled) StateWatermark() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.lastNow }

func (c *Compiled) stateRules() map[string]compiledRule {
	rules := make(map[string]compiledRule, len(c.rules))
	for _, r := range c.rules {
		if r.rule.Enabled == nil || *r.rule.Enabled {
			rules[r.rule.ID] = r
		}
	}
	return rules
}

func writeNumber(w io.Writer, v any) { _ = binary.Write(w, binary.BigEndian, v) }

// ExportState emits a versioned, deterministic binary snapshot bound to Revision.
// Only rule labels, opaque digests and timestamps are stored, never event values.
// The checksum detects corruption; private storage, not this checksum, authorizes state.
// Snapshots are private processor state, not metrics or untrusted client input.
func (c *Compiled) ExportState(ctx context.Context) ([]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s := c.stateStats()
	if s.Groups > MaxGroups || s.Entries > MaxStateEntries || s.AccountedBytes > MaxStateBytes {
		return nil, ErrStateCapacity
	}
	if !c.lastNow.IsZero() && !validStateTime(c.lastNow) {
		return nil, ErrSnapshot
	}
	if len(c.groups) > 0 && c.lastNow.IsZero() {
		return nil, ErrSnapshot
	}
	var b bytes.Buffer
	b.WriteString(snapshotMagic)
	rev, err := hex.DecodeString(c.revision)
	if err != nil || len(rev) != 32 {
		return nil, ErrSnapshot
	}
	b.Write(rev)
	stamp := int64(0)
	if !c.lastNow.IsZero() {
		stamp = c.lastNow.UnixNano()
	}
	writeNumber(&b, stamp)
	writeNumber(&b, uint32(len(c.groups)))
	keys := make([][32]byte, 0, len(c.groups))
	for k := range c.groups {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return bytes.Compare(keys[i][:], keys[j][:]) < 0 })
	rules := c.stateRules()
	for _, k := range keys {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		v := c.groups[k]
		r, ok := rules[v.ruleID]
		if !ok || validateCounter(v, r, c.lastNow) != nil || !validSnapshotKey(k, v, r) {
			return nil, ErrSnapshot
		}
		writeNumber(&b, uint16(len(v.ruleID)))
		b.WriteString(v.ruleID)
		b.WriteByte(v.kind)
		b.Write(k[:])
		b.Write(v.token[:])
		writeNumber(&b, v.expires.UnixNano())
		writeNumber(&b, uint32(v.count))
		writeNumber(&b, uint16(v.step))
		n := uint32(0)
		if v.history != nil {
			if v.history.distinct != nil {
				n = uint32(len(v.history.distinct))
			} else {
				n = uint32(v.count)
			}
		}
		writeNumber(&b, n)
		if v.history != nil && v.history.distinct != nil {
			values := make([][32]byte, 0, len(v.history.distinct))
			for value := range v.history.distinct {
				values = append(values, value)
			}
			sort.Slice(values, func(i, j int) bool { return bytes.Compare(values[i][:], values[j][:]) < 0 })
			for _, value := range values {
				b.Write(value[:])
				writeNumber(&b, v.history.distinct[value].UnixNano())
			}
		} else if v.history != nil {
			for i := 0; i < v.count; i++ {
				writeNumber(&b, v.history.stamps[(v.history.head+i)%len(v.history.stamps)].UnixNano())
			}
		}
		if b.Len() > MaxSnapshotBytes {
			return nil, ErrStateCapacity
		}
	}
	if b.Len()+sha256.Size > MaxSnapshotBytes {
		return nil, ErrStateCapacity
	}
	digest := sha256.Sum256(b.Bytes())
	b.Write(digest[:])
	return b.Bytes(), nil
}

// ImportState validates revision, descriptors, times, keys and allocation budgets
// before atomically replacing state. It refuses an older watermark on a live
// instance. Restore into a fresh Fork inside the authoritative DB transaction.
func (c *Compiled) ImportState(ctx context.Context, raw []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if len(raw) > MaxSnapshotBytes {
		return ErrStateCapacity
	}
	if len(raw) < len(snapshotMagic)+44+sha256.Size {
		return ErrSnapshot
	}
	body := raw[:len(raw)-sha256.Size]
	digest := sha256.Sum256(body)
	if !bytes.Equal(digest[:], raw[len(raw)-sha256.Size:]) {
		return ErrSnapshot
	}
	r := bytes.NewReader(body)
	magic := make([]byte, len(snapshotMagic))
	_, _ = io.ReadFull(r, magic)
	if string(magic) != snapshotMagic {
		return ErrSnapshot
	}
	var rev [32]byte
	_, _ = io.ReadFull(r, rev[:])
	if hex.EncodeToString(rev[:]) != c.revision {
		return ErrSnapshot
	}
	var watermark int64
	var count uint32
	if binary.Read(r, binary.BigEndian, &watermark) != nil || binary.Read(r, binary.BigEndian, &count) != nil || count > MaxGroups || watermark < 0 {
		return ErrSnapshot
	}
	now := time.Time{}
	if watermark > 0 {
		now = time.Unix(0, watermark).UTC()
		if !validStateTime(now) {
			return ErrSnapshot
		}
	} else if count > 0 {
		return ErrSnapshot
	}
	groups := make(map[[32]byte]counter, int(count))
	rules := c.stateRules()
	entries := 0
	for i := uint32(0); i < count; i++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		var size uint16
		if binary.Read(r, binary.BigEndian, &size) != nil || size < 1 || size > 128 {
			return ErrSnapshot
		}
		name := make([]byte, size)
		if _, err := io.ReadFull(r, name); err != nil {
			return ErrSnapshot
		}
		v := counter{ruleID: string(name)}
		rule, ok := rules[v.ruleID]
		if !ok {
			return ErrSnapshot
		}
		kind, err := r.ReadByte()
		if err != nil {
			return ErrSnapshot
		}
		v.kind = kind
		var key [32]byte
		var expiry int64
		var n, payload uint32
		var step uint16
		if _, err := io.ReadFull(r, key[:]); err != nil {
			return ErrSnapshot
		}
		if _, err := io.ReadFull(r, v.token[:]); err != nil {
			return ErrSnapshot
		}
		if key == ([32]byte{}) {
			return ErrSnapshot
		}
		if _, exists := groups[key]; exists {
			return ErrSnapshot
		}
		if binary.Read(r, binary.BigEndian, &expiry) != nil || binary.Read(r, binary.BigEndian, &n) != nil || binary.Read(r, binary.BigEndian, &step) != nil || binary.Read(r, binary.BigEndian, &payload) != nil || expiry <= 0 || n > 1000000 {
			return ErrSnapshot
		}
		v.count, v.step, v.expires = int(n), int(step), time.Unix(0, expiry).UTC()
		if kind == stateThreshold && rule.rule.Threshold != nil {
			t := rule.rule.Threshold
			if t.Distinct != "" {
				if payload == 0 || payload > MaxDistinct || int(payload) != v.count || int64(payload)*40 > int64(r.Len()) {
					return ErrSnapshot
				}
				entries += int(payload)
				if entries > MaxStateEntries {
					return ErrStateCapacity
				}
				h := &windowState{distinct: make(map[[32]byte]time.Time, int(payload)), window: rule.window, sliding: t.Mode == "sliding"}
				v.history = h
				for j := uint32(0); j < payload; j++ {
					var value [32]byte
					var ts int64
					if _, err := io.ReadFull(r, value[:]); err != nil {
						return ErrSnapshot
					}
					if binary.Read(r, binary.BigEndian, &ts) != nil || ts <= 0 || value == ([32]byte{}) {
						return ErrSnapshot
					}
					if _, ok := h.distinct[value]; ok {
						return ErrSnapshot
					}
					h.distinct[value] = time.Unix(0, ts).UTC()
				}
			} else if t.Mode == "sliding" {
				if payload == 0 || int(payload) != v.count || v.count > t.Count || int64(payload)*8 > int64(r.Len()) {
					return ErrSnapshot
				}
				entries += t.Count
				if entries > MaxStateEntries {
					return ErrStateCapacity
				}
				h := &windowState{stamps: make([]time.Time, t.Count), window: rule.window, sliding: true}
				v.history = h
				for j := 0; j < v.count; j++ {
					var ts int64
					if binary.Read(r, binary.BigEndian, &ts) != nil || ts <= 0 {
						return ErrSnapshot
					}
					h.stamps[j] = time.Unix(0, ts).UTC()
				}
			} else if payload != 0 {
				return ErrSnapshot
			}
		} else if payload != 0 {
			return ErrSnapshot
		}
		if err := validateCounter(v, rule, now); err != nil {
			return err
		}
		if !validSnapshotKey(key, v, rule) {
			return ErrSnapshot
		}
		groups[key] = v
	}
	if r.Len() != 0 {
		return ErrSnapshot
	}
	if int(count)*stateGroupBytes+entries*stateEntryBytes > MaxStateBytes {
		return ErrStateCapacity
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	if now.Before(c.lastNow) {
		return ErrStateClock
	}
	c.groups, c.lastNow = groups, now
	return nil
}

func validSnapshotKey(key [32]byte, v counter, r compiledRule) bool {
	if key == ([32]byte{}) || v.token == ([32]byte{}) {
		return false
	}
	id := "threshold:" + r.rule.ID
	if v.kind == stateSequence {
		if r.rule.Sequence == nil {
			return false
		}
		id = "sequence\x00" + r.rule.ID + "\x00" + r.rule.Sequence.Name
	}
	return key == stateKeyFromToken(id, v.token)
}

func validateCounter(v counter, r compiledRule, watermark time.Time) error {
	if watermark.IsZero() || !v.expires.After(watermark) || !validStateTime(v.expires) {
		return ErrSnapshot
	}
	window := r.window
	if v.kind == stateSequence {
		window = r.sequenceWindow
		if r.rule.Sequence == nil || v.step < 1 || v.step >= len(r.steps) || v.count != 0 || v.history != nil {
			return ErrSnapshot
		}
	} else if v.kind == stateThreshold {
		t := r.rule.Threshold
		if t == nil || t.Count <= 1 || v.count < 1 || v.step != 0 {
			return ErrSnapshot
		}
		if t.Distinct == "" && t.Mode != "sliding" {
			if v.history != nil || v.count > t.Count {
				return ErrSnapshot
			}
		} else {
			h := v.history
			if h == nil || h.window != window || h.sliding != (t.Mode == "sliding") {
				return ErrSnapshot
			}
			latest := time.Time{}
			lower := v.expires.Add(-window)
			if t.Distinct != "" {
				if len(h.stamps) != 0 || h.head != 0 || h.distinct == nil || len(h.distinct) != v.count || v.count > MaxDistinct {
					return ErrSnapshot
				}
				if h.sliding {
					lower = lower.Add(-window)
				}
				for key, ts := range h.distinct {
					if key == ([32]byte{}) || ts.Before(lower) || ts.After(watermark) || !ts.Before(v.expires) || !validStateTime(ts) {
						return ErrSnapshot
					}
					if ts.After(latest) {
						latest = ts
					}
				}
			} else {
				if h.distinct != nil || len(h.stamps) != t.Count || h.head < 0 || h.head >= t.Count || v.count > t.Count {
					return ErrSnapshot
				}
				lower = lower.Add(-window)
				for i := 0; i < v.count; i++ {
					ts := h.stamps[(h.head+i)%len(h.stamps)]
					if !ts.After(lower) || ts.After(watermark) || ts.Before(latest) || !validStateTime(ts) {
						return ErrSnapshot
					}
					latest = ts
				}
			}
			if h.sliding && !latest.Equal(v.expires.Add(-window)) {
				return ErrSnapshot
			}
		}
	} else {
		return ErrSnapshot
	}
	if window < time.Millisecond || window > 24*time.Hour || v.expires.After(watermark.Add(window)) {
		return ErrSnapshot
	}
	return nil
}
