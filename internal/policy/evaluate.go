package policy

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"time"

	"github.com/expr-lang/expr"
)

var ErrStateCapacity = errors.New("policy: threshold state capacity exhausted")

const MaxSimulationWork uint64 = 1 << 30

// Evaluate counts every matching enabled rule in the event's phase, then picks
// highest priority, deny before allow on ties, then lexicographically first ID.
// Default applies to both phases unless Defaults overrides it. Errors must be
// handled by the caller's fail-closed policy; they are never allows.
func (c *Compiled) Evaluate(e Event) (Decision, error) {
	return c.evaluate(context.Background(), e, time.Time{})
}

// EvaluateAt is for trusted authoritative processors. Event data never selects
// the clock. Callers must serialize import/evaluate/export as one transaction.
func (c *Compiled) EvaluateAt(ctx context.Context, e Event, now time.Time) (Decision, error) {
	if !validStateTime(now) {
		return Decision{}, ErrStateClock
	}
	return c.evaluate(ctx, e, now)
}

func (c *Compiled) evaluate(ctx context.Context, e Event, instant time.Time) (Decision, error) {
	if err := ctx.Err(); err != nil {
		return Decision{}, err
	}
	if e.Phase == "" {
		e.Phase = "request"
	}
	size, err := eventSize(e)
	if err != nil {
		return Decision{}, err
	}
	if c.phaseUnits[e.Phase] > MaxEvaluationWork/size {
		return Decision{}, ErrWorkBudget
	}
	matches := make([]int, 0, len(c.rules))
	for i, r := range c.rules {
		if err := ctx.Err(); err != nil {
			return Decision{}, err
		}
		if r.rule.Phase != e.Phase || (r.rule.Enabled != nil && !*r.rule.Enabled) {
			continue
		}
		v, err := expr.Run(r.program, e)
		if err != nil {
			return Decision{}, fmt.Errorf("policy: rule %s: evaluation failed", r.rule.ID)
		}
		matched, ok := v.(bool)
		if !ok {
			return Decision{}, fmt.Errorf("policy: rule %s: non-boolean result", r.rule.ID)
		}
		if matched {
			matches = append(matches, i)
		}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now()
	if !instant.IsZero() {
		now = instant
	}
	if err := ctx.Err(); err != nil {
		return Decision{}, err
	}
	if now.Before(c.lastNow) {
		return Decision{}, ErrStateClock
	}
	usage := c.stateStats()
	// Expiry is a state transition too: retain the original map and watermark
	// until every validation and capacity check succeeds.
	updates := make(map[[32]byte]counter)
	finalEntries := usage.Entries
	for key, v := range c.groups {
		if !now.Before(v.expires) {
			updates[key] = counter{}
			finalEntries -= counterEntries(v)
		}
	}
	budget := &stateBudget{live: usage, finalEntries: finalEntries}
	winner := -1
	for _, i := range matches {
		r := c.rules[i]
		if r.rule.Sequence != nil {
			completed, err := c.advanceSequence(r, e, now, updates)
			if err != nil {
				return Decision{}, err
			}
			if !completed {
				continue
			}
		}
		if r.rule.Threshold != nil {
			matched, err := c.advanceThreshold(r, e, now, updates, budget)
			if err != nil {
				return Decision{}, err
			}
			if !matched {
				continue
			}
		}
		if winner == -1 {
			winner = i
		}
	}
	d := Decision{Verdict: c.bundle.Default, Revision: c.revision, Monitor: c.bundle.Mode == "monitor"}
	if defaults := c.bundle.Defaults; defaults != nil {
		v := defaults.Request
		if e.Phase == "response" {
			v = defaults.Response
		}
		if v != "" {
			d.Verdict = v
		}
	}
	if winner >= 0 {
		r := c.rules[winner].rule
		d.Verdict, d.Status, d.RuleID = r.Action, r.Status, r.ID
		// Only the winning rule contributes effects. Monitor never emits intents.
		if !d.Monitor && !c.suppressEffects {
			d.Effects, err = makeIntents(r.Effects, e, d, now)
			if err != nil {
				return Decision{}, err
			}
		}
	}
	if err := ctx.Err(); err != nil {
		return Decision{}, err
	}
	if len(updates) > 0 {
		if err := c.applyUpdates(updates); err != nil {
			return Decision{}, err
		}
	}
	if d.Verdict == "deny" {
		if d.Status == 0 {
			d.Status = 403
		}
		if d.Monitor {
			d.Verdict = "would-deny"
		}
	}
	c.lastNow = now
	return d, nil
}

func (c *Compiled) applyUpdates(updates map[[32]byte]counter) error {
	usage := c.stateStats()
	for k, v := range updates {
		if old, exists := c.groups[k]; exists {
			usage.Groups--
			usage.Entries -= counterEntries(old)
		}
		if !v.expires.IsZero() {
			usage.Groups++
			usage.Entries += counterEntries(v)
		}
	}
	if usage.Groups > MaxGroups || usage.Entries > MaxStateEntries || usage.Groups*stateGroupBytes+usage.Entries*stateEntryBytes > MaxStateBytes {
		return ErrStateCapacity
	}
	for k, v := range updates {
		if v.expires.IsZero() {
			delete(c.groups, k)
		}
	}
	for k, v := range updates {
		if !v.expires.IsZero() {
			c.groups[k] = v
		}
	}
	return nil
}

func validateEvent(e Event) error {
	_, err := eventSize(e)
	return err
}

func eventSize(e Event) (uint64, error) {
	if e.Network.SrcPort < 0 || e.Network.SrcPort > 65535 || e.Network.DstPort < 0 || e.Network.DstPort > 65535 || (e.Network.IPVersion != 0 && e.Network.IPVersion != 4 && e.Network.IPVersion != 6) || e.Network.TCPFlags < 0 || e.Network.TCPFlags > 511 {
		return 0, errors.New("policy: invalid network fields")
	}
	for _, fields := range []map[string]string{e.Attributes, e.Fields} {
		if len(fields) > 128 {
			return 0, errors.New("policy: too many protocol fields")
		}
		for k := range fields {
			if len(k) == 0 || len(k) > 128 {
				return 0, errors.New("policy: invalid protocol field name")
			}
		}
	}
	if e.Phase != "request" && e.Phase != "response" {
		return 0, errors.New("policy: invalid event phase")
	}
	if e.Status != 0 && (e.Status < 100 || e.Status > 599) {
		return 0, errors.New("policy: invalid event status")
	}
	if len(e.Headers) > 128 {
		return 0, errors.New("policy: too many headers")
	}
	values := 0
	for k, vv := range e.Headers {
		if len(k) > 1024 || len(vv) > 1024-values {
			return 0, errors.New("policy: headers exceed limits")
		}
		values += len(vv)
	}
	total, nodes := uint64(0), 0
	err := measureValue(reflect.ValueOf(e), "", 0, &total, &nodes)
	return total + uint64(nodes) + 1, err
}

func measureValue(v reflect.Value, path string, depth int, total *uint64, nodes *int) error {
	*nodes++
	if depth > 8 || *nodes > 4096 {
		return errors.New("policy: event structure exceeds limits")
	}
	switch v.Kind() {
	case reflect.Ptr:
		if !v.IsNil() {
			return measureValue(v.Elem(), path, depth+1, total, nodes)
		}
	case reflect.Struct:
		for i := 0; i < v.NumField(); i++ {
			if err := measureValue(v.Field(i), path+"."+v.Type().Field(i).Name, depth+1, total, nodes); err != nil {
				return err
			}
		}
	case reflect.Map:
		if v.Len() > 128 {
			return errors.New("policy: event map exceeds limits")
		}
		it := v.MapRange()
		for it.Next() {
			if err := measureValue(it.Key(), path, depth+1, total, nodes); err != nil {
				return err
			}
			if err := measureValue(it.Value(), path, depth+1, total, nodes); err != nil {
				return err
			}
		}
	case reflect.Slice, reflect.Array:
		if v.Len() > 1024 {
			return errors.New("policy: event array exceeds limits")
		}
		for i := 0; i < v.Len(); i++ {
			if err := measureValue(v.Index(i), path, depth+1, total, nodes); err != nil {
				return err
			}
		}
	case reflect.String:
		n := uint64(v.Len())
		if path != ".Body" && path != ".Headers" && n > 65536 {
			return errors.New("policy: event field exceeds 65536 bytes")
		}
		if n > MaxEventBytes-*total {
			return errors.New("policy: event exceeds byte limit")
		}
		*total += n
	case reflect.Bool, reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64, reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
	default:
		return errors.New("policy: unsupported event field type")
	}
	return nil
}

func (c *Compiled) advanceSequence(r compiledRule, e Event, now time.Time, updates map[[32]byte]counter) (bool, error) {
	s := r.rule.Sequence
	key, token, err := stateKeyParts("sequence\x00"+r.rule.ID+"\x00"+s.Name, s.GroupBy, s.GroupByFields, e)
	if err != nil {
		return false, err
	}
	v := c.groups[key]
	if !now.Before(v.expires) {
		v = counter{}
	}
	value, err := expr.Run(r.steps[v.step], e)
	if err != nil {
		return false, fmt.Errorf("policy: sequence %s: evaluation failed", s.Name)
	}
	if value.(bool) {
		if v.step == 0 {
			v.expires = now.Add(r.sequenceWindow)
		}
		v.step++
		if v.step == len(r.steps) {
			updates[key] = counter{}
			return true, nil
		}
	} else if v.step > 0 {
		first, err := expr.Run(r.steps[0], e)
		if err != nil {
			return false, fmt.Errorf("policy: sequence %s: evaluation failed", s.Name)
		}
		if first.(bool) {
			v = counter{step: 1, expires: now.Add(r.sequenceWindow)}
		}
	}
	if v.step > 0 {
		v.ruleID, v.kind, v.token = r.rule.ID, stateSequence, token
		updates[key] = v
	}
	return false, nil
}

// Explain evaluates once, advancing counters just like Evaluate. Its output
// includes no request data, header values, body, or expression source.
func (c *Compiled) Explain(e Event) (Explanation, error) {
	d, err := c.Evaluate(e)
	if err != nil {
		return Explanation{}, err
	}
	d.Effects = nil // Intent sources are event values, not explanation metadata.
	reason := "bundle-default"
	if d.RuleID != "" {
		reason = "rule-matched"
	}
	return Explanation{Decision: d, Reason: reason}, nil
}

// Simulate starts with fresh state and never changes live threshold counters.
// Events are evaluated in slice order at one frozen instant (no elapsed time).
func (c *Compiled) Simulate(events []Event) ([]Decision, error) {
	if len(events) > 10000 {
		return nil, errors.New("policy: simulation exceeds 10000 events")
	}
	work := uint64(0)
	for _, e := range events {
		if e.Phase == "" {
			e.Phase = "request"
		}
		size, err := eventSize(e)
		if err != nil {
			return nil, err
		}
		units := c.phaseUnits[e.Phase]
		if units > (MaxSimulationWork-work)/size {
			return nil, ErrWorkBudget
		}
		work += units * size
	}
	shadow, err := CompileWithOptions(c.Bundle(), c.options)
	if err != nil {
		return nil, err
	}
	instant := time.Now()
	shadow.now = func() time.Time { return instant }
	shadow.suppressEffects = true
	decisions := make([]Decision, 0, len(events))
	for i, e := range events {
		d, err := shadow.Evaluate(e)
		if err != nil {
			return nil, fmt.Errorf("policy: simulation event %d: %w", i, err)
		}
		d.Effects = nil // Replay results cannot be submitted as live intents.
		decisions = append(decisions, d)
	}
	return decisions, nil
}
