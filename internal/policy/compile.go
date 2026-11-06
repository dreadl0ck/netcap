package policy

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"sync"
	"time"

	"github.com/expr-lang/expr/vm"
)

var validID = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$`)

const MaxCompiledWork uint64 = 65536

type compiledRule struct {
	rule           Rule
	program        *vm.Program
	window         time.Duration
	steps          []*vm.Program
	sequenceWindow time.Duration
	units          uint64
}

// Compiled owns an immutable, normalized bundle and revision-local counter state.
// It is safe for concurrent Evaluate calls. Create a new revision with Compile.
type Compiled struct {
	bundle     Bundle
	revision   string
	rules      []compiledRule
	mu         sync.Mutex
	groups     map[[32]byte]counter
	now        func() time.Time
	phaseUnits map[string]uint64
}

type counter struct {
	count   int
	step    int
	expires time.Time
}

// Compile validates versions 1/v1/netcap-policy/v1 and requires explicit mode/default. Expressions
// support comparisons, boolean/string operators, literal RE2 patterns and arrays,
// header indexing, and len/lower/upper/trim; iteration and dynamic calls are denied.
func Compile(b Bundle) (*Compiled, error) {
	if b.Version != "1" && b.Version != "v1" && b.Version != "netcap-policy/v1" {
		return nil, errors.New("policy: unsupported version")
	}
	if !validID.MatchString(b.ID) {
		return nil, errors.New("policy: invalid bundle ID")
	}
	if b.Mode != "enforce" && b.Mode != "monitor" {
		return nil, errors.New("policy: mode must be enforce or monitor")
	}
	if b.Default != "allow" && b.Default != "deny" {
		return nil, errors.New("policy: default must be allow or deny")
	}
	if len(b.Rules) > MaxRules {
		return nil, errors.New("policy: too many rules")
	}
	if err := checkBundleSize(b); err != nil {
		return nil, err
	}
	if b.Defaults != nil {
		for _, v := range []string{b.Defaults.Request, b.Defaults.Response} {
			if v != "" && v != "allow" && v != "deny" {
				return nil, errors.New("policy: invalid phase default")
			}
		}
	}
	b = cloneBundle(b)
	c := &Compiled{bundle: b, groups: make(map[[32]byte]counter), now: time.Now, phaseUnits: make(map[string]uint64)}
	ids := make(map[string]bool)
	names := make(map[string]bool)
	totalUnits := uint64(0)
	for i := range b.Rules {
		r := &b.Rules[i]
		if !validID.MatchString(r.ID) || ids[r.ID] {
			return nil, errors.New("policy: invalid or duplicate rule ID")
		}
		ids[r.ID] = true
		if r.Phase == "" {
			r.Phase = "request"
		}
		if r.Phase != "request" && r.Phase != "response" {
			return nil, fmt.Errorf("policy: rule %s: invalid phase", r.ID)
		}
		if r.Action != "allow" && r.Action != "deny" {
			return nil, fmt.Errorf("policy: rule %s: invalid action", r.ID)
		}
		if r.Action == "deny" && r.Status == 0 {
			r.Status = 403
		}
		if (r.Action == "deny" && (r.Status < 400 || r.Status > 599)) || (r.Action == "allow" && r.Status != 0) {
			return nil, fmt.Errorf("policy: rule %s: invalid action status", r.ID)
		}
		window, err := validateThreshold(r.Threshold)
		if err != nil {
			return nil, fmt.Errorf("policy: rule %s: %w", r.ID, err)
		}
		cr := compiledRule{rule: *r, window: window}
		if s := r.Sequence; s != nil {
			if !validID.MatchString(s.Name) || names[s.Name] {
				return nil, errors.New("policy: invalid or duplicate sequence name")
			}
			names[s.Name] = true
			if len(s.Steps) < 2 || len(s.Steps) > 16 {
				return nil, errors.New("policy: sequence requires 2..16 steps")
			}
			cr.sequenceWindow, err = validateThreshold(&Threshold{Count: 1, Window: s.Window, GroupBy: s.GroupBy})
			if err != nil {
				return nil, fmt.Errorf("policy: sequence %s: %w", s.Name, err)
			}
			for _, step := range s.Steps {
				p, err := compileExpression(step)
				if err != nil {
					return nil, fmt.Errorf("policy: sequence %s: %w", s.Name, err)
				}
				cr.steps = append(cr.steps, p)
				cr.units += programCost(step)
				if totalUnits+cr.units > MaxCompiledWork {
					return nil, errors.New("policy: compiled expression budget exceeded")
				}
			}
			if r.Expression == "" {
				r.Expression = "true"
			}
		}
		p, err := compileExpression(r.Expression)
		if err != nil {
			return nil, fmt.Errorf("policy: rule %s: %w", r.ID, err)
		}
		cr.rule, cr.program = *r, p
		cr.units += programCost(r.Expression)
		totalUnits += cr.units
		if totalUnits > MaxCompiledWork {
			return nil, errors.New("policy: compiled expression budget exceeded")
		}
		if r.Enabled == nil || *r.Enabled {
			c.phaseUnits[r.Phase] += cr.units
		}
		c.rules = append(c.rules, cr)
	}
	encoded, err := json.Marshal(b)
	if err != nil || len(encoded) > MaxBundleBytes {
		return nil, errors.New("policy: normalized bundle exceeds byte limit")
	}
	digest := sha256.Sum256(encoded)
	c.revision = hex.EncodeToString(digest[:])
	c.bundle = b
	sort.Slice(c.rules, func(i, j int) bool {
		a, b := c.rules[i].rule, c.rules[j].rule
		if a.Priority != b.Priority {
			return a.Priority > b.Priority
		}
		if a.Action != b.Action {
			return a.Action == "deny"
		}
		return a.ID < b.ID
	})
	return c, nil
}

func validateThreshold(t *Threshold) (time.Duration, error) {
	if t == nil {
		return 0, nil
	}
	if t.Count < 1 || t.Count > 1000000 {
		return 0, errors.New("threshold count must be 1..1000000")
	}
	if len(t.Window) > 32 {
		return 0, errors.New("threshold window is too long")
	}
	d, err := time.ParseDuration(t.Window)
	if err != nil || d < time.Millisecond || d > 24*time.Hour {
		return 0, errors.New("threshold window must be 1ms..24h")
	}
	switch t.GroupBy {
	case "", "ClientIP", "Host", "Path", "Method", "Protocol", "DNS.Name", "DNS.Type", "Modbus.UnitID":
	default:
		return 0, errors.New("unsupported threshold group_by")
	}
	return d, nil
}

// Bound direct in-memory Compile callers before cloning or compiling expressions.
func checkBundleSize(b Bundle) error {
	total := 0
	add := func(s string) bool {
		if len(s) > MaxBundleBytes-total {
			return false
		}
		total += len(s)
		return true
	}
	for _, s := range []string{b.Version, b.ID, b.Mode, b.Default} {
		if !add(s) {
			return errors.New("policy: bundle exceeds byte limit")
		}
	}
	for _, r := range b.Rules {
		for _, s := range []string{r.ID, r.Phase, r.Expression, r.Action} {
			if !add(s) {
				return errors.New("policy: bundle exceeds byte limit")
			}
		}
		if r.Threshold != nil {
			if !add(r.Threshold.Window) || !add(r.Threshold.GroupBy) {
				return errors.New("policy: bundle exceeds byte limit")
			}
		}
		if s := r.Sequence; s != nil {
			if len(s.Steps) < 2 || len(s.Steps) > 16 {
				return errors.New("policy: sequence requires 2..16 steps")
			}
			for _, v := range append([]string{s.Name, s.Window, s.GroupBy}, s.Steps...) {
				if !add(v) {
					return errors.New("policy: bundle exceeds byte limit")
				}
			}
		}
	}
	return nil
}

func cloneBundle(b Bundle) Bundle {
	if b.Defaults != nil {
		v := *b.Defaults
		b.Defaults = &v
	}
	b.Rules = append([]Rule(nil), b.Rules...)
	for i := range b.Rules {
		if p := b.Rules[i].Enabled; p != nil {
			v := *p
			b.Rules[i].Enabled = &v
		}
		if p := b.Rules[i].Threshold; p != nil {
			v := *p
			b.Rules[i].Threshold = &v
		}
		if p := b.Rules[i].Sequence; p != nil {
			v := *p
			v.Steps = append([]string(nil), p.Steps...)
			b.Rules[i].Sequence = &v
		}
	}
	return b
}

func (c *Compiled) Revision() string { return c.revision }

// Bundle returns a deep copy; changing it cannot alter the compiled policy.
func (c *Compiled) Bundle() Bundle { return cloneBundle(c.bundle) }
