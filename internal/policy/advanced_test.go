package policy

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"
)

func sequenceRule() Rule {
	r := deny("ordered", "")
	r.Sequence = &Sequence{Name: "login-export", GroupBy: "ClientIP", Window: "1s", Steps: []string{`Path == "/login"`, `Path == "/account"`, `Path == "/export"`}}
	return r
}

func TestNamedSequenceOrderGroupsAndWindow(t *testing.T) {
	c := compiled(t, bundle(sequenceRule()))
	now := time.Unix(100, 0)
	c.now = func() time.Time { return now }
	check := func(ip, path, want string) {
		t.Helper()
		d := evaluate(t, c, Event{ClientIP: ip, Path: path})
		if d.Verdict != want {
			t.Fatal(ip, path, d)
		}
	}
	check("a", "/export", "allow")
	check("a", "/login", "allow")
	check("b", "/account", "allow")
	check("a", "/unrelated", "allow")
	check("a", "/account", "allow")
	now = now.Add(time.Second - time.Nanosecond)
	check("a", "/export", "deny")
	check("a", "/export", "allow")
	check("a", "/login", "allow")
	check("a", "/account", "allow")
	now = now.Add(time.Second)
	check("a", "/export", "allow")
	check("a", "/login", "allow")
	check("a", "/account", "allow")
	check("a", "/login", "allow") // restart incomplete sequence
	check("a", "/export", "allow")
	check("a", "/account", "allow")
	check("a", "/export", "deny")
}

func TestSequenceGatePhaseThresholdAndImmutability(t *testing.T) {
	r := sequenceRule()
	r.Expression = `Method == "POST"`
	r.Sequence.Steps = []string{`Path == "/start"`, `Path == "/end"`}
	r.Threshold = &Threshold{Count: 2, Window: "1h", GroupBy: "ClientIP"}
	c := compiled(t, bundle(r))
	copy := c.Bundle()
	copy.Rules[0].Sequence.Steps[0] = "false"
	r.Sequence.Steps[0] = "false"
	for _, e := range []Event{
		{Method: "GET", Path: "/start"},
		{Method: "POST", Path: "/end"},
		{Method: "POST", Path: "/start", Phase: "response"},
		{Method: "POST", Path: "/end"},
		{Method: "POST", Path: "/start"},
		{Method: "POST", Path: "/end"},
		{Method: "POST", Path: "/end"},
		{Method: "POST", Path: "/start"},
	} {
		if d := evaluate(t, c, e); d.Verdict != "allow" {
			t.Fatal(d)
		}
	}
	if d := evaluate(t, c, Event{Method: "POST", Path: "/end"}); d.Verdict != "deny" {
		t.Fatal(d)
	}
	if len(c.groups) != 1 {
		t.Fatal("completed sequence retained state", len(c.groups))
	}
}

func TestSequenceOneStepPerEventAndConcurrentCompletion(t *testing.T) {
	r := sequenceRule()
	r.Sequence.Steps = []string{"true", "true"}
	r.Sequence.Window = "1h"
	c := compiled(t, bundle(r))
	var wg sync.WaitGroup
	results := make(chan Decision, 200)
	for i := 0; i < 200; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			d, err := c.Evaluate(Event{})
			if err != nil {
				t.Error(err)
				return
			}
			results <- d
		}()
	}
	wg.Wait()
	close(results)
	denied := 0
	for d := range results {
		if d.Verdict == "deny" {
			denied++
		}
	}
	if denied != 100 {
		t.Fatal("non-atomic sequence advancement", denied)
	}
}

func TestSequenceValidationAndJSONYAML(t *testing.T) {
	for name, mutate := range map[string]func(*Sequence){
		"name":       func(s *Sequence) { s.Name = "" },
		"short":      func(s *Sequence) { s.Steps = []string{"true"} },
		"long":       func(s *Sequence) { s.Steps = make([]string, 17) },
		"expression": func(s *Sequence) { s.Steps[0] = "now() == now()" },
		"window":     func(s *Sequence) { s.Window = "25h" },
		"group":      func(s *Sequence) { s.GroupBy = "Body" },
	} {
		t.Run(name, func(t *testing.T) {
			r := sequenceRule()
			mutate(r.Sequence)
			if _, err := Compile(bundle(r)); err == nil {
				t.Fatal("invalid sequence accepted")
			}
		})
	}
	a, b := sequenceRule(), sequenceRule()
	b.ID = "other"
	if _, err := Compile(bundle(a, b)); err == nil {
		t.Fatal("duplicate sequence name accepted")
	}
	bundle := bundle(sequenceRule())
	bundle.Version = "netcap-policy/v1"
	data, _ := json.Marshal(bundle)
	parsed, err := Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	compiled(t, parsed)
	y := `version: netcap-policy/v1
id: example
mode: enforce
default: allow
defaults: {response: allow}
rules:
  - id: ordered
    action: deny
    sequence:
      name: login-export
      group_by: ClientIP
      window: 1m
      steps:
        - Path == "/login"
        - Path == "/export"
`
	parsed, err = Parse([]byte(y))
	if err != nil {
		t.Fatal(err)
	}
	compiled(t, parsed)
}

func TestBudgetPreflightDoesNotRunExpressionsOrAdvanceState(t *testing.T) {
	r := deny("first", "true")
	r.Threshold = &Threshold{Count: 2, Window: "1h"}
	rules := []Rule{r}
	for i := 0; i < 100; i++ {
		rules = append(rules, deny(fmt.Sprint(i), `Body matches "^[a-z]*$"`))
	}
	c := compiled(t, bundle(rules...))
	if d, err := c.Evaluate(Event{Body: strings.Repeat("a", 1<<20)}); !errors.Is(err, ErrWorkBudget) || d.Verdict != "" {
		t.Fatal(d, err)
	}
	if len(c.groups) != 0 {
		t.Fatal("budget failure advanced state")
	}
	if d := evaluate(t, c, Event{Body: "a"}); d.Verdict != "deny" {
		t.Fatal(d)
	}
	rules[0].Expression = `Headers["Absent"][9] == "x"`
	c = compiled(t, bundle(rules...))
	if _, err := c.Evaluate(Event{Body: strings.Repeat("a", 1<<20)}); !errors.Is(err, ErrWorkBudget) {
		t.Fatal("expression ran before preflight", err)
	}
	// Unreachable/short-circuited expensive expressions are charged too.
	c = compiled(t, bundle(deny("cost", `false and Body matches "a{1000}"`)))
	if _, err := c.Evaluate(Event{Body: strings.Repeat("a", 1<<20)}); !errors.Is(err, ErrWorkBudget) {
		t.Fatal(err)
	}
}

func TestProtocolFieldsAndAllFieldBounds(t *testing.T) {
	c := compiled(t, bundle(deny("write", `Protocol == "modbus" && Modbus.IsWrite && Modbus.UnitID == 7 && Modbus.Address >= 100`)))
	if d := evaluate(t, c, Event{Protocol: "modbus", Modbus: ModbusEvent{IsWrite: true, UnitID: 7, Address: 100}}); d.Verdict != "deny" {
		t.Fatal(d)
	}
	c = compiled(t, bundle(deny("dns", `Protocol == "dns" && DNS.Name endsWith ".test" && DNS.Type == 16`)))
	if d := evaluate(t, c, Event{Protocol: "dns", DNS: DNSEvent{Name: "blocked.test", Type: 16}}); d.Verdict != "deny" {
		t.Fatal(d)
	}
	for _, e := range []Event{{Protocol: strings.Repeat("x", 65537)}, {DNS: DNSEvent{Name: strings.Repeat("x", 65537)}}, {Body: strings.Repeat("x", MaxEventBytes-7), Protocol: "dns", DNS: DNSEvent{Name: "x"}}} {
		if _, err := c.Evaluate(e); err == nil {
			t.Fatal("gateway event escaped size accounting")
		}
	}
	r := deny("by-name", "true")
	r.Threshold = &Threshold{Count: 2, Window: "1h", GroupBy: "DNS.Name"}
	c = compiled(t, bundle(r))
	evaluate(t, c, Event{DNS: DNSEvent{Name: "one"}})
	if d := evaluate(t, c, Event{DNS: DNSEvent{Name: "two"}}); d.Verdict != "allow" {
		t.Fatal(d)
	}
	if d := evaluate(t, c, Event{DNS: DNSEvent{Name: "one"}}); d.Verdict != "deny" {
		t.Fatal(d)
	}
}

func TestPerPhaseDefaults(t *testing.T) {
	b := bundle(Rule{ID: "whitelist", Action: "allow", Expression: `Path == "/ok"`})
	b.Default = "deny"
	c := compiled(t, b)
	if d := evaluate(t, c, Event{Phase: "response"}); d.Verdict != "deny" {
		t.Fatal("legacy default behavior changed", d)
	}
	b.Defaults = &PhaseDefaults{Response: "allow"}
	c = compiled(t, b)
	if d := evaluate(t, c, Event{Path: "/ok"}); d.Verdict != "allow" {
		t.Fatal(d)
	}
	if d := evaluate(t, c, Event{Path: "/bad"}); d.Verdict != "deny" {
		t.Fatal(d)
	}
	if d := evaluate(t, c, Event{Phase: "response"}); d.Verdict != "allow" {
		t.Fatal(d)
	}
	b.Defaults.Response = "deny"
	copy := c.Bundle()
	copy.Defaults.Response = "deny"
	if d := evaluate(t, c, Event{Phase: "response"}); d.Verdict != "allow" {
		t.Fatal("mutable defaults", d)
	}
	b.Defaults.Response = "invalid"
	if _, err := Compile(b); err == nil {
		t.Fatal("invalid phase default")
	}
}

func TestYAMLIndicatorsAliasesAndMergeDuplicates(t *testing.T) {
	for _, data := range []string{
		"id: &id test", "id: !!str test", strings.Repeat(" ", 65) + "id: test",
		"id: first\u0085mode: monitor", "id: 'do *something << useful & literal ! text'",
		"id: first # ! * & << these are ordinary comments",
		"id: test\nmode: &mode enforce\ndefault: *mode",
	} {
		if _, err := Parse([]byte(data)); err != nil {
			t.Fatal(data, err)
		}
	}
	for _, data := range []string{
		"id: first\n<<: {id: second}", "<<: {id: second}\nid: first",
		"rules: [{id: first, <<: {id: second}}]",
		"rules: [{sequence: {name: first, <<: {name: second}}}]",
		"rules: [{sequence: {name: &cycle {name: *cycle}}}]",
	} {
		if _, err := Parse([]byte(data)); err == nil {
			t.Fatal("merge/cycle accepted", data)
		}
	}
	data := `version: netcap-policy/v1
id: quoted-text
mode: enforce
default: &allow allow
rules:
  - id: body-text
    <<: {action: deny, expression: 'Body contains "<< * & !"'}
  - id: safe
    action: *allow
    expression: 'Path == "/safe"'
`
	b, err := Parse([]byte(data))
	if err != nil {
		t.Fatal(err)
	}
	if d := evaluate(t, compiled(t, b), Event{Body: "<< * & !"}); d.Verdict != "deny" {
		t.Fatal(d)
	}
}

func TestSequenceEvaluatesOnlyExpectedStepAndRollsBackErrors(t *testing.T) {
	r := sequenceRule()
	r.Sequence.Steps = []string{`Path == "/start"`, `Headers["X-Step"][0] == "finish"`}
	c := compiled(t, bundle(r))
	// The final step cannot safely run on the first event, and must not run yet.
	if d := evaluate(t, c, Event{Path: "/start"}); d.Verdict != "allow" {
		t.Fatal(d)
	}
	before := make(map[[32]byte]counter)
	for k, v := range c.groups {
		before[k] = v
	}
	if _, err := c.Evaluate(Event{Path: "/end", Body: "private-content"}); err == nil || strings.Contains(err.Error(), "private-content") {
		t.Fatal(err)
	}
	for k, v := range before {
		if c.groups[k] != v {
			t.Fatal("error advanced sequence")
		}
	}
	if d := evaluate(t, c, Event{Headers: map[string][]string{"X-Step": {"finish"}}}); d.Verdict != "deny" {
		t.Fatal(d)
	}
}

func TestMixedStateCapacityUpdateIsTransactional(t *testing.T) {
	r := deny("a", "true")
	r.Threshold = &Threshold{Count: 2, Window: "1h", GroupBy: "ClientIP"}
	s := sequenceRule()
	s.ID = "b"
	s.Sequence.Window = "1h"
	c := compiled(t, bundle(r, s))
	now := time.Unix(100, 0)
	c.now = func() time.Time { return now }
	key := groupKey("threshold:a", "ClientIP", Event{ClientIP: "shared"})
	c.groups[key] = counter{count: 1, expires: now.Add(time.Hour)}
	for i := 0; len(c.groups) < MaxGroups; i++ {
		c.groups[groupKey(fmt.Sprint(i), "", Event{})] = counter{count: 1, expires: now.Add(time.Hour)}
	}
	e := Event{ClientIP: "shared", Path: "/login"}
	if _, err := c.Evaluate(e); !errors.Is(err, ErrStateCapacity) {
		t.Fatal(err)
	}
	if c.groups[key].count != 1 || len(c.groups) != MaxGroups {
		t.Fatal("capacity error partially committed updates")
	}
	for k := range c.groups {
		if k != key {
			delete(c.groups, k)
			break
		}
	}
	if d := evaluate(t, c, e); d.Verdict != "deny" {
		t.Fatal(d)
	}
	if c.groups[key].count != 2 || len(c.groups) != MaxGroups {
		t.Fatal("mixed state updates not committed together")
	}
}

func TestSimulationSequenceIsolationFrozenClockAndBudget(t *testing.T) {
	r := sequenceRule()
	r.Sequence.Steps = []string{"true", "true"}
	r.Sequence.Window = "1ms"
	c := compiled(t, bundle(r))
	ds, err := c.Simulate(make([]Event, 200))
	if err != nil {
		t.Fatal(err)
	}
	for i, d := range ds {
		want := "allow"
		if i%2 == 1 {
			want = "deny"
		}
		if d.Verdict != want {
			t.Fatal(i, d)
		}
	}
	if len(c.groups) != 0 {
		t.Fatal("simulation advanced live sequence")
	}
	if d := evaluate(t, c, Event{}); d.Verdict != "allow" {
		t.Fatal(d)
	}
	c = compiled(t, bundle(deny("cost", `Body matches "^[a-z]*$"`)))
	large := Event{Body: strings.Repeat("a", 1<<20)}
	events := make([]Event, 200)
	for i := range events {
		events[i] = large
	}
	if _, err := c.Simulate(events); !errors.Is(err, ErrWorkBudget) {
		t.Fatal("unbounded simulation", err)
	}
}

func TestCompilerAggregateBudget(t *testing.T) {
	rules := make([]Rule, 100)
	for i := range rules {
		rules[i] = deny(fmt.Sprint(i), `Body matches "a{1000}"`)
	}
	if _, err := Compile(bundle(rules...)); err == nil || !strings.Contains(err.Error(), "budget") {
		t.Fatal("unbounded regex compilation", err)
	}
	r := sequenceRule()
	r.Sequence.Steps = make([]string, 17)
	if _, err := Compile(bundle(r)); err == nil {
		t.Fatal("large step slice cloned")
	}
}

func TestPriorityCannotSuppressThresholdAccounting(t *testing.T) {
	r := deny("rate", "true")
	r.Threshold = &Threshold{Count: 2, Window: "1h"}
	allow := Rule{ID: "exception", Expression: "true", Action: "allow", Priority: 100}
	c := compiled(t, bundle(r, allow))
	for i := 0; i < 2; i++ {
		if d := evaluate(t, c, Event{}); d.RuleID != "exception" {
			t.Fatal(d)
		}
	}
	key := groupKey("threshold:rate", "", Event{})
	if c.groups[key].count != 2 {
		t.Fatal("winning allow suppressed lower-priority threshold")
	}
}

func TestSequenceNamespaceCannotCollideOnColonIDs(t *testing.T) {
	a, b := sequenceRule(), sequenceRule()
	a.ID, a.Sequence.Name = "a:b", "c"
	b.ID, b.Sequence.Name = "a", "b:c"
	a.Sequence.Steps = []string{`Path == "/a-start"`, `Path == "/a-end"`}
	b.Sequence.Steps = []string{`Path == "/b-start"`, `Path == "/b-end"`}
	c := compiled(t, bundle(a, b))
	evaluate(t, c, Event{Path: "/a-start"})
	if d := evaluate(t, c, Event{Path: "/b-end"}); d.Verdict != "allow" {
		t.Fatal("sequence namespace collision", d)
	}
	if d := evaluate(t, c, Event{Path: "/a-end"}); d.RuleID != "a:b" {
		t.Fatal(d)
	}
}

func TestCountOneNeedsNoPersistentState(t *testing.T) {
	r := deny("always", "true")
	r.Threshold = &Threshold{Count: 1, Window: "1h", GroupBy: "ClientIP"}
	c := compiled(t, bundle(r))
	for i := 0; i < MaxGroups+1; i++ {
		if d := evaluate(t, c, Event{ClientIP: fmt.Sprint(i)}); d.Verdict != "deny" {
			t.Fatal(d)
		}
	}
	if len(c.groups) != 0 {
		t.Fatal("count-one threshold allocated unnecessary state")
	}
}
