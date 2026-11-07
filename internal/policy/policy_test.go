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

func bundle(rules ...Rule) Bundle {
	return Bundle{Version: "1", ID: "test-policy", Mode: "enforce", Default: "allow", Rules: rules}
}

func deny(id, expression string) Rule {
	return Rule{ID: id, Expression: expression, Action: "deny"}
}

func compiled(t *testing.T, b Bundle) *Compiled {
	t.Helper()
	c, err := Compile(b)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func evaluate(t *testing.T, c *Compiled, e Event) Decision {
	t.Helper()
	d, err := c.Evaluate(e)
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func TestParseStrictDocuments(t *testing.T) {
	valid := `version: "1"
id: test
mode: enforce
default: allow
rules:
  - id: post
    expression: Method == "POST"
    action: deny
    threshold:
      count: 2
      window: 1m
      group_by: ClientIP
`
	b, err := Parse([]byte(valid))
	if err != nil {
		t.Fatal(err)
	}
	c := compiled(t, b)
	if d := evaluate(t, c, Event{Method: "POST"}); d.Verdict != "allow" {
		t.Fatal(d)
	}
	if d := evaluate(t, c, Event{Method: "POST"}); d.Verdict != "deny" {
		t.Fatal(d)
	}
	j, _ := json.Marshal(b)
	if _, err := Parse(j); err != nil {
		t.Fatal(err)
	}
	bad := []string{
		"", "   ", "null", "~", "[]", "true", "---\n", valid + "\n---\n{}",
		valid + "\nid: duplicate", valid + "\nunknown: value",
		strings.Replace(valid, "action: deny", "action: deny\n    action: allow", 1),
		strings.Replace(valid, "action: deny", "action: deny\n    surprise: 1", 1),
		strings.Replace(valid, "count: 2", "count: 2\n      count: 3", 1),
		strings.Replace(valid, "count: 2", "count: 2\n      extra: 3", 1),
		`{"id":"a","id":"b"}`, `{"ID":"a"}`, `{"id":"a","ID":"b"}`,
		`{"rules":[{"id":"x","id":"y"}]}`,
		`{"rules":[{"threshold":{"count":1,"count":2}}]}`,
		`{"rules":[{"threshold":{"Count":1}}]}`,
		`{"rules":[{"extra":1}]}`, `{"rules":[]} {}`, `{"rules":[]} trailing`,
		`{"rules":[{"priority":"2"}]}`, `{"unknown":true}`,
		"id: first\n<<: {id: second}", "<<: {id: second}\nid: first",
		"id: *anchor",
		"rules: " + strings.Repeat("[", 17) + strings.Repeat("]", 17),
		"expression: true /* ' */\n<<: {id: hidden}\nid: duplicate",
		"id: first\u0085<<: {id: second}",
		"rules: [*missing]",
		strings.Repeat(" ", MaxBundleBytes+1),
	}
	for i, data := range bad {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			if _, err := Parse([]byte(data)); err == nil {
				t.Fatalf("accepted invalid document %.150q", data)
			}
		})
	}
}

func TestCompileValidation(t *testing.T) {
	base := bundle(deny("rule", "true"))
	tests := map[string]func(*Bundle){
		"version":      func(b *Bundle) { b.Version = "2" },
		"bundle id":    func(b *Bundle) { b.ID = "bad\nID" },
		"mode":         func(b *Bundle) { b.Mode = "blocking" },
		"default":      func(b *Bundle) { b.Default = "alert" },
		"rule id":      func(b *Bundle) { b.Rules[0].ID = "" },
		"duplicate":    func(b *Bundle) { b.Rules = append(b.Rules, b.Rules[0]) },
		"phase":        func(b *Bundle) { b.Rules[0].Phase = "both" },
		"action":       func(b *Bundle) { b.Rules[0].Action = "alert" },
		"status low":   func(b *Bundle) { b.Rules[0].Status = 399 },
		"status high":  func(b *Bundle) { b.Rules[0].Status = 600 },
		"allow status": func(b *Bundle) { b.Rules[0].Action = "allow"; b.Rules[0].Status = 403 },
		"count":        func(b *Bundle) { b.Rules[0].Threshold = &Threshold{Count: 0, Window: "1m"} },
		"count high":   func(b *Bundle) { b.Rules[0].Threshold = &Threshold{Count: 1000001, Window: "1m"} },
		"window low":   func(b *Bundle) { b.Rules[0].Threshold = &Threshold{Count: 1, Window: "1ns"} },
		"window high":  func(b *Bundle) { b.Rules[0].Threshold = &Threshold{Count: 1, Window: "25h"} },
		"group":        func(b *Bundle) { b.Rules[0].Threshold = &Threshold{Count: 1, Window: "1m", GroupBy: "Body"} },
		"too many":     func(b *Bundle) { b.Rules = make([]Rule, MaxRules+1) },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			b := cloneBundle(base)
			mutate(&b)
			if _, err := Compile(b); err == nil {
				t.Fatal("accepted invalid bundle")
			}
		})
	}
}

func TestExpressionSandbox(t *testing.T) {
	bad := []string{
		"", "Method", "42", "Missing == 1", `Method ==`,
		`map(1..100000000, # * #) == []`, `all(Headers, true)`,
		`repeat(Body, 100000000) == ""`, `Body + Body == ""`,
		`2 ** 100000000 > 1`, `1 / 0 == 0`, `now() == now()`,
		`Body matches RawQuery`, `Body matches "["`,
		`let x = Body; x == "secret"`, `Method == "GET" ? true : false`,
		`Headers.String() == ""`, `toJSON(Headers) == ""`,
		`Body[0:1] == "x"`, `true; false`,
		`Body matches "` + strings.Repeat("a", 257) + `"`,
		strings.Repeat("!", 33) + "true",
		strings.Repeat("a", MaxExpressionBytes+1),
		`Method in [` + strings.Repeat(`"x",`, 65) + `"y"]`,
	}
	for _, expression := range bad {
		if _, err := Compile(bundle(deny("sandbox", expression))); err == nil {
			t.Errorf("accepted unsafe expression %.100q", expression)
		}
	}
	good := []string{
		`Method == "POST" and Host == "example.test"`,
		`Path startsWith "/admin" && RawQuery contains "bad"`,
		`lower(Body) contains "attack"`, `upper(Method) == "POST"`,
		`trim(Host) == "example.test"`, `len(Body) > 0`,
		`Method in ["GET", "POST"]`, `Path matches "^/admin(/|$)"`,
		`len(Headers["Authorization"]) > 0`,
		`Headers["Authorization"][0] == "secret"`,
		`Status >= 400 or Phase == "request"`,
		`not (Method == "GET")`, `Path endsWith "admin"`,
	}
	e := Event{Method: "POST", Host: "example.test", Path: "/admin", RawQuery: "bad", Body: "ATTACK", Headers: map[string][]string{"Authorization": {"secret"}}}
	for _, expression := range good {
		c := compiled(t, bundle(deny("good", expression)))
		if d := evaluate(t, c, e); d.Verdict != "deny" {
			t.Errorf("expression %q: %+v", expression, d)
		}
	}
}

func TestDeterministicPrecedenceAndPhase(t *testing.T) {
	allow := Rule{ID: "exception", Expression: "true", Action: "allow", Priority: 1}
	a, z := deny("a", "true"), deny("z", "true")
	response := deny("response", "Status == 500")
	response.Phase, response.Priority = "response", 100
	disabled := false
	off := deny("off", "true")
	off.Enabled, off.Priority = &disabled, 1000
	for _, rules := range [][]Rule{{z, a, response, off}, {off, response, a, z}} {
		c := compiled(t, bundle(rules...))
		if d := evaluate(t, c, Event{}); d.RuleID != "a" || d.Status != 403 {
			t.Fatal(d)
		}
		if d := evaluate(t, c, Event{Phase: "response", Status: 500}); d.RuleID != "response" {
			t.Fatal(d)
		}
		if d := evaluate(t, c, Event{Phase: "response", Status: 200}); d.Verdict != "allow" || d.RuleID != "" {
			t.Fatal(d)
		}
	}
	c := compiled(t, bundle(a, allow))
	if d := evaluate(t, c, Event{}); d.Verdict != "allow" || d.RuleID != "exception" {
		t.Fatal(d)
	}
	allow.Priority = 0
	c = compiled(t, bundle(allow, a))
	if d := evaluate(t, c, Event{}); d.RuleID != "a" {
		t.Fatal(d)
	}
}

func TestMonitorAndDefault(t *testing.T) {
	for _, mode := range []string{"monitor", "enforce"} {
		for _, withRule := range []bool{false, true} {
			b := bundle()
			b.Default, b.Mode = "deny", mode
			if withRule {
				b.Rules = []Rule{deny("block", "true")}
			}
			d := evaluate(t, compiled(t, b), Event{})
			want := "deny"
			if mode == "monitor" {
				want = "would-deny"
			}
			if d.Verdict != want || d.Status != 403 || d.Monitor != (mode == "monitor") {
				t.Fatal(d)
			}
		}
	}
}

func TestRevisionAndImmutability(t *testing.T) {
	enabled := true
	r := deny("r", "true")
	r.Enabled, r.Threshold = &enabled, &Threshold{Count: 2, Window: "1m"}
	b := bundle(r)
	c := compiled(t, b)
	if len(c.Revision()) != 64 {
		t.Fatal(c.Revision())
	}
	if got := compiled(t, c.Bundle()).Revision(); got != c.Revision() {
		t.Fatal("unstable revision")
	}
	copy := c.Bundle()
	copy.Rules[0].Expression = "false"
	*copy.Rules[0].Enabled = false
	copy.Rules[0].Threshold.Count = 999
	*b.Rules[0].Enabled = false
	b.Rules[0].Threshold.Count = 999
	if d := evaluate(t, c, Event{}); d.Verdict != "allow" {
		t.Fatal(d)
	}
	if d := evaluate(t, c, Event{}); d.Verdict != "deny" {
		t.Fatal(d)
	}
	if got := compiled(t, copy).Revision(); got == c.Revision() {
		t.Fatal("revision did not change")
	}
}

func TestGroupedWindowsAndScope(t *testing.T) {
	clock := time.Unix(100, 0)
	r := deny("rate", `Method == "POST"`)
	r.Threshold = &Threshold{Count: 2, Window: "1s", GroupBy: "ClientIP"}
	c := compiled(t, bundle(r))
	c.now = func() time.Time { return clock }
	post := Event{Method: "POST", ClientIP: "a"}
	if d := evaluate(t, c, post); d.Verdict != "allow" {
		t.Fatal(d)
	}
	if d := evaluate(t, c, Event{Method: "GET", ClientIP: "a"}); d.Verdict != "allow" {
		t.Fatal(d)
	}
	if d := evaluate(t, c, Event{Phase: "response", Method: "POST", ClientIP: "a"}); d.Verdict != "allow" {
		t.Fatal(d)
	}
	if d := evaluate(t, c, Event{Method: "POST", ClientIP: "b"}); d.Verdict != "allow" {
		t.Fatal(d)
	}
	if d := evaluate(t, c, post); d.Verdict != "deny" {
		t.Fatal(d)
	}
	clock = clock.Add(time.Second - time.Nanosecond)
	if d := evaluate(t, c, post); d.Verdict != "deny" {
		t.Fatal(d)
	}
	clock = clock.Add(time.Nanosecond)
	if d := evaluate(t, c, post); d.Verdict != "allow" {
		t.Fatal(d)
	}
	if d := evaluate(t, compiled(t, c.Bundle()), post); d.Verdict != "allow" {
		t.Fatal("counter leaked across revisions", d)
	}
}

func TestStateCapacityFailsClosedAndExpires(t *testing.T) {
	r := deny("rate", "true")
	r.Threshold = &Threshold{Count: 2, Window: "1s", GroupBy: "ClientIP"}
	c := compiled(t, bundle(r))
	clock := time.Unix(100, 0)
	c.now = func() time.Time { return clock }
	for i := 0; i < MaxGroups; i++ {
		evaluate(t, c, Event{ClientIP: fmt.Sprint(i)})
	}
	if d, err := c.Evaluate(Event{ClientIP: "overflow"}); !errors.Is(err, ErrStateCapacity) || d.Verdict != "" {
		t.Fatal(d, err)
	}
	if len(c.groups) != MaxGroups {
		t.Fatal(len(c.groups))
	}
	if d := evaluate(t, c, Event{ClientIP: "0"}); d.Verdict != "deny" {
		t.Fatal(d)
	}
	clock = clock.Add(time.Second)
	if d := evaluate(t, c, Event{ClientIP: "overflow"}); d.Verdict != "allow" {
		t.Fatal(d)
	}
	if len(c.groups) != 1 {
		t.Fatal(len(c.groups))
	}
}

func TestRuntimeErrorsAreRedactedAndAtomic(t *testing.T) {
	r := deny("counter", "true")
	r.Threshold = &Threshold{Count: 2, Window: "1m"}
	failure := deny("bad-index", `Headers["Secret"][9] == "x"`)
	c := compiled(t, bundle(r, failure))
	_, err := c.Evaluate(Event{Body: "private-body", Headers: map[string][]string{"Secret": {"private-header"}}})
	if err == nil {
		t.Fatal("expected runtime error")
	}
	if strings.Contains(err.Error(), "private") || strings.Contains(err.Error(), "Headers") {
		t.Fatal(err)
	}
	if len(c.groups) != 0 {
		t.Fatal("counter updated on evaluation failure")
	}
}

func TestSimulationAndExplanation(t *testing.T) {
	r := deny("rate", `Body contains "private"`)
	r.Threshold = &Threshold{Count: 2, Window: "1m"}
	c := compiled(t, bundle(r))
	e := Event{Body: "private-payload"}
	ds, err := c.Simulate([]Event{e, e})
	if err != nil || len(ds) != 2 || ds[0].Verdict != "allow" || ds[1].Verdict != "deny" {
		t.Fatal(ds, err)
	}
	x, err := c.Explain(e)
	if err != nil || x.Reason != "bundle-default" {
		t.Fatal(x, err)
	}
	x, err = c.Explain(e)
	if err != nil || x.Reason != "rule-matched" {
		t.Fatal(x, err)
	}
	encoded, _ := json.Marshal(x)
	if strings.Contains(string(encoded), "private") || strings.Contains(string(encoded), "Body") {
		t.Fatal(string(encoded))
	}
	if _, err := c.Simulate(make([]Event, 10001)); err == nil {
		t.Fatal("unbounded simulation")
	}
}

func TestConcurrentThreshold(t *testing.T) {
	r := deny("rate", "true")
	r.Threshold = &Threshold{Count: 50, Window: "1h", GroupBy: "ClientIP"}
	c := compiled(t, bundle(r))
	var wg sync.WaitGroup
	results := make(chan Decision, 200)
	for i := 0; i < 200; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			d, err := c.Evaluate(Event{ClientIP: "same"})
			if err != nil {
				t.Error(err)
				return
			}
			_ = c.Bundle()
			results <- d
		}()
	}
	wg.Wait()
	close(results)
	allowed := 0
	for d := range results {
		if d.Verdict == "allow" {
			allowed++
		}
	}
	if allowed != 49 {
		t.Fatalf("allowed %d, want 49", allowed)
	}
}

func TestEventBounds(t *testing.T) {
	c := compiled(t, bundle(deny("r", "true")))
	bad := []Event{
		{Phase: "unknown"}, {Status: 99}, {Status: 600},
		{Body: strings.Repeat("x", MaxEventBytes+1)},
		{Body: strings.Repeat("x", MaxEventBytes), Headers: map[string][]string{"X": nil}},
		{Path: strings.Repeat("x", 65537)},
		{Headers: map[string][]string{strings.Repeat("x", 1025): nil}},
		{Headers: map[string][]string{"X": make([]string, 1025)}},
		{Headers: map[string][]string{"X": {strings.Repeat("x", MaxEventBytes+1)}}},
	}
	h := Event{Headers: map[string][]string{}}
	for i := 0; i < 129; i++ {
		h.Headers[fmt.Sprint(i)] = nil
	}
	bad = append(bad, h)
	for _, e := range bad {
		if d, err := c.Evaluate(e); err == nil || d.Verdict != "" {
			t.Fatal("accepted oversized/invalid event", d, err)
		}
	}
	if d := evaluate(t, c, Event{Body: strings.Repeat("x", MaxEventBytes-len("request"))}); d.Verdict != "deny" {
		t.Fatal(d)
	}
}

func TestAllGroupScopes(t *testing.T) {
	for _, field := range []string{"", "Host", "Path", "Method", "ClientIP"} {
		t.Run(field, func(t *testing.T) {
			r := deny("rate", "true")
			r.Threshold = &Threshold{Count: 2, Window: "1h", GroupBy: field}
			c := compiled(t, bundle(r))
			first := Event{Host: "one", Path: "/one", Method: "GET", ClientIP: "one"}
			second := Event{Host: "two", Path: "/two", Method: "POST", ClientIP: "two"}
			evaluate(t, c, first)
			d := evaluate(t, c, second)
			want := "allow"
			if field == "" {
				want = "deny"
			}
			if d.Verdict != want {
				t.Fatal(d)
			}
			if d := evaluate(t, c, first); d.Verdict != "deny" {
				t.Fatal(d)
			}
		})
	}
}

func TestCounterRulesDoNotShadowEachOther(t *testing.T) {
	a, b := deny("a", "true"), deny("b", "true")
	a.Threshold = &Threshold{Count: 3, Window: "1h"}
	b.Threshold = &Threshold{Count: 2, Window: "1h"}
	c := compiled(t, bundle(a, b))
	evaluate(t, c, Event{})
	if d := evaluate(t, c, Event{}); d.RuleID != "b" {
		t.Fatal(d)
	}
	if d := evaluate(t, c, Event{}); d.RuleID != "a" {
		t.Fatal(d)
	}
	if len(c.groups) != 2 {
		t.Fatal("rule counters shared")
	}
}

func TestCompileBoundsAndNormalizedDefaults(t *testing.T) {
	rules := make([]Rule, MaxRules)
	for i := range rules {
		rules[i] = deny(fmt.Sprint(i), "false")
	}
	c := compiled(t, bundle(rules...))
	if d := evaluate(t, c, Event{}); d.Verdict != "allow" {
		t.Fatal(d)
	}
	b := c.Bundle()
	if b.Rules[0].Phase != "request" || b.Rules[0].Status != 403 {
		t.Fatal("defaults not normalized")
	}
	b.Rules[0].Threshold = &Threshold{Count: 1, Window: "1ms"}
	compiled(t, b)
	b.Rules[0].Threshold.Window = "24h"
	compiled(t, b)
	for i := range rules {
		rules[i].Expression = `Body == "` + strings.Repeat("x", 2048) + `"`
	}
	if _, err := Compile(bundle(rules...)); err == nil {
		t.Fatal("accepted oversized in-memory bundle")
	}
}

func FuzzParse(f *testing.F) {
	for _, seed := range []string{
		`{"version":"1","id":"fuzz","mode":"enforce","default":"allow","rules":[]}`,
		"version: v1\nid: fuzz\nmode: enforce\ndefault: allow\nrules: []",
		"id: x\n<<: {id: y}", "rules: [*a]", "id: 'a''b'", "[", "null",
	} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		b, err := Parse(data)
		if err != nil {
			return
		}
		c, err := Compile(b)
		if err != nil {
			return
		}
		d, err := c.Evaluate(Event{})
		if err == nil && (d.Revision != c.Revision() || d.Verdict == "") {
			t.Fatal("invalid decision")
		}
	})
}

func BenchmarkEvaluate(b *testing.B) {
	p := bundle(deny("admin", `Method == "POST" && Path startsWith "/admin"`))
	c, err := Compile(p)
	if err != nil {
		b.Fatal(err)
	}
	e := Event{Method: "POST", Path: "/admin"}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := c.Evaluate(e); err != nil {
			b.Fatal(err)
		}
	}
}
