package policy

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func effectRule() Rule {
	return Rule{ID: "block", Expression: `Network.DstPort == 443 && TLS.JA4 == "suspicious" && Attributes["smtp.command"] == "AUTH" && RecordType == "TLS" && Fields["Version"] == "13"`, Action: "deny", Effects: []Effect{{Kind: "block_source", Duration: "1m", Target: "source", Scope: "edge"}}}
}

func effectEvent() Event {
	return Event{ClientIP: "192.0.2.7", Network: NetworkEvent{SrcIP: "192.0.2.8", DstPort: 443, Transport: "tcp", IPVersion: 4}, TLS: TLSEvent{JA4: "suspicious", Encrypted: true}, Attributes: map[string]string{"smtp.command": "AUTH"}, RecordType: "TLS", Fields: map[string]string{"Version": "13"}}
}

func TestEffectsAdmissionWinnerAndIsolation(t *testing.T) {
	b := bundle(effectRule())
	if _, err := Compile(b); err == nil {
		t.Fatal("effects accepted without admission")
	}
	c, err := CompileWithOptions(b, CompileOptions{AllowEffects: true})
	if err != nil {
		t.Fatal(err)
	}
	b.Rules[0].Effects[0].Scope = "changed"
	c.Bundle().Rules[0].Effects[0].Scope = "also-changed"
	e := effectEvent()
	d, err := c.Evaluate(e)
	if err != nil || d.Verdict != "deny" || len(d.Effects) != 1 {
		t.Fatalf("%+v %v", d, err)
	}
	i := d.Effects[0]
	if i.Source != e.Network.SrcIP || i.Scope != "edge" || i.TTL != time.Minute || i.ExpiresAt.Sub(i.IssuedAt) != time.Minute || i.ID != IntentID(i) {
		t.Fatalf("invalid intent %+v", i)
	}
	d2, _ := c.Evaluate(e)
	if d2.Effects[0].ID != i.ID {
		t.Fatal("repeated evaluation changes lease identity")
	}
	e.Network.SrcIP = "192.0.2.9"
	d3, _ := c.Evaluate(e)
	if d3.Effects[0].ID == i.ID {
		t.Fatal("different source shares lease identity")
	}
	allow := Rule{ID: "override", Expression: "true", Action: "allow", Priority: 100}
	c, err = CompileWithOptions(bundle(effectRule(), allow), CompileOptions{AllowEffects: true})
	if err != nil {
		t.Fatal(err)
	}
	d, err = c.Evaluate(e)
	if err != nil || d.Verdict != "allow" || len(d.Effects) != 0 {
		t.Fatalf("loser emitted effects: %+v %v", d, err)
	}
}

func TestEffectsMonitorSimulationAndInvalidSource(t *testing.T) {
	b := bundle(effectRule())
	b.Mode = "monitor"
	c, err := CompileWithOptions(b, CompileOptions{AllowEffects: true})
	if err != nil {
		t.Fatal(err)
	}
	e := effectEvent()
	e.Network.SrcIP = "header-controlled"
	d, err := c.Evaluate(e)
	if err != nil || d.Verdict != "would-deny" || len(d.Effects) != 0 {
		t.Fatalf("%+v %v", d, err)
	}
	b.Mode = "enforce"
	c, _ = CompileWithOptions(b, CompileOptions{AllowEffects: true})
	if _, err := c.Evaluate(e); err == nil {
		t.Fatal("invalid effect source accepted")
	}
	for _, source := range []string{"127.0.0.1", "::ffff:192.0.2.1", "fe80::1%en0", "192.0.2.0/24", "224.0.0.1"} {
		e.Network.SrcIP = source
		if _, err := c.Evaluate(e); err == nil {
			t.Fatalf("accepted %s", source)
		}
	}
	decisions, err := c.Simulate([]Event{effectEvent()})
	if err != nil || len(decisions) != 1 || len(decisions[0].Effects) != 0 {
		t.Fatalf("replay produced actionable intents: %+v %v", decisions, err)
	}
	e.Network.SrcIP = "not-a-live-source"
	if _, err := c.Simulate([]Event{e}); err != nil {
		t.Fatalf("simulation required live effect attribution: %v", err)
	}
	explanation, err := c.Explain(effectEvent())
	if err != nil || len(explanation.Decision.Effects) != 0 {
		t.Fatalf("explanation leaked effect source: %+v %v", explanation, err)
	}
}

func TestEffectsStrictReadersAndValidation(t *testing.T) {
	valid := `{"version":"1","id":"test","mode":"enforce","default":"allow","rules":[{"id":"block","expression":"true","action":"deny","effects":[{"kind":"block_source","target":"client","duration":"10s","scope":"edge"}]}]}`
	yaml := "version: '1'\nid: test\nmode: enforce\ndefault: allow\nrules:\n- id: block\n  expression: 'true'\n  action: deny\n  effects:\n  - kind: block_source\n    target: client\n    duration: 10s\n    scope: edge\n"
	for _, raw := range []string{valid, yaml} {
		b, err := Parse([]byte(raw))
		if err != nil {
			t.Fatal(err)
		}
		if _, err = CompileWithOptions(b, CompileOptions{AllowEffects: true}); err != nil {
			t.Fatal(err)
		}
	}
	for _, raw := range []string{strings.Replace(valid, `"scope":"edge"`, `"scope":"edge","url":"https://evil"`, 1), strings.Replace(valid, `"scope":"edge"`, `"scope":"edge","scope":"other"`, 1), strings.Replace(valid, `"scope"`, `"Scope"`, 1), strings.Replace(yaml, "    scope: edge", "    scope: edge\n    shell: whoami", 1)} {
		if _, err := Parse([]byte(raw)); err == nil {
			t.Fatalf("accepted %s", raw)
		}
	}
	for _, effect := range []Effect{
		{Kind: "notify", Target: "client", Duration: "1m", Scope: "edge"},
		{Kind: "block_source", Target: "header", Duration: "1m", Scope: "edge"},
		{Kind: "block_source", Target: "client", Duration: "16m", Scope: "edge"},
		{Kind: "block_source", Target: "client", Duration: "1.5s", Scope: "edge"},
		{Kind: "block_source", Target: "client", Duration: "1s", Scope: "https://evil"},
	} {
		r := effectRule()
		r.Effects = []Effect{effect}
		if _, err := CompileWithOptions(bundle(r), CompileOptions{AllowEffects: true}); err == nil {
			t.Fatalf("accepted %+v", effect)
		}
	}
}

func TestProtocolSchemaBoundsAndDiscovery(t *testing.T) {
	s := RecordSchema{RecordType: "TLS", Fields: map[string]ScalarType{"Version": IntField, "Encrypted": BoolField}}
	e := effectEvent()
	if err := s.Validate(e); err != nil {
		t.Fatal(err)
	}
	e.Fields["Version"] = "013"
	if err := s.Validate(e); err == nil {
		t.Fatal("noncanonical number accepted")
	}
	e.Fields = map[string]string{"arbitrary": "value"}
	if err := s.Validate(e); err == nil {
		t.Fatal("unknown scalar accepted")
	}
	e = effectEvent()
	e.Attributes["huge"] = strings.Repeat("a", 65537)
	c := compiled(t, bundle())
	if _, err := c.Evaluate(e); err == nil {
		t.Fatal("unbounded Attributes accepted")
	}
	e = effectEvent()
	e.Network.DstPort = 65536
	if _, err := c.Evaluate(e); err == nil {
		t.Fatal("invalid port accepted")
	}
	fields := map[string]string{}
	for _, f := range DiscoverFields() {
		fields[f.Name] = f.Type
	}
	if fields["Network.SrcIP"] != "string" || fields["TLS.Encrypted"] != "bool" || fields["Attributes"] != "map[string]string" || fields["Fields"] != "map[string]string" {
		t.Fatal(fields)
	}
	// Generic records cannot introduce arbitrary nested objects through JSON.
	var event Event
	if json.Unmarshal([]byte(`{"fields":{"nested":{"x":"y"}}}`), &event) == nil {
		t.Fatal("nested record accepted")
	}
}
