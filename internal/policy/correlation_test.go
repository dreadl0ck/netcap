package policy

import (
	"encoding/json"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestCrossProtocolNamedSequenceToFutureBlockIntent(t *testing.T) {
	r := deny("cross-protocol", "")
	r.Sequence = &Sequence{Name: "dns-tls-network", Window: "1m", GroupByFields: []string{"Attributes.tenant", "ClientIP"}, Steps: []string{
		`Protocol == "dns" && DNS.Name == "command.example"`,
		`Protocol == "tls" && TLS.ServerName == "command.example" && TLS.JA4 == "suspicious"`,
		`Protocol == "network" && Network.Transport == "tcp" && Network.DstPort == 443`,
	}}
	r.Effects = []Effect{{Kind: "block_source", Target: "source", Duration: "5m", Scope: "edge"}}
	c, err := CompileWithOptions(bundle(r), CompileOptions{AllowEffects: true})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(100, 0)
	c.now = func() time.Time { return now }
	makeEvent := func(protocol, tenant string) Event {
		return Event{Protocol: protocol, ClientIP: "192.0.2.5", Attributes: map[string]string{"tenant": tenant}, DNS: DNSEvent{Name: "command.example"}, TLS: TLSEvent{ServerName: "command.example", JA4: "suspicious"}, Network: NetworkEvent{SrcIP: "192.0.2.5", Transport: "tcp", DstPort: 443}}
	}
	copy := c.Bundle()
	copy.Rules[0].Sequence.GroupByFields[0] = "Protocol"
	r.Sequence.GroupByFields[1] = "Host"
	events := []Event{makeEvent("network", "one"), makeEvent("dns", "one"), makeEvent("tls", "other"), makeEvent("network", "one")}
	wrongPhase := makeEvent("tls", "one")
	wrongPhase.Phase = "response"
	events = append(events, wrongPhase, makeEvent("tls", "one"))
	for _, event := range events {
		d, err := c.Evaluate(event)
		if err != nil || d.Verdict != "allow" || len(d.Effects) != 0 {
			t.Fatalf("sequence gated incorrectly: %+v %v", d, err)
		}
	}
	now = now.Add(30 * time.Second)
	d, err := c.Evaluate(makeEvent("network", "one"))
	if err != nil || d.Verdict != "deny" || len(d.Effects) != 1 {
		t.Fatalf("sequence did not complete: %+v %v", d, err)
	}
	i := d.Effects[0]
	if i.Source != "192.0.2.5" || !i.ExpiresAt.Equal(now.Add(5*time.Minute)) || !i.ExpiresAt.After(now) || i.ID != IntentID(i) {
		t.Fatal(i)
	}
	if c.RequiresBody("request") || c.RequiresBody("response") {
		t.Fatal("metadata-only correlation requires body")
	}
	if c.StateStats().Groups != 0 {
		t.Fatal("completed sequence retained state")
	}
}

func TestNativeAuditRecordToNetworkCorrelation(t *testing.T) {
	r := deny("audit-network", "")
	r.Sequence = &Sequence{Name: "audit-risk", Window: "1m", GroupByFields: []string{"Attributes.tenant", "ClientIP"}, Steps: []string{`Protocol == "audit" && RecordType == "Connection" && Fields["Risk"] == "critical"`, `Protocol == "network" && Network.DstPort == 23`}}
	c := compiled(t, bundle(r))
	audit := Event{Protocol: "audit", RecordType: "Connection", Fields: map[string]string{"Risk": "critical", "Packets": "17"}, ClientIP: "192.0.2.5", Attributes: map[string]string{"tenant": "one"}}
	schema := RecordSchema{RecordType: "Connection", Fields: map[string]ScalarType{"Risk": StringField, "Packets": IntField}}
	if err := schema.Validate(audit); err != nil {
		t.Fatal(err)
	}
	if d := evaluate(t, c, audit); d.Verdict != "allow" {
		t.Fatal(d)
	}
	network := Event{Protocol: "network", Network: NetworkEvent{DstPort: 23}, ClientIP: "192.0.2.5", Attributes: map[string]string{"tenant": "other"}}
	if d := evaluate(t, c, network); d.Verdict != "allow" {
		t.Fatal("tenant correlation leaked", d)
	}
	network.Attributes["tenant"] = "one"
	if d := evaluate(t, c, network); d.Verdict != "deny" {
		t.Fatal("audit record did not gate network rule", d)
	}
}

func TestSlidingThresholdCountsSequenceCompletions(t *testing.T) {
	r := thresholdRule("sliding", 2)
	r.Expression = ""
	r.Sequence = &Sequence{Name: "dns-tls", Window: "5s", GroupBy: "ClientIP", Steps: []string{`Protocol == "dns"`, `Protocol == "tls"`}}
	c := compiled(t, bundle(r))
	start := time.Unix(100, 0)
	now := start
	c.now = func() time.Time { return now }
	for _, tc := range []struct {
		second         int
		protocol, want string
	}{{0, "dns", "allow"}, {1, "tls", "allow"}, {2, "tls", "allow"}, {5, "dns", "allow"}, {6, "tls", "deny"}, {12, "dns", "allow"}, {13, "tls", "deny"}, {30, "dns", "allow"}, {31, "tls", "allow"}} {
		now = start.Add(time.Duration(tc.second) * time.Second)
		if d := evaluate(t, c, Event{Protocol: tc.protocol}); d.Verdict != tc.want {
			t.Fatalf("completion window at %d: %+v want %s", tc.second, d, tc.want)
		}
	}
}

func TestThresholdStrictReadersValidationAndBodyMetadata(t *testing.T) {
	r := thresholdRule("sliding", 3)
	r.Threshold.Distinct = "Attributes.identity"
	r.Threshold.GroupBy = ""
	r.Threshold.GroupByFields = []string{"Attributes.tenant", "ClientIP"}
	raw, _ := json.Marshal(bundle(r))
	yaml := `version: '1'
id: exact
mode: enforce
default: allow
rules:
- id: exact
  action: deny
  expression: 'true'
  threshold:
    mode: sliding
    count: 3
    window: 10s
    distinct: Attributes.identity
    group_by_fields: [Attributes.tenant, ClientIP]
`
	for _, input := range [][]byte{raw, []byte(yaml)} {
		b, err := Parse(input)
		if err != nil {
			t.Fatal(err)
		}
		c := compiled(t, b)
		if c.RequiresBody("request") {
			t.Fatal("scalar references acquired a Body dependency")
		}
	}
	for _, input := range []string{strings.Replace(string(raw), `"mode":"sliding"`, `"mode":"sliding","mode":"fixed"`, 1), strings.Replace(string(raw), `"distinct"`, `"Distinct"`, 1), strings.Replace(yaml, "    distinct:", "    unexpected:", 1)} {
		if _, err := Parse([]byte(input)); err == nil {
			t.Fatal("non-strict threshold schema", input)
		}
	}
	for name, change := range map[string]func(*Threshold){
		"mode":            func(t *Threshold) { t.Mode = "rolling" },
		"matches":         func(t *Threshold) { t.Distinct = ""; t.Count = MaxMatches + 1 },
		"distinct-limit":  func(t *Threshold) { t.Count = MaxDistinct + 1 },
		"body-distinct":   func(t *Threshold) { t.Distinct = "Body" },
		"headers":         func(t *Threshold) { t.Distinct = "Headers.Authorization" },
		"dynamic-map":     func(t *Threshold) { t.Distinct = `Attributes[Method]` },
		"empty-key":       func(t *Threshold) { t.Distinct = "Fields." },
		"body-group":      func(t *Threshold) { t.GroupByFields = []string{"Body"} },
		"dual-grouping":   func(t *Threshold) { t.GroupBy = "ClientIP" },
		"tuple-limit":     func(t *Threshold) { t.GroupByFields = make([]string, 5) },
		"duplicate-group": func(t *Threshold) { t.GroupByFields = []string{"Host", "Host"} },
	} {
		t.Run(name, func(t *testing.T) {
			copy := r
			value := *r.Threshold
			copy.Threshold = &value
			change(copy.Threshold)
			if _, err := Compile(bundle(copy)); err == nil {
				t.Fatal("invalid threshold accepted")
			}
		})
	}
	for _, distinct := range []string{"", "Network.DstPort"} {
		one := thresholdRule("sliding", 1)
		one.Threshold.Distinct = distinct
		c := compiled(t, bundle(one))
		for i := 0; i < MaxGroups+1; i++ {
			if evaluate(t, c, Event{Method: "POST", ClientIP: strconv.Itoa(i)}).Verdict != "deny" {
				t.Fatal("count one failed")
			}
		}
		if c.StateStats().Groups != 0 {
			t.Fatal("count-one allocated state")
		}
	}
}
