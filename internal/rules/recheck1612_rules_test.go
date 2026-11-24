package rules

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v2"

	"github.com/dreadl0ck/netcap/types"
)

// These tests evaluate the embedded rules through NewAuditReplay, the path
// WebUI and MCP post-analysis use. EvaluateScoped with a scope would hide an
// unscoped failure, which is how a broken group_by rule passed review.
func embeddedReplay(t *testing.T) (*AuditReplay, func() map[string]int) {
	t.Helper()
	config, err := LoadEmbeddedRules()
	if err != nil {
		t.Fatal(err)
	}
	var alerts []*types.Alert
	replay, err := NewAuditReplay(config, alertWriterFunc(func(a *types.Alert) error { alerts = append(alerts, a); return nil }))
	if err != nil {
		t.Fatal(err)
	}
	return replay, func() map[string]int {
		counts := map[string]int{}
		for _, a := range alerts {
			counts[a.RuleName]++
		}
		return counts
	}
}

var recheckEpoch = time.Date(2026, 11, 19, 16, 0, 0, 0, time.UTC).UnixNano()

func at(offset time.Duration) int64 { return recheckEpoch + int64(offset) }

func feed(t *testing.T, replay *AuditReplay, records ...types.AuditRecord) {
	t.Helper()
	for _, record := range records {
		if _, err := replay.Evaluate(record); err != nil {
			t.Fatalf("%T: %v", record, err)
		}
	}
}

func synTo(ts int64, src, dst string, port int32) *types.TCP {
	return &types.TCP{Timestamp: ts, SrcIP: src, DstIP: dst, DstPort: port, SrcPort: 50000, SYN: true}
}

func dnsMessage(ts int64, src, resolver, name string, qtype int32, response bool) *types.DNS {
	return &types.DNS{Timestamp: ts, SrcIP: src, DstIP: resolver, QR: response, Questions: []*types.DNSQuestion{{Name: name, Type: qtype}}}
}

const thresholdRules = "SYN Scan Detection,Multiple External Connections,DNS Beaconing Pattern,DNS Tunneling Volume"

func assertFired(t *testing.T, counts map[string]int, fired string) {
	t.Helper()
	for _, name := range strings.Split(thresholdRules, ",") {
		if name == fired && counts[name] == 0 {
			t.Errorf("%s did not fire", name)
		}
		if name != fired && counts[name] != 0 {
			t.Errorf("%s fired %d times", name, counts[name])
		}
	}
}

// V1612-3: 150 HTTPS connections and A, AAAA and HTTPS lookups (with
// responses) for 150 names within 30 seconds is ordinary browsing.
func TestEmbeddedRulesIgnoreBrowseBurst(t *testing.T) {
	replay, counts := embeddedReplay(t)
	src := "172.16.3.122"
	for i := range 150 {
		ts := at(time.Duration(i) * 200 * time.Millisecond)
		feed(t, replay, synTo(ts, src, fmt.Sprintf("1.2.%d.%d", i/250, i%250+1), 443))
		name := fmt.Sprintf("cdn-%d.example.com", i)
		for _, qtype := range []int32{1, 28, 65} {
			feed(t, replay, dnsMessage(ts, src, "8.8.8.8", name, qtype, false), dnsMessage(ts, "8.8.8.8", src, name, qtype, true))
		}
	}
	assertFired(t, counts(), "")
}

func TestEmbeddedSYNScanCountsDistinctPorts(t *testing.T) {
	t.Run("100 ports fires", func(t *testing.T) {
		replay, counts := embeddedReplay(t)
		for port := range int32(100) {
			feed(t, replay, synTo(at(time.Duration(port)*time.Millisecond), "10.0.0.5", "10.0.0.9", port+1))
		}
		assertFired(t, counts(), "SYN Scan Detection")
	})
	t.Run("one port per host across 100 hosts fires", func(t *testing.T) {
		replay, counts := embeddedReplay(t)
		for i := range int32(100) {
			feed(t, replay, synTo(at(time.Duration(i)*time.Millisecond), "10.0.0.5", fmt.Sprintf("10.0.1.%d", i+1), i+1))
		}
		assertFired(t, counts(), "SYN Scan Detection")
	})
	t.Run("150 SYNs to one port do not", func(t *testing.T) {
		replay, counts := embeddedReplay(t)
		for i := range 150 {
			feed(t, replay, synTo(at(time.Duration(i)*time.Millisecond), "10.0.0.5", "10.0.0.9", 443))
		}
		assertFired(t, counts(), "")
	})
	t.Run("three sources with 40 ports each do not", func(t *testing.T) {
		replay, counts := embeddedReplay(t)
		for _, src := range []string{"10.0.0.5", "10.0.0.6", "10.0.0.7"} {
			for port := range int32(40) {
				feed(t, replay, synTo(at(time.Duration(port)*time.Millisecond), src, "10.0.0.9", port+1))
			}
		}
		assertFired(t, counts(), "")
	})
}

func TestEmbeddedMultipleExternalConnections(t *testing.T) {
	replay, counts := embeddedReplay(t)
	for i := range 80 {
		feed(t, replay, synTo(at(time.Duration(i)*time.Millisecond), "10.0.0.5", fmt.Sprintf("1.2.3.%d", i+1), 443))
	}
	assertFired(t, counts(), "")
	for i := range 50 {
		feed(t, replay, synTo(at(time.Second+time.Duration(i)*time.Millisecond), "10.0.0.5", fmt.Sprintf("1.2.4.%d", i+1), 2323))
	}
	assertFired(t, counts(), "Multiple External Connections")
}

func TestEmbeddedDNSBeaconing(t *testing.T) {
	t.Run("100 queries for one name from one host fire", func(t *testing.T) {
		replay, counts := embeddedReplay(t)
		for i := range 100 {
			ts := at(time.Duration(i) * 5 * time.Second)
			feed(t, replay, dnsMessage(ts, "10.0.0.5", "8.8.8.8", "c2.example.org", 1, false), dnsMessage(ts, "8.8.8.8", "10.0.0.5", "c2.example.org", 1, true))
		}
		assertFired(t, counts(), "DNS Beaconing Pattern")
	})
	t.Run("the same queries split across four hosts do not", func(t *testing.T) {
		replay, counts := embeddedReplay(t)
		for i := range 100 {
			feed(t, replay, dnsMessage(at(time.Duration(i)*5*time.Second), fmt.Sprintf("10.0.0.%d", i%4+1), "8.8.8.8", "c2.example.org", 1, false))
		}
		assertFired(t, counts(), "")
	})
}

func TestEmbeddedDNSTunnelingNeedsLongNames(t *testing.T) {
	replay, counts := embeddedReplay(t)
	for i := range 250 {
		name := fmt.Sprintf("%050x.t.example.net", i)
		feed(t, replay, dnsMessage(at(time.Duration(i)*100*time.Millisecond), "10.0.0.5", "8.8.8.8", name, 16, false))
	}
	assertFired(t, counts(), "DNS Tunneling Volume")
}

func TestEmbeddedSecretRulesSeparateSNMP(t *testing.T) {
	for _, tc := range []struct {
		service, password string
		fires, silent     string
	}{
		{"SNMP", "public", "SNMP Default Community String", "Cleartext Password Captured,SNMP Community String Observed"},
		{"SNMP", "s3cr3t", "SNMP Community String Observed", "Cleartext Password Captured,SNMP Default Community String"},
		{"FTP", "hunter2", "Cleartext Password Captured", "SNMP Community String Observed,SNMP Default Community String"},
	} {
		replay, counts := embeddedReplay(t)
		feed(t, replay, &types.Secret{Timestamp: at(0), Service: tc.service, Password: tc.password})
		got := counts()
		if got[tc.fires] == 0 {
			t.Errorf("%s/%s: %s did not fire: %v", tc.service, tc.password, tc.fires, got)
		}
		for _, name := range strings.Split(tc.silent, ",") {
			if got[name] != 0 {
				t.Errorf("%s/%s: %s fired", tc.service, tc.password, name)
			}
		}
	}
}

// A rules folder written by a WebUI save holds the old default verbatim; it
// overrides the embedded rule by name and would keep the false positives.
func TestSavedLegacyDefaultsLoadCurrentDefinition(t *testing.T) {
	embedded, err := LoadEmbeddedRules()
	if err != nil {
		t.Fatal(err)
	}
	var legacy Config
	if err := yaml.Unmarshal(legacyDefaultsYAML, &legacy); err != nil {
		t.Fatal(err)
	}
	current := map[string]*Rule{}
	for _, rule := range embedded.Rules {
		current[rule.Name] = rule
	}
	// Every entry must name a shipped rule and differ from it, or it either
	// never migrates or turns every saved copy back into the default.
	for _, old := range legacy.Rules {
		if current[old.Name] == nil || bytes.Equal(legacyComparable(old), legacyComparable(current[old.Name])) && old.Enabled == current[old.Name].Enabled {
			t.Fatalf("legacy entry %q has no distinct current definition", old.Name)
		}
	}
	if len(legacy.Rules) < 42 {
		t.Fatalf("legacy rules %d: superseded definitions were dropped", len(legacy.Rules))
	}
	for _, old := range legacy.Rules {
		saved := *old
		saved.Enabled = false // the operator disabled it; that choice survives
		saved.Tags = append(saved.Tags, "ruleset:custom")
		merged := MergeConfigs(embedded, &Config{Rules: []*Rule{&saved}})
		var got *Rule
		for _, rule := range merged.Rules {
			if rule.Name == old.Name {
				got = rule
			}
		}
		if got == nil || got.Expression != current[old.Name].Expression || got.DistinctField != current[old.Name].DistinctField ||
			len(got.GroupBy) != len(current[old.Name].GroupBy) || got.Enabled {
			t.Fatalf("%s not migrated: %+v", old.Name, got)
		}
	}
	// An edited copy stays the operator's.
	edited := *legacy.Rules[0]
	edited.Threshold = 7
	merged := MergeConfigs(embedded, &Config{Rules: []*Rule{&edited}})
	for _, rule := range merged.Rules {
		if rule.Name == edited.Name && rule.Threshold != 7 {
			t.Fatal("edited override was replaced")
		}
	}
}

// capture -rules DIR loads a folder on its own, without the embedded merge
// that migrates saved defaults; it must migrate them the same way.
func TestRulesDirectoryMigratesSavedDefaults(t *testing.T) {
	var legacy Config
	if err := yaml.Unmarshal(legacyDefaultsYAML, &legacy); err != nil {
		t.Fatal(err)
	}
	embedded, err := LoadEmbeddedRules()
	if err != nil {
		t.Fatal(err)
	}
	current := map[string]*Rule{}
	for _, rule := range embedded.Rules {
		current[rule.Name] = rule
	}
	load := func(rules ...*Rule) map[string]*Rule {
		t.Helper()
		data, err := yaml.Marshal(&Config{Rules: rules})
		if err != nil {
			t.Fatal(err)
		}
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "saved.yml"), data, 0600); err != nil {
			t.Fatal(err)
		}
		engine, err := NewEngine(dir, &MockAlertWriter{})
		if err != nil {
			t.Fatal(err)
		}
		names := map[string]*Rule{}
		for _, rule := range engine.config.Rules {
			names[rule.Name] = rule
		}
		return names
	}
	// One folder per entry: a rule superseded twice has two entries.
	for _, old := range legacy.Rules {
		want := current[old.Name]
		if got := load(old)[old.Name]; got == nil || got.Expression != want.Expression || !reflect.DeepEqual(got.GroupBy, want.GroupBy) ||
			got.Threshold != want.Threshold || got.DistinctField != want.DistinctField || got.FoldCase != want.FoldCase {
			t.Fatalf("%s not migrated: %+v", old.Name, got)
		}
	}
	custom := &Rule{Name: "Operator Rule", Type: "TCP", Expression: "SYN", Severity: "low", Enabled: true}
	names := load(append(retiredDefinitions(t), custom)...)
	for _, old := range retiredDefinitions(t) {
		if names[old.Name] != nil {
			t.Fatalf("retired default %s still loads", old.Name)
		}
	}
	if names[custom.Name] == nil {
		t.Fatal("operator rule dropped")
	}
}

func retiredDefinitions(t *testing.T) []*Rule {
	t.Helper()
	var retired Config
	if err := yaml.Unmarshal(retiredDefaultsYAML, &retired); err != nil {
		t.Fatal(err)
	}
	return retired.Rules
}

// A threshold without grouping counts every host in the capture together, so
// one busy network reaches it with no single actor behaving abnormally.
func TestEmbeddedThresholdsAreGrouped(t *testing.T) {
	embedded, err := LoadEmbeddedRules()
	if err != nil {
		t.Fatal(err)
	}
	for _, rule := range embedded.Rules {
		if rule.Threshold > 1 && len(rule.GroupBy) == 0 && rule.DistinctField == "" {
			t.Errorf("%s counts globally", rule.Name)
		}
	}
}

// Busy networks reach global counts with no single actor misbehaving; the
// regrouped rules must stay quiet there and still fire for one actor.
func TestEmbeddedThresholdsCountPerActor(t *testing.T) {
	type check struct {
		rule        string
		busy, actor func(i int) types.AuditRecord
		n           int
	}
	checks := []check{
		{"SSH Brute Force", func(i int) types.AuditRecord {
			return synTo(at(time.Duration(i)*time.Second), fmt.Sprintf("10.0.%d.%d", i/200, i%200+1), fmt.Sprintf("10.1.0.%d", i%50+1), 22)
		}, func(i int) types.AuditRecord {
			return synTo(at(time.Duration(i)*time.Second), "198.51.100.9", "10.1.0.1", 22)
		}, 60},
		{"SYN Flood Detection", func(i int) types.AuditRecord {
			return synTo(at(time.Duration(i)*time.Microsecond), "203.0.113.1", fmt.Sprintf("10.2.%d.%d", i/250, i%250+1), 443)
		}, func(i int) types.AuditRecord {
			return synTo(at(time.Duration(i)*time.Microsecond), fmt.Sprintf("203.0.%d.%d", i/250, i%250+1), "10.2.0.1", 443)
		}, 10_000},
		{"ICMP Echo Request Detected", func(i int) types.AuditRecord {
			return &types.ICMPv4{Timestamp: at(time.Duration(i) * 100 * time.Millisecond), SrcIP: fmt.Sprintf("10.3.0.%d", i%250+1), DstIP: "10.3.1.1", IsEchoRequest: true, TypeCode: 8}
		}, func(i int) types.AuditRecord {
			return &types.ICMPv4{Timestamp: at(time.Duration(i) * 100 * time.Millisecond), SrcIP: "10.3.0.9", DstIP: fmt.Sprintf("10.3.2.%d", i+1), IsEchoRequest: true, TypeCode: 8}
		}, 60},
		{"HTTP 404 Scanning", func(i int) types.AuditRecord {
			return &types.HTTP{Timestamp: at(time.Duration(i) * time.Second), SrcIP: fmt.Sprintf("10.4.0.%d", i%200+1), DstIP: "10.4.1.1", StatusCode: 404, Method: "GET", URL: "/x"}
		}, func(i int) types.AuditRecord {
			return &types.HTTP{Timestamp: at(time.Duration(i) * time.Second), SrcIP: "10.4.0.9", DstIP: "10.4.1.1", StatusCode: 404, Method: "GET", URL: fmt.Sprintf("/x%d", i)}
		}, 120},
	}
	for _, c := range checks {
		t.Run(c.rule, func(t *testing.T) {
			replay, counts := embeddedReplay(t)
			for i := range c.n {
				feed(t, replay, c.busy(i))
			}
			if counts()[c.rule] != 0 {
				t.Fatalf("busy network fired %s %d times", c.rule, counts()[c.rule])
			}
			replay, counts = embeddedReplay(t)
			for i := range c.n {
				feed(t, replay, c.actor(i))
			}
			if counts()[c.rule] == 0 {
				t.Fatalf("single actor did not fire %s", c.rule)
			}
		})
	}
}

// Single-match rules that fired on ordinary traffic: CORS preflight, an LDAP
// bind, any DCERPC endpoint mapper call, or one large SMB segment.
func TestRewrittenSingleMatchRulesNeedTheirBehaviour(t *testing.T) {
	type check struct {
		rule         string
		benign, real []types.AuditRecord
	}
	var preflight, optionsScan, oneAccount, enumeration, oneFile, encryption []types.AuditRecord
	for i := range 40 {
		ts := at(time.Duration(i) * time.Second)
		preflight = append(preflight, &types.HTTP{Timestamp: ts, SrcIP: "10.5.0.2", DstIP: "10.5.0.1", Method: "OPTIONS", URL: fmt.Sprintf("/api/%d", i),
			RequestHeader: map[string]string{"Access-Control-Request-Method": "POST"}})
		optionsScan = append(optionsScan, &types.HTTP{Timestamp: ts, SrcIP: "10.5.0.3", DstIP: "10.5.0.1", Method: "OPTIONS", URL: fmt.Sprintf("/x%d", i)})
		oneAccount = append(oneAccount, &types.LDAP{Timestamp: ts, SrcIP: "10.6.0.2", DstIP: "10.6.0.1", Operation: "SearchRequest", SearchAccount: "svc-backup"})
		enumeration = append(enumeration, &types.LDAP{Timestamp: ts, SrcIP: "10.6.0.3", DstIP: "10.6.0.1", Operation: "SearchRequest", SearchAccount: fmt.Sprintf("user%d", i)})
	}
	for i := range 300 {
		ts := at(time.Duration(i) * 100 * time.Millisecond)
		oneFile = append(oneFile, &types.SMB{Timestamp: ts, SrcIP: "10.7.0.2", DstIP: "10.7.0.1", Action: "WRITE", FileID: 7})
		encryption = append(encryption, &types.SMB{Timestamp: ts, SrcIP: "10.7.0.3", DstIP: "10.7.0.1", Action: "WRITE", FileID: uint64(i + 1)})
	}
	epm := []types.AuditRecord{&types.DCERPC{Timestamp: at(0), SrcIP: "10.8.0.2", DstIP: "10.8.0.1", DstPort: 135, InterfaceName: "EPM", PacketTypeName: "Bind"}}
	wmi := []types.AuditRecord{&types.DCERPC{Timestamp: at(0), SrcIP: "10.8.0.3", DstIP: "10.8.0.1", DstPort: 49667, InterfaceName: "IWbemServices", PacketTypeName: "Request"}}
	for _, c := range []check{
		{"HTTP OPTIONS Enumeration", preflight, optionsScan},
		{"LDAP Enumeration", oneAccount, enumeration},
		{"High Volume SMB Write", oneFile, encryption},
		{"WMI Activity", epm, wmi},
	} {
		t.Run(c.rule, func(t *testing.T) {
			replay, counts := embeddedReplay(t)
			feed(t, replay, c.benign...)
			if n := counts()[c.rule]; n != 0 {
				t.Fatalf("ordinary traffic fired %d times", n)
			}
			replay, counts = embeddedReplay(t)
			feed(t, replay, c.real...)
			if counts()[c.rule] == 0 {
				t.Fatal("behaviour did not fire")
			}
		})
	}
	embedded, err := LoadEmbeddedRules()
	if err != nil {
		t.Fatal(err)
	}
	for _, rule := range embedded.Rules {
		for _, retired := range retiredDefinitions(t) {
			if rule.Name == retired.Name {
				t.Errorf("retired rule %s still ships", rule.Name)
			}
		}
	}
	if len(retiredDefinitions(t)) != 3 {
		t.Fatal("retired list changed")
	}
}

// Resolvers using DNS 0x20 randomize query-name case; the beacon is still one name.
func TestDNSBeaconingIgnoresNameCase(t *testing.T) {
	replay, counts := embeddedReplay(t)
	for i := range 100 {
		name := []byte("beacon.example.com")
		for j := range name {
			if (i>>(j%7))&1 == 1 && name[j] >= 'a' && name[j] <= 'z' {
				name[j] -= 'a' - 'A'
			}
		}
		feed(t, replay, dnsMessage(at(time.Duration(i)*5*time.Second), "10.9.0.2", "8.8.8.8", string(name), 1, false))
	}
	if counts()["DNS Beaconing Pattern"] != 1 {
		t.Fatalf("case variants split the beacon: %v", counts())
	}
}

// v0.16.15 disables inventory rules. A saved copy still at the old default
// (enabled) follows the new default; an operator's own choice survives.
func TestSavedDefaultFollowsNewlyDisabledDefault(t *testing.T) {
	embedded, err := LoadEmbeddedRules()
	if err != nil {
		t.Fatal(err)
	}
	var legacy Config
	if err := yaml.Unmarshal(legacyDefaultsYAML, &legacy); err != nil {
		t.Fatal(err)
	}
	var old *Rule
	for _, rule := range legacy.Rules {
		if rule.Name == "WPAD Query Detection" && rule.Enabled {
			copy := *rule
			old = &copy
		}
	}
	if old == nil {
		t.Fatal("fixture missing")
	}
	for _, savedEnabled := range []bool{true, false} {
		saved := *old
		saved.Enabled = savedEnabled
		for _, rule := range MergeConfigs(embedded, &Config{Rules: []*Rule{&saved}}).Rules {
			if rule.Name == saved.Name && rule.Enabled {
				t.Fatalf("saved enabled=%v: WPAD Query Detection still enabled", savedEnabled)
			}
		}
	}
}
