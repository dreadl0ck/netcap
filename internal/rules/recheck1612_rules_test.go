package rules

import (
	"fmt"
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
		fires, silent    string
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
	if len(legacy.Rules) != 5 {
		t.Fatalf("legacy rules %d", len(legacy.Rules))
	}
	current := map[string]*Rule{}
	for _, rule := range embedded.Rules {
		current[rule.Name] = rule
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
