package waf

import (
	"testing"
	"time"
)

func TestCRSExclusionsCannotDisableBlockingOrInjectDirectives(t *testing.T) {
	for _, id := range []int{920100, 921100, 949110, 959100, 10000001} {
		c := config("http://origin.invalid")
		c.CorazaCRS = true
		c.CRSProfile = &CRSProfile{ParanoiaLevel: 1, InboundThreshold: 5, OutboundThreshold: 4, Exclusions: []CRSExclusion{{RuleID: id, Owner: "ops", Reason: "test", ExpiresAt: time.Now().Add(time.Hour)}}}
		if ValidateConfig(c) == nil {
			t.Fatalf("non-detector %d allowed", id)
		}
	}
	for _, parameter := range []string{"q;ctl:ruleEngine=Off", "q\nSecRuleEngine Off", "/.* /", "*", "q'"} {
		c := config("http://origin.invalid")
		c.CorazaCRS = true
		c.CRSProfile = &CRSProfile{ParanoiaLevel: 1, InboundThreshold: 5, OutboundThreshold: 4, Exclusions: []CRSExclusion{{RuleID: 942100, Parameter: parameter, Owner: "ops", Reason: "test", ExpiresAt: time.Now().Add(time.Hour)}}}
		if ValidateConfig(c) == nil {
			t.Fatalf("unsafe parameter %q allowed", parameter)
		}
	}
}

func TestNestedConfigDuplicatesFailClosed(t *testing.T) {
	for _, data := range []string{
		`{"version":"netcap-firewall/v1","routes":[{"id":"a","id":"b"}]}`,
		`{"version":"netcap-firewall/v1","crsProfile":{"paranoiaLevel":1,"paranoiaLevel":4}}`,
	} {
		if _, err := LoadConfig([]byte(data)); err == nil {
			t.Fatal("duplicate security binding accepted")
		}
	}
}
