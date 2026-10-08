package rules

import (
	"testing"
	"time"

	"github.com/dreadl0ck/netcap/types"
)

func exampleRules(t *testing.T, file string) map[string]*Rule {
	t.Helper()
	config, err := LoadRulesFromFile("examples/" + file)
	if err != nil {
		t.Fatal(err)
	}
	if err := CompileRules(config); err != nil {
		t.Fatal(err)
	}
	rules := map[string]*Rule{}
	for _, r := range config.Rules {
		rules[r.Name] = r
	}
	return rules
}

func matches(t *testing.T, rule *Rule, record types.AuditRecord) bool {
	t.Helper()
	if rule == nil {
		t.Fatal("rule missing")
	}
	alert, err := EvaluateRule(rule, record)
	if err != nil {
		t.Fatal(err)
	}
	return alert != nil
}

// Operation-level DCE/RPC rules fire on the attributed request only, not on
// the Bind, the response or other operations of the same interface.
func TestDCERPCOperationRules(t *testing.T) {
	rules := exampleRules(t, "dcerpc_security.yml")
	req := func(iface, op string) *types.DCERPC {
		return &types.DCERPC{PacketTypeName: "Request", InterfaceName: iface, OperationName: op}
	}
	for _, c := range []struct {
		rule   string
		record *types.DCERPC
		want   bool
	}{
		{"DCERPC Remote Service Creation", req("SVCCTL", "RCreateServiceW"), true},
		{"DCERPC Remote Service Creation", req("SVCCTL", "ROpenSCManagerW"), false},
		{"DCERPC Remote Service Creation", &types.DCERPC{PacketTypeName: "Response", InterfaceName: "SVCCTL", OperationName: "RCreateServiceW"}, false},
		{"DCERPC Remote Service Creation", &types.DCERPC{PacketTypeName: "Bind", InterfaceName: "SVCCTL"}, false},
		{"DCERPC SAMR User Enumeration", req("SAMR", "SamrEnumerateUsersInDomain"), true},
		// LSARPC used to satisfy the SAMR-named rule.
		{"DCERPC SAMR User Enumeration", req("LSARPC", "LsarLookupNames"), false},
		{"DCERPC DRSUAPI GetNCChanges", req("DRSUAPI", "IDL_DRSGetNCChanges"), true},
		{"DCERPC DRSUAPI GetNCChanges", req("DRSUAPI", "IDL_DRSBind"), false},
		{"DCERPC Remote Registry Modification", req("WINREG", "BaseRegSetValue"), true},
		{"DCERPC Remote Registry Modification", req("WINREG", "BaseRegQueryValue"), false},
		{"DCERPC Remote Scheduled Task Creation", req("ITaskSchedulerService", "SchRpcRegisterTask"), true},
		{"DCERPC Remote Scheduled Task Creation", req("ATSVC", "NetrJobAdd"), true},
		{"DCERPC EFSR Coercion Attempt", req("EFSR", "EfsRpcOpenFileRaw"), true},
		{"DCERPC EFSR Coercion Attempt", req("", ""), false},
	} {
		if got := matches(t, rules[c.rule], c.record); got != c.want {
			t.Errorf("%s on %+v = %v, want %v", c.rule, c.record, got, c.want)
		}
	}
}

func TestCorrectedExfiltrationRuleSemantics(t *testing.T) {
	rules := exampleRules(t, "data_exfiltration.yml")
	weekdayNoon := time.Date(2026, 10, 7, 12, 0, 0, 0, time.Local).UnixNano()
	weekdayNight := time.Date(2026, 10, 7, 23, 0, 0, 0, time.Local).UnixNano()
	saturday := time.Date(2026, 10, 10, 12, 0, 0, 0, time.Local).UnixNano()
	tcp := func(ts int64) *types.TCP {
		return &types.TCP{Timestamp: ts, SrcIP: "10.0.0.5", DstIP: "93.184.216.34", PayloadSize: 6000}
	}
	afterHours := rules["After Hours Data Transfer"]
	if matches(t, afterHours, tcp(weekdayNoon)) {
		t.Fatal("after-hours rule fired during business hours")
	}
	if !matches(t, afterHours, tcp(weekdayNight)) || !matches(t, afterHours, tcp(saturday)) {
		t.Fatal("after-hours rule missed off-hours transfer")
	}
	multi := rules["DNS Multi-Question Message"]
	questions := func(n int) *types.DNS {
		d := &types.DNS{}
		for range n {
			d.Questions = append(d.Questions, &types.DNSQuestion{Name: "a.example"})
		}
		return d
	}
	if matches(t, multi, questions(1)) || !matches(t, multi, questions(6)) {
		t.Fatal("multi-question semantics")
	}
	if rules["DNS High Query Volume"] != nil {
		t.Fatal("misnamed per-message rule still shipped")
	}
}

func TestBeaconingRuleIsNamedForWhatItMeasures(t *testing.T) {
	rules := exampleRules(t, "connection_anomalies.yml")
	if rules["Potential C2 Beaconing"] != nil {
		t.Fatal("byte-ratio rule still claims to detect beaconing")
	}
	sym := rules["Symmetric External Connection"]
	c := &types.Connection{ByteRatio: 1, NumPackets: 30, SrcIP: "10.0.0.5", DstIP: "93.184.216.34", TotalSize: 5000}
	if !matches(t, sym, c) {
		t.Fatal("symmetric external connection not matched")
	}
}
