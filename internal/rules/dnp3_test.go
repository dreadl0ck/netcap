package rules

import (
	"testing"

	"github.com/dreadl0ck/netcap/types"
)

// Rules that ship enabled carry no site-specific values. The rest use
// documentation addresses and placeholder hours, so enabling them by default
// would alert on a site they were never written for.
var dnp3SiteDependent = map[string]bool{
	"DNP3 Control Outside Maintenance Window": true,
	"DNP3 Control From Unapproved Master":     true,
}

func dnp3HuntRules(t *testing.T) map[string]*Rule {
	t.Helper()

	config, err := LoadRulesFromFile("examples/dnp3_hunt.yml")
	if err != nil {
		t.Fatal(err)
	}

	rules := make(map[string]*Rule)

	for _, rule := range config.Rules {
		if rules[rule.Name] != nil || rule.Type != "DNP3" || !ValidateSeverity(rule.Severity) {
			t.Fatalf("invalid rule metadata: %+v", rule)
		}
		if len(rule.Actions) != 0 {
			t.Fatalf("hunt must not automate responses: %s", rule.Name)
		}
		if rule.Enabled == dnp3SiteDependent[rule.Name] {
			t.Fatalf("unsafe default for %s: enabled=%v", rule.Name, rule.Enabled)
		}

		rule.Enabled = true // Compile and evaluate disabled templates too.
		rules[rule.Name] = rule
	}

	// Every expression has to compile against the real record type. A rule that
	// never fires and a rule that was never written produce the same output.
	if err := CompileRules(config); err != nil {
		t.Fatal(err)
	}

	return rules
}

func TestDNP3HuntRulesCompile(t *testing.T) {
	if got := len(dnp3HuntRules(t)); got < 20 {
		t.Fatalf("got %d rules, want the full hunt set", got)
	}
}

func dnp3Match(t *testing.T, rule *Rule, record *types.DNP3) bool {
	t.Helper()

	alert, err := EvaluateRule(rule, record)
	if err != nil {
		t.Fatal(err)
	}

	return alert != nil
}

func dnp3Valid(fc int32) *types.DNP3 {
	return &types.DNP3{
		ParseStatus: "valid", FunctionCode: fc, FunctionCodeName: "X",
		SrcIP: "192.0.2.10", DstIP: "192.0.2.20", Source: 4, Destination: 3,
	}
}

// The premise of the whole hunt: telemetry is excluded, everything else is not.
func TestDNP3ControlPlaneRule(t *testing.T) {
	rule := dnp3HuntRules(t)["DNP3 Control Plane Activity"]

	for _, fc := range []int32{0, 1, 129, 130} {
		if dnp3Match(t, rule, dnp3Valid(fc)) {
			t.Errorf("function %d matched, but it is routine telemetry", fc)
		}
	}
	for _, fc := range []int32{2, 3, 4, 5, 6, 13, 18, 21, 25, 31} {
		if !dnp3Match(t, rule, dnp3Valid(fc)) {
			t.Errorf("function %d did not match the control plane rule", fc)
		}
	}

	// A malformed frame carries no decoded function code, so it must not be
	// reported as a control command.
	malformed := dnp3Valid(0)
	malformed.ParseStatus = "malformed"

	if dnp3Match(t, rule, malformed) {
		t.Error("malformed frame matched the control plane rule")
	}
}

func TestDNP3DirectOperateRule(t *testing.T) {
	rule := dnp3HuntRules(t)["DNP3 Direct Operate"]

	for _, fc := range []int32{5, 6} {
		if !dnp3Match(t, rule, dnp3Valid(fc)) {
			t.Errorf("function %d did not match", fc)
		}
	}
	for _, fc := range []int32{3, 4} {
		if dnp3Match(t, rule, dnp3Valid(fc)) {
			t.Errorf("function %d matched, but it is Select-Before-Operate", fc)
		}
	}
}

func TestDNP3SBORules(t *testing.T) {
	rules := dnp3HuntRules(t)

	for name, status := range map[string]string{
		"DNP3 Operate Without Select": "operate_without_select",
		"DNP3 Select Never Operated":  "select_never_operated",
	} {
		record := dnp3Valid(4)
		record.SBOStatus = status

		if !dnp3Match(t, rules[name], record) {
			t.Errorf("%s did not match SBOStatus %q", name, status)
		}

		matched := dnp3Valid(4)
		matched.SBOStatus = "matched"

		if dnp3Match(t, rules[name], matched) {
			t.Errorf("%s matched a correctly paired control", name)
		}
	}

	mismatch := rules["DNP3 Select Operate Mismatch"]
	for _, status := range []string{"sbo_object_mismatch", "sbo_sequence_mismatch", "select_expired"} {
		record := dnp3Valid(4)
		record.SBOStatus = status

		if !dnp3Match(t, mismatch, record) {
			t.Errorf("mismatch rule did not match %q", status)
		}
	}
}

func dnp3WithCROB(tcc int32) *types.DNP3 {
	record := dnp3Valid(4)
	record.Objects = []*types.DNP3Object{{
		ObjectGroup: 12, Variation: 1,
		ControlBlocks: []*types.DNP3CROB{{Index: 7, TripCloseCode: tcc}},
	}}

	return record
}

// Trip and close must not be reported as each other.
func TestDNP3BreakerRules(t *testing.T) {
	rules := dnp3HuntRules(t)
	trip, close := rules["DNP3 Breaker Trip Command"], rules["DNP3 Breaker Close Command"]

	if !dnp3Match(t, trip, dnp3WithCROB(2)) {
		t.Error("trip rule did not match a TRIP control block")
	}
	if dnp3Match(t, close, dnp3WithCROB(2)) {
		t.Error("close rule matched a TRIP control block")
	}
	if !dnp3Match(t, close, dnp3WithCROB(1)) {
		t.Error("close rule did not match a CLOSE control block")
	}
	if dnp3Match(t, trip, dnp3WithCROB(1)) {
		t.Error("trip rule matched a CLOSE control block")
	}
	// A control with no trip/close code set is neither.
	if dnp3Match(t, trip, dnp3WithCROB(0)) || dnp3Match(t, close, dnp3WithCROB(0)) {
		t.Error("a NUL trip/close code matched a breaker rule")
	}
	// No objects at all must not match either.
	if dnp3Match(t, trip, dnp3Valid(4)) {
		t.Error("trip rule matched a record with no objects")
	}
}

// The Class 0 poll returns the whole static point map; the event classes do not.
func TestDNP3ClassZeroPollRule(t *testing.T) {
	rule := dnp3HuntRules(t)["DNP3 Class 0 Integrity Poll Sweep"]

	poll := func(variation int32) *types.DNP3 {
		record := dnp3Valid(1)
		record.Objects = []*types.DNP3Object{{ObjectGroup: 60, Variation: variation}}

		return record
	}

	if !dnp3Match(t, rule, poll(0)) {
		t.Error("Class 0 poll did not match")
	}
	for _, v := range []int32{1, 2, 3} {
		if dnp3Match(t, rule, poll(v)) {
			t.Errorf("Class %d event poll matched the integrity poll rule", v)
		}
	}
	if rule.DistinctField != "Destination" || rule.DistinctThreshold != 5 {
		t.Errorf("sweep detection not configured: field=%q threshold=%d", rule.DistinctField, rule.DistinctThreshold)
	}
}

// The trust that runs upward: a malformed frame arriving from the outstation.
func TestDNP3MalformedFromOutstationRule(t *testing.T) {
	rule := dnp3HuntRules(t)["DNP3 Malformed Frame From Outstation"]

	outstation := dnp3Valid(0)
	outstation.ParseStatus, outstation.IsMaster = "malformed", false

	if !dnp3Match(t, rule, outstation) {
		t.Error("malformed frame from an outstation did not match")
	}

	master := dnp3Valid(0)
	master.ParseStatus, master.IsMaster = "malformed", true

	if dnp3Match(t, rule, master) {
		t.Error("malformed frame from the master matched the outstation rule")
	}

	healthy := dnp3Valid(129)
	if dnp3Match(t, rule, healthy) {
		t.Error("a valid frame matched the malformed rule")
	}
}

// Both halves of the identity are checked, because nothing on the wire binds
// the link address to the IP.
func TestDNP3UnapprovedMasterRule(t *testing.T) {
	rule := dnp3HuntRules(t)["DNP3 Control From Unapproved Master"]

	approved := dnp3Valid(4)
	approved.IsCriticalFunction = true

	if dnp3Match(t, rule, approved) {
		t.Error("an approved IP and link address pair alerted")
	}

	// Right IP, wrong link address.
	spoofedAddress := dnp3Valid(4)
	spoofedAddress.IsCriticalFunction, spoofedAddress.Source = true, 99

	if !dnp3Match(t, rule, spoofedAddress) {
		t.Error("an approved IP with an unknown link address did not alert")
	}

	// Right link address, wrong IP.
	spoofedIP := dnp3Valid(4)
	spoofedIP.IsCriticalFunction, spoofedIP.SrcIP = true, "198.51.100.7"

	if !dnp3Match(t, rule, spoofedIP) {
		t.Error("an unknown IP with an approved link address did not alert")
	}

	// A read from anywhere is not a control.
	read := dnp3Valid(1)
	read.SrcIP = "198.51.100.7"

	if dnp3Match(t, rule, read) {
		t.Error("a read matched a control rule")
	}
}

func TestDNP3CaptureLossRule(t *testing.T) {
	rule := dnp3HuntRules(t)["DNP3 Capture Loss"]

	marker := &types.DNP3{ParseStatus: "lost", LostBytes: -1, SrcIP: "192.0.2.10"}
	if !dnp3Match(t, rule, marker) {
		t.Error("loss marker did not match")
	}
	if dnp3Match(t, rule, dnp3Valid(1)) {
		t.Error("a decoded record matched the loss rule")
	}
}

func TestDNP3OutstationRejectionRule(t *testing.T) {
	rule := dnp3HuntRules(t)["DNP3 Outstation Rejected Request"]

	for _, set := range []func(*types.DNP3){
		func(r *types.DNP3) { r.IINNoFuncCodeSupport = true },
		func(r *types.DNP3) { r.IINObjectUnknown = true },
		func(r *types.DNP3) { r.IINParameterError = true },
	} {
		record := dnp3Valid(129)
		set(record)

		if !dnp3Match(t, rule, record) {
			t.Error("a rejection indication did not match")
		}
	}

	healthy := dnp3Valid(129)
	if dnp3Match(t, rule, healthy) {
		t.Error("a clean response matched the rejection rule")
	}
}

func TestDNP3BroadcastControlRule(t *testing.T) {
	rule := dnp3HuntRules(t)["DNP3 Broadcast Control"]

	broadcast := dnp3Valid(4)
	broadcast.IsBroadcast, broadcast.IsCriticalFunction = true, true

	if !dnp3Match(t, rule, broadcast) {
		t.Error("a broadcast control did not match")
	}

	unicast := dnp3Valid(4)
	unicast.IsCriticalFunction = true

	if dnp3Match(t, rule, unicast) {
		t.Error("a unicast control matched the broadcast rule")
	}

	broadcastRead := dnp3Valid(1)
	broadcastRead.IsBroadcast = true

	if dnp3Match(t, rule, broadcastRead) {
		t.Error("a broadcast read matched a control rule")
	}
}
