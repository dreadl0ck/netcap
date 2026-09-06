package rules

import (
	"fmt"
	"testing"
	"time"

	"github.com/dreadl0ck/netcap/types"
)

func modbusHuntRules(t *testing.T) map[string]*Rule {
	t.Helper()
	config, err := LoadRulesFromFile("examples/modbus_hunt.yml")
	if err != nil {
		t.Fatal(err)
	}
	rules := make(map[string]*Rule)
	for _, rule := range config.Rules {
		if rules[rule.Name] != nil || rule.Type != "Modbus" || !ValidateSeverity(rule.Severity) {
			t.Fatalf("invalid rule metadata: %+v", rule)
		}
		if len(rule.Actions) != 0 {
			t.Fatalf("hunt must not automate responses: %s", rule.Name)
		}
		wantEnabled := rule.Name == "Modbus Device Identification Request" || rule.Name == "Modbus Disruptive Diagnostic Request" || rule.Name == "Modbus Unknown Role Triage" || rule.Name == "Modbus Parse Triage"
		if rule.Enabled != wantEnabled {
			t.Fatalf("unsafe default for %s: enabled=%v", rule.Name, rule.Enabled)
		}
		rule.Enabled = true // Compile and evaluate disabled templates too.
		rules[rule.Name] = rule
	}
	if len(rules) != 12 {
		t.Fatalf("got %d rules, want 12", len(rules))
	}
	if err := CompileRules(config); err != nil {
		t.Fatal(err)
	}
	return rules
}

func modbusMatch(t *testing.T, rule *Rule, record *types.Modbus) bool {
	t.Helper()
	alert, err := EvaluateRule(rule, record)
	if err != nil {
		t.Fatal(err)
	}
	return alert != nil
}

func TestModbusWriteBaseline(t *testing.T) {
	rules := modbusHuntRules(t)
	rule := rules["Modbus Write Outside Baseline"]
	for _, fc := range []int32{5, 6, 15, 16, 22, 23} {
		t.Run(fmt.Sprint(fc), func(t *testing.T) {
			bank, start, end := "holding_registers", uint32(1000), uint32(1099)
			if fc == 5 || fc == 15 {
				bank, start, end = "coils", 100, 199
			}
			// The decoder reports FC23 writes in WriteAddress/WriteQuantity and
			// every other write function in Address/Quantity.
			setAddr := func(m *types.Modbus, v uint32) { m.Address = v }
			setQty := func(m *types.Modbus, v uint32) { m.Quantity = v }
			clearAddr := func(m *types.Modbus) { m.HasAddress = false }
			if fc == 23 {
				setAddr = func(m *types.Modbus, v uint32) { m.WriteAddress = v }
				setQty = func(m *types.Modbus, v uint32) { m.WriteQuantity = v }
				clearAddr = func(m *types.Modbus) { m.HasWriteAddress = false }
			}
			good := types.Modbus{MessageRole: "request", ParseStatus: "valid", FunctionCode: fc,
				SrcIP: "192.0.2.10", DstIP: "192.0.2.20", UnitID: 1, Bank: bank,
				Values: []uint32{1}}
			if fc == 23 {
				good.HasWriteAddress, good.WriteValues = true, []uint32{1}
				good.HasReadAddress, good.ReadAddress, good.ReadQuantity = true, 60000, 1
			} else {
				good.HasAddress = true
			}
			setAddr(&good, start)
			setQty(&good, 1)
			for _, tt := range []struct {
				name string
				edit func(*types.Modbus)
				want bool
			}{
				{"approved", func(m *types.Modbus) {}, false},
				{"upper boundary", func(m *types.Modbus) { setAddr(m, end) }, false},
				{"unapproved master", func(m *types.Modbus) { m.SrcIP = "198.51.100.9" }, true},
				{"other destination", func(m *types.Modbus) { m.DstIP = "192.0.2.21" }, true},
				{"other unit", func(m *types.Modbus) { m.UnitID = 2 }, true},
				{"other bank", func(m *types.Modbus) { m.Bank = "input_registers" }, true},
				{"below range", func(m *types.Modbus) { setAddr(m, start-1) }, true},
				{"approved master outside range", func(m *types.Modbus) { setAddr(m, end+1) }, true},
				{"missing address", clearAddr, true},
				{"zero quantity", func(m *types.Modbus) { setQty(m, 0) }, true},
				{"uint32 address overflow", func(m *types.Modbus) { setAddr(m, ^uint32(0)); setQty(m, 2) }, true},
				{"uint32 quantity overflow", func(m *types.Modbus) { setQty(m, ^uint32(0)) }, true},
				{"wire span overflow", func(m *types.Modbus) { setAddr(m, 65535); setQty(m, 2) }, true},
				{"cross-form address does not authorize", func(m *types.Modbus) {
					// An FC23 write must not be authorized by Address, nor an
					// FC5/6/15/16/22 write by WriteAddress.
					setAddr(m, end+1)
					if fc == 23 {
						m.HasAddress, m.Address, m.Quantity = true, start, 1
					} else {
						m.HasWriteAddress, m.WriteAddress, m.WriteQuantity = true, start, 1
					}
				}, true},
				{"read span does not authorize write", func(m *types.Modbus) { m.ReadAddress = start; setAddr(m, end+1) }, true},
				{"matched response", func(m *types.Modbus) {
					m.MessageRole = "response"
					m.CorrelationStatus = "matched"
					setAddr(m, end+1)
				}, false},
				{"unknown", func(m *types.Modbus) { m.MessageRole = "unknown"; setAddr(m, end+1) }, false},
				{"malformed", func(m *types.Modbus) { m.ParseStatus = "malformed"; setAddr(m, end+1) }, false},
				{"unsupported", func(m *types.Modbus) { m.ParseStatus = "unsupported"; setAddr(m, end+1) }, false},
				{"exception", func(m *types.Modbus) { m.Exception = true; setAddr(m, end+1) }, false},
			} {
				t.Run(tt.name, func(t *testing.T) {
					m := good
					tt.edit(&m)
					if got := modbusMatch(t, rule, &m); got != tt.want {
						t.Fatalf("match=%v, want %v: %+v", got, tt.want, m)
					}
				})
			}
			if fc == 15 || fc == 16 || fc == 23 {
				setQty(&good, 100)
				if modbusMatch(t, rule, &good) {
					t.Fatal("complete approved interval rejected")
				}
				setAddr(&good, start+1)
				if !modbusMatch(t, rule, &good) {
					t.Fatal("span crossing upper boundary accepted")
				}
			}
		})
	}
}

func TestModbusFileBaseline(t *testing.T) {
	rule := modbusHuntRules(t)["Modbus File Write Outside Baseline"]
	for _, tt := range []struct {
		name string
		edit func(*types.Modbus)
		want bool
	}{
		{"approved", func(m *types.Modbus) {}, false},
		{"other source", func(m *types.Modbus) { m.SrcIP = "198.51.100.9" }, true},
		{"other destination", func(m *types.Modbus) { m.DstIP = "192.0.2.21" }, true},
		{"other unit", func(m *types.Modbus) { m.UnitID = 2 }, true},
		{"other bank", func(m *types.Modbus) { m.Bank = "holding_registers" }, true},
		{"empty", func(m *types.Modbus) { m.FileRecords = nil }, true},
		{"other file", func(m *types.Modbus) { m.FileRecords[1].FileNumber = 2 }, true},
		{"reference", func(m *types.Modbus) { m.FileRecords[1].ReferenceType = 5 }, true},
		{"below", func(m *types.Modbus) { m.FileRecords[1].RecordNumber = 99 }, true},
		{"whole span", func(m *types.Modbus) { m.FileRecords[1].RecordLength = 2 }, true},
		{"zero", func(m *types.Modbus) { m.FileRecords[1].RecordLength = 0 }, true},
		{"overflow", func(m *types.Modbus) { m.FileRecords[1].RecordNumber = ^uint32(0); m.FileRecords[1].RecordLength = 2 }, true},
		{"length overflow", func(m *types.Modbus) { m.FileRecords[1].RecordLength = ^uint32(0) }, true},
		{"response", func(m *types.Modbus) {
			m.MessageRole = "response"
			m.CorrelationStatus = "matched"
			m.FileRecords = nil
		}, false},
		{"unknown", func(m *types.Modbus) { m.MessageRole = "unknown"; m.FileRecords = nil }, false},
		{"malformed", func(m *types.Modbus) { m.ParseStatus = "malformed"; m.FileRecords = nil }, false},
		{"not FC21", func(m *types.Modbus) { m.FunctionCode = 20; m.FileRecords = nil }, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			m := types.Modbus{MessageRole: "request", ParseStatus: "valid", FunctionCode: 21,
				SrcIP: "192.0.2.10", DstIP: "192.0.2.20", UnitID: 1, Bank: "file_records",
				FileRecords: []*types.ModbusFileRecord{
					{ReferenceType: 6, FileNumber: 1, RecordNumber: 100, RecordLength: 2, Values: []uint32{1, 2}},
					{ReferenceType: 6, FileNumber: 1, RecordNumber: 199, RecordLength: 1, Values: []uint32{3}},
				}}
			tt.edit(&m)
			if got := modbusMatch(t, rule, &m); got != tt.want {
				t.Fatalf("match=%v, want %v", got, tt.want)
			}
		})
	}
}

func TestModbusObservations(t *testing.T) {
	rules := modbusHuntRules(t)
	for _, tt := range []struct {
		rule string
		m    types.Modbus
	}{
		{"Modbus Device Identification Request", types.Modbus{FunctionCode: 43, MEIType: 14}},
		{"Modbus Disruptive Diagnostic Request", types.Modbus{FunctionCode: 8, HasDiagnostic: true, DiagnosticSubfunction: 4}},
		{"Modbus Disruptive Diagnostic Request", types.Modbus{FunctionCode: 8, HasDiagnostic: true, DiagnosticSubfunction: 10}},
		{"Modbus Disruptive Diagnostic Request", types.Modbus{FunctionCode: 8, HasDiagnostic: true, DiagnosticSubfunction: 1}},
	} {
		t.Run(fmt.Sprintf("%s/%d", tt.rule, tt.m.DiagnosticSubfunction), func(t *testing.T) {
			tt.m.MessageRole, tt.m.ParseStatus = "request", "valid"
			if !modbusMatch(t, rules[tt.rule], &tt.m) {
				t.Fatal("observation missing")
			}
			for _, role := range []string{"response", "unknown", ""} {
				m := tt.m
				m.MessageRole, m.CorrelationStatus = role, "matched"
				if modbusMatch(t, rules[tt.rule], &m) {
					t.Fatalf("non-request %q matched", role)
				}
			}
			for _, status := range []string{"malformed", "unsupported", ""} {
				m := tt.m
				m.ParseStatus = status
				if modbusMatch(t, rules[tt.rule], &m) {
					t.Fatalf("non-valid status %q matched", status)
				}
			}
			tt.m.MEIType, tt.m.DiagnosticSubfunction = 13, 0
			if modbusMatch(t, rules[tt.rule], &tt.m) {
				t.Fatal("ordinary diagnostic or other MEI matched")
			}
		})
	}
	for _, status := range []string{"valid", "malformed", "unsupported", ""} {
		m := &types.Modbus{MessageRole: "unknown", ParseStatus: status, FunctionCode: 6}
		if modbusMatch(t, rules["Modbus Unknown Role Triage"], m) != (status == "valid") ||
			modbusMatch(t, rules["Modbus Parse Triage"], m) != (status == "malformed" || status == "unsupported") {
			t.Fatalf("incorrect triage for %q", status)
		}
	}
	for _, role := range []string{"request", "response", "unknown", ""} {
		for _, status := range []string{"valid", "malformed", "unsupported", ""} {
			m := &types.Modbus{MessageRole: role, ParseStatus: status, FunctionCode: 3}
			if modbusMatch(t, rules["Modbus Request Baseline Collection"], m) != (role == "request" && status == "valid") {
				t.Fatalf("incorrect baseline collection for %q/%q", role, status)
			}
		}
	}
}

func TestModbusExceptionAttribution(t *testing.T) {
	rule := modbusHuntRules(t)["Modbus Correlated Illegal Address"]
	good := types.Modbus{MessageRole: "response", ParseStatus: "valid", Exception: true, ExceptionCode: 2,
		CorrelationStatus: "matched", SrcIP: "192.0.2.20", DstIP: "192.0.2.10", UnitID: 1, FunctionCode: 3}
	alert, err := EvaluateRule(rule, &good)
	if err != nil || alert == nil {
		t.Fatalf("matched exception missing: %v", err)
	}
	if alert.SrcIP != good.SrcIP || alert.DstIP != good.DstIP || rule.Threshold > 1 || rule.DistinctField != "" {
		t.Fatal("response attribution must retain controller source and initiating destination without source-grouped burst")
	}
	for _, edit := range []func(*types.Modbus){
		func(m *types.Modbus) { m.CorrelationStatus = "unmatched" },
		func(m *types.Modbus) { m.CorrelationStatus = "ambiguous" },
		func(m *types.Modbus) { m.CorrelationStatus = "expired" },
		func(m *types.Modbus) { m.ExceptionCode = 1 },
		func(m *types.Modbus) { m.Exception = false },
		func(m *types.Modbus) { m.MessageRole = "request" },
		func(m *types.Modbus) { m.ParseStatus = "malformed" },
		func(m *types.Modbus) { m.SrcIP, m.DstIP = m.DstIP, m.SrcIP },
		func(m *types.Modbus) { m.DstIP = "192.0.2.11" },
		func(m *types.Modbus) { m.UnitID = 2 },
	} {
		m := good
		edit(&m)
		if modbusMatch(t, rule, &m) {
			t.Fatalf("unattributable or unrelated response matched: %+v", m)
		}
	}
}

func TestModbusDistinctWindows(t *testing.T) {
	rules := modbusHuntRules(t)
	// The decoder reports FC1-4 reads in Address/Quantity and only FC23 reads in
	// ReadAddress/ReadQuantity. Synthesizing the wrong pairing hides rules that
	// can never fire against real records.
	readFC3 := func(m *types.Modbus) {
		m.FunctionCode, m.Bank = 3, "holding_registers"
		m.HasAddress, m.Address, m.Quantity = true, 1000, 1
	}
	readFC23 := func(m *types.Modbus) {
		m.FunctionCode, m.Bank = 23, "holding_registers"
		m.HasReadAddress, m.ReadAddress, m.ReadQuantity = true, 1000, 1
		m.HasWriteAddress, m.WriteAddress, m.WriteQuantity = true, 2000, 1
		m.WriteValues = []uint32{1}
	}
	for _, name := range []string{"Modbus Distinct Destinations", "Modbus Distinct Units",
		"Modbus Distinct Holding Read Addresses", "Modbus Distinct Read/Write Read Addresses"} {
		t.Run(name, func(t *testing.T) {
			rule := rules[name]
			engine := newDistinctEngine()
			base := int64(1700000000) * int64(time.Second)
			shape := readFC3
			if rule.DistinctField == "ReadAddress" {
				shape = readFC23
			}
			makeRecord := func(i int) *types.Modbus {
				m := &types.Modbus{Timestamp: base + int64(i), MessageRole: "request", ParseStatus: "valid",
					SrcIP: "192.0.2.10", DstIP: "192.0.2.20", UnitID: 1}
				shape(m)
				switch rule.DistinctField {
				case "DstIP":
					m.DstIP = fmt.Sprintf("192.0.2.%d", 20+i)
				case "UnitID":
					m.UnitID = int32(i + 1)
				case "Address":
					m.Address += uint32(i)
				case "ReadAddress":
					m.ReadAddress += uint32(i)
				default:
					t.Fatalf("unexpected distinct field %q", rule.DistinctField)
				}
				return m
			}
			fires := func(m *types.Modbus) bool {
				return modbusMatch(t, rule, m) && engine.checkDistinctThreshold(rule, m)
			}
			for i := 0; i < rule.DistinctThreshold-1; i++ {
				if fires(makeRecord(i)) || fires(makeRecord(i)) {
					t.Fatal("repeated polling or subthreshold cardinality fired")
				}
			}
			last := rule.DistinctThreshold - 1
			m := makeRecord(last)
			m.SrcIP = "192.0.2.11"
			if fires(m) {
				t.Fatal("sources combined")
			}
			for _, edit := range []func(*types.Modbus){
				func(m *types.Modbus) { m.MessageRole = "response"; m.CorrelationStatus = "matched" },
				func(m *types.Modbus) { m.MessageRole = "unknown" },
				func(m *types.Modbus) { m.ParseStatus = "malformed" },
			} {
				m = makeRecord(last)
				edit(m)
				if fires(m) {
					t.Fatal("non-valid-request counted")
				}
			}
			if rule.DistinctField != "DstIP" {
				m = makeRecord(last)
				m.DstIP = "192.0.2.21"
				if fires(m) {
					t.Fatal("destinations combined")
				}
			}
			if rule.DistinctField == "Address" || rule.DistinctField == "ReadAddress" {
				edits := []func(*types.Modbus){func(m *types.Modbus) { m.UnitID = 2 }}
				if rule.DistinctField == "Address" {
					edits = append(edits,
						// FC4 uses the same fields against another bank.
						func(m *types.Modbus) { m.FunctionCode, m.Bank = 4, "input_registers" },
						func(m *types.Modbus) { m.HasAddress = false },
						// An FC23 request never populates Address.
						func(m *types.Modbus) {
							m.HasAddress, m.Address, m.Quantity = false, 0, 0
							readFC23(m)
						},
					)
				} else {
					edits = append(edits,
						func(m *types.Modbus) { m.HasReadAddress = false },
						// A plain FC3 read never populates ReadAddress.
						func(m *types.Modbus) {
							m.HasReadAddress, m.ReadAddress, m.ReadQuantity = false, 0, 0
							m.HasWriteAddress, m.WriteAddress, m.WriteQuantity, m.WriteValues = false, 0, 0, nil
							readFC3(m)
						},
					)
				}
				for _, edit := range edits {
					m = makeRecord(last)
					edit(m)
					if fires(m) {
						t.Fatal("unscoped read counted")
					}
				}
			}
			if !fires(makeRecord(last)) {
				t.Fatal("distinct threshold not reached")
			}
			m = makeRecord(last + 1)
			m.Timestamp = base + int64(rule.ThresholdWindow+1)*int64(time.Second)
			if fires(m) {
				t.Fatal("expired observations counted")
			}
		})
	}
}
