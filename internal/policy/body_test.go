package policy

import "testing"

func TestRequiresBodyASTDependencies(t *testing.T) {
	for _, tc := range []struct {
		name, expression string
		want             bool
	}{
		{"direct", `Body == "blocked"`, true},
		{"normalized", `lower(trim((Body))) == "blocked"`, true},
		{"scalar-map-key", `Attributes[trim(Body)] == "x"`, true},
		{"member-key", `Headers[lower(Body)][0] == "x"`, true},
		{"array-element", `Body in ["x", "y"]`, true},
		{"constant-branch", `false && Body == "blocked"`, true},
		{"literal", `Host == "Body"`, false},
		{"regex-literal", `Host matches "Body|body"`, false},
		{"header-key", `Headers["Body"][0] == "x"`, false},
		{"escaped-key", `Attributes["B\u006fdy"] == "x"`, false},
		{"record-field", `Fields.Body == "x"`, false},
		{"lowercase-string", `lower(Host) == "body"`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := compiled(t, bundle(deny("rule", tc.expression)))
			if got := c.RequiresBody("request"); got != tc.want {
				t.Fatalf("RequiresBody=%v want %v", got, tc.want)
			}
			if c.RequiresBody("response") {
				t.Fatal("request dependency leaked to response")
			}
		})
	}
	for _, expression := range []string{`Body[0] == 97`, `$env["Body"] != ""`, `Event["Body"] != ""`} {
		if _, err := Compile(bundle(deny("unsupported-root", expression))); err == nil {
			t.Fatalf("unsupported body alias accepted: %s", expression)
		}
	}
}

func TestRequiresBodyPhasesSequencesAndDefaults(t *testing.T) {
	disabled := false
	for _, tc := range []struct {
		name              string
		rules             []Rule
		request, response bool
	}{
		{"empty-default", nil, false, false},
		{"disabled", []Rule{{ID: "off", Action: "deny", Expression: `Body == "x"`, Enabled: &disabled}}, false, false},
		{"response-allow", []Rule{{ID: "allow", Phase: "response", Action: "allow", Expression: `Body == "x"`}}, false, true},
		{"unrelated-winner", []Rule{deny("request-body", `Body == "x"`), {ID: "response-allow", Phase: "response", Action: "allow", Expression: "true", Priority: 100}}, true, false},
		{"sequence-normalized-filter", []Rule{{ID: "seq", Phase: "response", Action: "deny", Sequence: &Sequence{Name: "ordered", Window: "1m", Steps: []string{`Method == "GET"`, `lower(Body) == "x"`}}}}, false, true},
		{"sequence-filter", []Rule{{ID: "seq", Action: "allow", Expression: `Body != ""`, Sequence: &Sequence{Name: "ordered", Window: "1m", Steps: []string{"true", "true"}}}}, true, false},
		{"disabled-sequence", []Rule{{ID: "seq", Action: "deny", Enabled: &disabled, Sequence: &Sequence{Name: "ordered", Window: "1m", Steps: []string{`Body != ""`, "true"}}}}, false, false},
		{"sequence-string-only", []Rule{{ID: "seq", Action: "deny", Sequence: &Sequence{Name: "ordered", Window: "1m", Steps: []string{`Host == "Body"`, `Fields["Body"] == "x"`}}}}, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b := bundle(tc.rules...)
			b.Default = "deny"
			b.Defaults = &PhaseDefaults{Response: "allow"}
			c := compiled(t, b)
			if c.RequiresBody("request") != tc.request || c.RequiresBody("response") != tc.response {
				t.Fatal("incorrect phase dependencies")
			}
			for _, phase := range []string{"", "REQUEST", "unknown"} {
				if c.RequiresBody(phase) {
					t.Fatalf("unknown phase %q requires body", phase)
				}
			}
			copy := c.Bundle()
			if len(copy.Rules) > 0 {
				copy.Rules[0].Expression = `Body == "added"`
			}
			if c.RequiresBody("request") != tc.request || c.RequiresBody("response") != tc.response {
				t.Fatal("dependency metadata mutated through Bundle")
			}
		})
	}
	var nilPolicy *Compiled
	if nilPolicy.RequiresBody("request") {
		t.Fatal("nil policy requires body")
	}
}
