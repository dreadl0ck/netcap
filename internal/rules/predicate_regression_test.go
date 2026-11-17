package rules

import (
	"regexp"
	"strings"
	"testing"

	"github.com/dreadl0ck/netcap/internal/filter"
	"github.com/dreadl0ck/netcap/types"
	"github.com/expr-lang/expr/ast"
	"github.com/expr-lang/expr/parser"
)

type literalPatternVisitor struct{ patterns []string }

func (v *literalPatternVisitor) Visit(node *ast.Node) {
	call, ok := (*node).(*ast.CallNode)
	if !ok || len(call.Arguments) != 2 {
		return
	}
	name, ok := call.Callee.(*ast.IdentifierNode)
	if !ok || name.Value != "MatchesPattern" {
		return
	}
	if pattern, ok := call.Arguments[1].(*ast.StringNode); ok {
		v.patterns = append(v.patterns, pattern.Value)
	}
}

func TestEmbeddedPatternsRequireNonemptyEvidence(t *testing.T) {
	config, err := LoadEmbeddedRules()
	if err != nil {
		t.Fatal(err)
	}
	for _, rule := range config.Rules {
		tree, err := parser.Parse(rule.Expression)
		if err != nil {
			t.Fatal(rule.Name, err)
		}
		visitor := &literalPatternVisitor{}
		ast.Walk(&tree.Node, visitor)
		for _, pattern := range visitor.patterns {
			compiled, err := regexp.Compile(pattern)
			if err != nil {
				t.Fatal(rule.Name, err)
			}
			if compiled.MatchString("") {
				t.Errorf("rule %s has a pattern matching empty evidence: %q", rule.Name, pattern)
			}
		}
	}
}

func TestHeaderPresenceRulesHavePositiveAndNegativeControls(t *testing.T) {
	config, err := LoadEmbeddedRules()
	if err != nil {
		t.Fatal(err)
	}
	checked := 0
	headerLiteral := regexp.MustCompile(`(?:HeaderValue|HasHeaderPrefix)\(ResponseHeader, "([^"]+)"\)`)
	for _, rule := range config.Rules {
		if !strings.Contains(rule.Expression, "HeaderValue(") && !strings.Contains(rule.Expression, "HasHeaderPrefix(") {
			continue
		}
		program, err := filter.CompileExpression(rule.Expression, types.Type(types.Type_value["NC_HTTP"]))
		if err != nil {
			t.Fatal(rule.Name, err)
		}
		for _, record := range []*types.HTTP{{}, {URL: "/index?category=ordinary", ResponseHeader: map[string]string{"Server": "generic"}}} {
			match, err := filter.EvaluateExpression(program, record)
			if err != nil || match {
				t.Fatal("plain response matched presence rule", rule.Name, match, err)
			}
		}
		literal := headerLiteral.FindStringSubmatch(rule.Expression)
		if len(literal) != 2 {
			t.Fatal("missing literal header control", rule.Name)
		}
		key := strings.ToLower(literal[1])
		if strings.Contains(rule.Expression, "HasHeaderPrefix(") {
			key += "state"
		}
		value := "active"
		// Prefer a direct presence clause over a value-matching clause.
		presence := regexp.MustCompile(`HeaderValue\(ResponseHeader, "([^"]+)"\) != ""`).FindStringSubmatch(rule.Expression)
		if len(presence) == 2 {
			key = strings.ToLower(presence[1])
		}
		match, err := filter.EvaluateExpression(program, &types.HTTP{ResponseHeader: map[string]string{key: value}})
		if err != nil || !match {
			t.Fatal("header evidence was missed", rule.Name, err)
		}
		checked++
	}
	if checked != 4 {
		t.Fatal("presence control coverage changed", checked)
	}
}

func TestCommandBoundaryRegression(t *testing.T) {
	config, err := LoadEmbeddedRules()
	if err != nil {
		t.Fatal(err)
	}
	var expression string
	for _, rule := range config.Rules {
		if rule.Name == "Command Injection" {
			expression = rule.Expression
		}
	}
	if expression == "" {
		t.Fatal("missing command rule")
	}
	program, err := filter.CompileExpression(expression, types.Type(types.Type_value["NC_HTTP"]))
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		url  string
		want bool
	}{
		{"/item;x=1&cat=books", false}, {"/item;category=books", false}, {"/item;ls=ordinary", false}, {"/item;catalog", false},
		{"/item; cat /etc/passwd", true}, {"/item|ls", true}, {"/item; /bin/cat /etc/passwd", true}, {"/item;cat</etc/passwd", true},
	} {
		got, err := filter.EvaluateExpression(program, &types.HTTP{URL: tc.url})
		if err != nil || got != tc.want {
			t.Fatal(tc.url, got, tc.want, err)
		}
	}
}

func TestUnchangedSavedPredicateMigratesWithoutOverwritingCustomization(t *testing.T) {
	config, err := LoadEmbeddedRules()
	if err != nil {
		t.Fatal(err)
	}
	var base *Rule
	for _, rule := range config.Rules {
		if strings.HasPrefix(rule.Expression, `HeaderValue(ResponseHeader, "X-Application-Context") != ""`) {
			base = rule
			break
		}
	}
	if base == nil {
		t.Fatal("missing header presence predicate")
	}
	lookup := regexp.MustCompile(`HeaderValue\(ResponseHeader, "([^"]+)"\)`)
	clauses := strings.Split(lookup.ReplaceAllString(base.Expression, `ResponseHeader["$1"]`), " || ")
	legacy := *base
	legacy.Expression = `MatchesPattern(ResponseHeader["X-Application-Context"], "(?i)") || ` + clauses[1] + " || " + clauses[0]
	for _, tag := range []string{"embedded", "ruleset:local"} {
		legacy.Tags = append(append([]string(nil), legacy.Tags...), tag)
	}
	merged := MergeConfigs(&Config{Rules: []*Rule{base}}, &Config{Rules: []*Rule{&legacy}})
	if merged.Rules[0].Expression != base.Expression || legacy.Expression == base.Expression {
		t.Fatal("saved default did not migrate as a detached copy")
	}
	for _, edit := range []func(*Rule){func(r *Rule) { r.Description += " customized" }, func(r *Rule) { r.Enabled = false }, func(r *Rule) { r.Expression += " || false" }, func(r *Rule) { r.Threshold = 3 }} {
		custom := legacy
		edit(&custom)
		merged := MergeConfigs(&Config{Rules: []*Rule{base}}, &Config{Rules: []*Rule{&custom}})
		if merged.Rules[0].Expression != custom.Expression {
			t.Fatal("operator customization was overwritten")
		}
	}
}
