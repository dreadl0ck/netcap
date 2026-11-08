package docsvalidation

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/dreadl0ck/netcap/internal/rules"
	"github.com/dreadl0ck/netcap/types"
	"gopkg.in/yaml.v2"
)

var root = filepath.Join("..", "..")

func examples(t *testing.T) map[string]*rules.Rule {
	t.Helper()
	result := map[string]*rules.Rule{}
	for _, name := range []string{"RULES_ENGINE.md", "s7-threat-hunt-AA26-231A.md", "FIREWALL_RESPONSE_ACTIONS.md"} {
		data, err := os.ReadFile(filepath.Join(root, "docs", name))
		if err != nil {
			t.Fatal(err)
		}
		for _, match := range regexp.MustCompile("(?ms)^```yaml\\n(.*?)^```").FindAllSubmatch(data, -1) {
			if !strings.HasPrefix(strings.TrimSpace(string(match[1])), "rules:") {
				continue
			}
			var config rules.Config
			if err := yaml.Unmarshal(match[1], &config); err != nil {
				// The first field-reference block explicitly illustrates placeholders.
				if strings.Contains(string(match[1]), "name: Rule_Name") {
					continue
				}
				t.Fatalf("%s: %v", name, err)
			}
			if err := rules.CompileRules(&config); err != nil {
				t.Fatalf("%s: %v", name, err)
			}
			for _, rule := range config.Rules {
				result[rule.Name] = rule
			}
		}
	}
	return result
}

func TestConcreteDocumentationRules(t *testing.T) {
	if got := len(examples(t)); got < 15 {
		t.Fatalf("only %d concrete rules found", got)
	}
}

func TestDocumentationRuleControls(t *testing.T) {
	all := examples(t)
	for _, test := range []struct {
		name   string
		record types.AuditRecord
		want   bool
	}{
		{"Documentation UDP Observation", &types.UDP{DstPort: 9999}, true},
		{"Documentation UDP Observation", &types.UDP{DstPort: 53}, false},
		{"TCP_SYN_Observation", &types.TCP{SYN: true}, true},
		{"TCP_SYN_Observation", &types.TCP{SYN: true, ACK: true}, false},
		{"ICMP_Echo_Request", &types.ICMPv4{Type: 8}, true},
		{"ICMP_Echo_Request", &types.ICMPv4{Type: 0}, false},
		{"S7comm Horizontal Enumeration", &types.Connection{SrcIP: "192.0.2.11", DstPort: "102"}, true},
		{"S7comm Horizontal Enumeration", &types.Connection{SrcIP: "192.0.2.11", DstPort: "443"}, false},
		{"Suspicious_HTTP_Upload", &types.HTTP{Method: "POST", ReqContentLength: 20000000, UserAgent: "curl/8.10.1"}, true},
		{"Suspicious_HTTP_Upload", &types.HTTP{Method: "POST", ReqContentLength: 20000000, UserAgent: "Mozilla/5.0"}, false},
	} {
		rule := all[test.name]
		if rule == nil || !rule.Enabled {
			t.Fatalf("missing or disabled concrete rule: %s", test.name)
		}
		alert, err := rules.EvaluateRule(rule, test.record)
		if err != nil {
			t.Fatal(err)
		}
		if (alert != nil) != test.want {
			t.Errorf("%s: record %#v: match=%v, want %v", test.name, test.record, alert != nil, test.want)
		}
	}
}

func TestProtoFieldExcerptsMatchSchema(t *testing.T) {
	schema, err := os.ReadFile(filepath.Join(root, "types", "netcap.proto"))
	if err != nil {
		t.Fatal(err)
	}
	doc, err := os.ReadFile(filepath.Join(root, "docs", "industrial-control-systems.md"))
	if err != nil {
		t.Fatal(err)
	}
	messages := regexp.MustCompile(`(?s)message (\w+)\s*\{([^}]+)\}`)
	fields := regexp.MustCompile(`(?m)^\s*((?:repeated )?\w+)\s+(\w+)\s*=\s*(\d+)\s*;`)
	checked := 0
	for _, excerpt := range messages.FindAllSubmatch(doc, -1) {
		canonical := regexp.MustCompile(`(?s)message ` + string(excerpt[1]) + `\s*\{([^}]+)\}`).FindSubmatch(schema)
		if canonical == nil {
			t.Fatalf("unknown message %s", excerpt[1])
		}
		for _, field := range fields.FindAllSubmatch(excerpt[2], -1) {
			definition := regexp.MustCompile(`(?m)^\s*` + string(field[1]) + `\s+` + string(field[2]) + `\s*=\s*` + string(field[3]) + `\s*;`)
			if !definition.Match(canonical[1]) {
				t.Errorf("%s: field %s disagrees with schema", excerpt[1], field[0])
			}
			checked++
		}
	}
	if checked != 9 {
		t.Fatalf("checked %d fields, want 9", checked)
	}
}
