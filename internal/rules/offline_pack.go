package rules

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"reflect"
	"regexp"
	"time"
	"unicode/utf8"

	"github.com/expr-lang/expr"
	"github.com/expr-lang/expr/ast"
	"github.com/expr-lang/expr/parser"
	"github.com/expr-lang/expr/vm"
	"gopkg.in/yaml.v2"

	"github.com/dreadl0ck/netcap/types"
)

const OfflineFormat = "netcap-offline-rules/v1"

// OfflinePack is deliberately incompatible with the live engine's integer threshold.
type OfflinePack struct {
	Format string        `yaml:"format" json:"format"`
	Rules  []OfflineRule `yaml:"rules" json:"rules"`
}

type OfflineRule struct {
	ID          string           `yaml:"id" json:"id"`
	Name        string           `yaml:"name" json:"name"`
	Description string           `yaml:"description" json:"description"`
	Type        string           `yaml:"type" json:"type"`
	Expression  string           `yaml:"expression" json:"expression"`
	Severity    string           `yaml:"severity" json:"severity"`
	Enabled     bool             `yaml:"enabled" json:"enabled"`
	Threshold   OfflineThreshold `yaml:"threshold" json:"threshold"`
}

type OfflineThreshold struct {
	Count   int      `yaml:"count" json:"count"`
	Window  string   `yaml:"window" json:"window"`
	GroupBy []string `yaml:"group_by" json:"groupBy"`
}

type offlineCompiled struct {
	rule    OfflineRule
	program *vm.Program
	fields  []int
	window  int64
	digest  string
}

var offlineID = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$`)

func LoadOfflinePack(path string) (*OfflinePack, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, (1<<20)+1))
	if err != nil {
		return nil, err
	}
	return ParseOfflinePack(b)
}

func ParseOfflinePack(data []byte) (*OfflinePack, error) {
	if len(data) > 1<<20 || !utf8.Valid(data) {
		return nil, fmt.Errorf("offline pack exceeds 1 MiB or contains invalid UTF-8")
	}
	var pack OfflinePack
	d := yaml.NewDecoder(bytes.NewReader(data))
	d.SetStrict(true)
	if err := d.Decode(&pack); err != nil {
		return nil, err
	}
	var extra any
	if err := d.Decode(&extra); err != io.EOF {
		return nil, fmt.Errorf("offline pack requires exactly one YAML document")
	}
	if err := ValidateOfflinePack(&pack); err != nil {
		return nil, err
	}
	return &pack, nil
}

func ValidateOfflinePack(pack *OfflinePack) error {
	_, err := compileOfflinePack(pack)
	return err
}

func offlineRecord(name string) types.AuditRecord {
	switch name {
	case "TCP":
		return &types.TCP{}
	case "UDP":
		return &types.UDP{}
	case "DNS":
		return &types.DNS{}
	case "HTTP":
		return &types.HTTP{}
	}
	return nil
}

func offlineType(name string) types.Type { return types.Type(types.Type_value["NC_"+name]) }

func compileOfflinePack(pack *OfflinePack) ([]offlineCompiled, error) {
	if pack == nil || pack.Format != OfflineFormat {
		return nil, fmt.Errorf("offline pack requires format %s", OfflineFormat)
	}
	if len(pack.Rules) == 0 || len(pack.Rules) > 64 {
		return nil, fmt.Errorf("offline pack requires 1..64 rules")
	}
	seen := map[string]bool{}
	enabled := false
	compiled := make([]offlineCompiled, 0, len(pack.Rules))
	for _, rule := range pack.Rules {
		enabled = enabled || rule.Enabled
		rule.Threshold.GroupBy = append([]string(nil), rule.Threshold.GroupBy...)
		if !offlineID.MatchString(rule.ID) || seen[rule.ID] {
			return nil, fmt.Errorf("invalid or duplicate offline rule id %q", rule.ID)
		}
		seen[rule.ID] = true
		if len(rule.Name) == 0 || len(rule.Name) > 256 || len(rule.Description) > 4096 || !utf8.ValidString(rule.Name+rule.Description) {
			return nil, fmt.Errorf("rule %s: invalid name/description", rule.ID)
		}
		if rule.Severity != "low" && rule.Severity != "medium" && rule.Severity != "high" && rule.Severity != "critical" {
			return nil, fmt.Errorf("rule %s: invalid severity", rule.ID)
		}
		record := offlineRecord(rule.Type)
		if record == nil {
			return nil, fmt.Errorf("rule %s: type must be TCP, UDP, DNS or HTTP", rule.ID)
		}
		if rule.Threshold.Count < 2 || rule.Threshold.Count > 65536 || len(rule.Threshold.GroupBy) < 1 || len(rule.Threshold.GroupBy) > 8 {
			return nil, fmt.Errorf("rule %s: count requires 2..65536 and group_by requires 1..8 fields", rule.ID)
		}
		if rule.Threshold.Window == "" {
			rule.Threshold.Window = "60s"
		}
		window, err := time.ParseDuration(rule.Threshold.Window)
		if err != nil || window <= 0 || window > 30*24*time.Hour {
			return nil, fmt.Errorf("rule %s: window requires a positive duration <=720h", rule.ID)
		}
		rule.Threshold.Window = window.String()
		c := offlineCompiled{rule: rule, window: int64(window)}
		typ := reflect.TypeOf(record).Elem()
		fields := map[string]bool{}
		for _, name := range rule.Threshold.GroupBy {
			f, ok := typ.FieldByName(name)
			if !ok || fields[name] || !offlineGroupKind(f.Type.Kind()) {
				return nil, fmt.Errorf("rule %s: group_by %q requires a unique exact Go scalar string/integer field name", rule.ID, name)
			}
			fields[name] = true
			c.fields = append(c.fields, f.Index[0])
		}
		if len(rule.Expression) == 0 || len(rule.Expression) > 4096 || !utf8.ValidString(rule.Expression) {
			return nil, fmt.Errorf("rule %s: expression requires 1..4096 UTF-8 bytes", rule.ID)
		}
		tree, err := parser.Parse(rule.Expression)
		if err != nil {
			return nil, fmt.Errorf("rule %s: %w", rule.ID, err)
		}
		v := &offlineSyntax{}
		ast.Walk(&tree.Node, v)
		if v.err != nil {
			return nil, fmt.Errorf("rule %s: %w", rule.ID, v.err)
		}
		c.program, err = expr.Compile(rule.Expression, expr.Env(offlineEnvironment(record)), expr.AsBool(), expr.DisableAllBuiltins())
		if err != nil {
			return nil, fmt.Errorf("rule %s: %w", rule.ID, err)
		}
		b, _ := json.Marshal([]any{OfflineFormat, rule})
		c.digest = offlineHash(b)
		compiled = append(compiled, c)
	}
	if !enabled {
		return nil, fmt.Errorf("offline pack requires at least one enabled rule")
	}
	return compiled, nil
}

func offlineGroupKind(k reflect.Kind) bool {
	return k == reflect.String || (k >= reflect.Int && k <= reflect.Int64) || (k >= reflect.Uint && k <= reflect.Uint64)
}

// Expressions support exact Go scalar fields, literals, literal arrays, comparisons,
// boolean operators, contains/startsWith/endsWith/in. No calls, methods, map access,
// arithmetic, regex, ranges, iteration or ambient helpers are admitted in v1.
type offlineSyntax struct{ err error }

func (v *offlineSyntax) Visit(node *ast.Node) {
	if v.err != nil {
		return
	}
	switch n := (*node).(type) {
	case *ast.IdentifierNode, *ast.IntegerNode, *ast.FloatNode, *ast.StringNode, *ast.BoolNode:
	case *ast.ArrayNode:
		for _, item := range n.Nodes {
			switch item.(type) {
			case *ast.IntegerNode, *ast.FloatNode, *ast.StringNode, *ast.BoolNode:
			default:
				v.err = fmt.Errorf("offline arrays require scalar literals")
			}
		}
	case *ast.UnaryNode:
		if n.Operator != "!" && n.Operator != "not" && n.Operator != "-" && n.Operator != "+" {
			v.err = fmt.Errorf("unsupported offline unary operator")
		}
	case *ast.BinaryNode:
		switch n.Operator {
		case "==", "!=", "<", "<=", ">", ">=", "and", "or", "&&", "||", "contains", "startsWith", "endsWith", "in":
		default:
			v.err = fmt.Errorf("unsupported offline operator %s", n.Operator)
		}
	default:
		v.err = fmt.Errorf("offline expressions reject calls, collections and non-scalar access (%T)", n)
	}
}

func offlineEnvironment(record types.AuditRecord) map[string]any {
	v := reflect.ValueOf(record).Elem()
	t := v.Type()
	env := make(map[string]any)
	for i := 0; i < v.NumField(); i++ {
		k := v.Field(i).Kind()
		if offlineGroupKind(k) || k == reflect.Bool || k == reflect.Float32 || k == reflect.Float64 {
			env[t.Field(i).Name] = v.Field(i).Interface()
		}
	}
	return env
}
