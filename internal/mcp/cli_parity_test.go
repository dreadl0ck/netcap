package mcp

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestInvestigationCLICapabilityParity(t *testing.T) {
	covered := map[string]string{
		"protocol-fields": "interpret_protocol_grammar", "tls-capture": "analyze_tls_capture", "protocol-proxy": "start_protocol_listener", "exchange": "run_protocol_exchange",
		"collect-flows": "flow_receiver", "exported-flows": "query_flow_exports", "flows": "query_flows", "related": "get_related_evidence", "packet-evidence": "export_packet_evidence",
		"protocol-fuzz": "run_protocol_campaign", "protocol-server": "start_protocol_listener", "protocol-access": "run_protocol_access_matrix", "protocol-corpus": "generate_protocol_corpus",
		"protocol-generate": "generate_protocol_cases", "protocol-reproduce": "reproduce_protocol_case", "protocol-triage": "import_protocol_triage", "protocol-boundary": "run_protocol_boundary", "rules": "execute_offline_rule_pack",
		"sensor-seal": "sensor_bundle", "sensor-import": "sensor_bundle", "sensor-prune": "sensor_bundle", "deliver-alerts": "alert_delivery",
	}
	root := filepath.Join("..", "..", "cmd", "investigate")
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	found := map[string]bool{}
	for _, entry := range entries {
		if !strings.HasSuffix(entry.Name(), ".go") || strings.HasSuffix(entry.Name(), "_test.go") {
			continue
		}
		file, err := parser.ParseFile(token.NewFileSet(), filepath.Join(root, entry.Name()), nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		ast.Inspect(file, func(node ast.Node) bool {
			literal, ok := node.(*ast.CompositeLit)
			if !ok {
				return true
			}
			if literal.Type != nil {
				kind, ok := literal.Type.(*ast.SelectorExpr)
				if !ok || kind.Sel.Name != "Command" {
					return true
				}
			}
			command := false
			var name ast.Expr
			for _, element := range literal.Elts {
				kv, ok := element.(*ast.KeyValueExpr)
				if !ok {
					continue
				}
				key, ok := kv.Key.(*ast.Ident)
				if !ok {
					continue
				}
				if key.Name == "Action" || key.Name == "Commands" {
					command = true
				}
				if key.Name == "Name" {
					name = kv.Value
				}
			}
			if !command {
				return true
			}
			if value, ok := name.(*ast.BasicLit); ok && value.Kind == token.STRING {
				text, _ := strconv.Unquote(value.Value)
				if text != "investigate" {
					found[text] = true
				}
			}
			if expression, ok := name.(*ast.BinaryExpr); ok {
				if prefix, ok := expression.X.(*ast.BasicLit); ok && prefix.Value == `"sensor-"` {
					ast.Inspect(file, func(n ast.Node) bool {
						loop, ok := n.(*ast.RangeStmt)
						if !ok {
							return true
						}
						values, ok := loop.X.(*ast.CompositeLit)
						if !ok {
							return true
						}
						for _, element := range values.Elts {
							if value, ok := element.(*ast.BasicLit); ok && value.Kind == token.STRING {
								mode, _ := strconv.Unquote(value.Value)
								found["sensor-"+mode] = true
							}
						}
						return true
					})
				}
			}
			return true
		})
	}
	s, err := New(Options{BaseURL: "http://127.0.0.1:1", CarveDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	for command := range found {
		tool, ok := covered[command]
		if ok {
			if s.mcpSrv.GetTool(tool) == nil {
				t.Errorf("%s maps to missing tool %s", command, tool)
			}
		} else {
			t.Errorf("new investigation command %s requires a real MCP workflow", command)
		}
	}
	for command := range covered {
		if !found[command] {
			t.Errorf("stale CLI coverage claim %s", command)
		}
	}
}
