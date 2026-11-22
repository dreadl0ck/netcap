package main

import (
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

type item struct {
	ID     string `json:"id,omitempty"`
	Source string `json:"source"`
	File   string `json:"file"`
	Line   int    `json:"line"`
	Kind   string `json:"kind"`
}

func backendIDs(root string) []item {
	fset := token.NewFileSet()
	directory := filepath.Join(root, "cmd", "capture", "webui")
	entries, err := os.ReadDir(directory)
	if err != nil { panic(err) }
	files := map[string]*ast.File{}
	constants := map[string]string{}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") || strings.HasSuffix(entry.Name(), "_test.go") { continue }
		data, err := os.ReadFile(filepath.Join(directory, entry.Name()))
		if err != nil { panic(err) }
		text := string(data)
		if !strings.Contains(text, "UIMessage") && !strings.Contains(text, ".message(") && !strings.Contains(text, "chartFieldDescriptions") && !strings.Contains(text, "chartLimitationIDs") { continue }
		file, err := parser.ParseFile(fset, filepath.Join(directory, entry.Name()), data, 0)
		if err != nil { panic(err) }
		files[entry.Name()] = file
		ast.Inspect(file, func(node ast.Node) bool {
			if spec, ok := node.(*ast.ValueSpec); ok && len(spec.Names) == 1 && len(spec.Values) == 1 { if text, ok := literal(spec.Values[0]); ok { constants[spec.Names[0].Name] = text } }
			return true
		})
	}
	value := func(expr ast.Expr) string { if text, ok := literal(expr); ok { return text }; if name, ok := expr.(*ast.Ident); ok { return constants[name.Name] }; return "" }
	var result []item
	for name, file := range files {
		add := func(id, source string, node ast.Node) { if id != "" && source != "" { result = append(result, item{ID: id, Source: source, File: "cmd/capture/webui/" + name, Line: fset.Position(node.Pos()).Line, Kind: "backend-message-id"}) } }
		ast.Inspect(file, func(node ast.Node) bool {
			switch n := node.(type) {
			case *ast.ValueSpec:
				if len(n.Names) != 1 || len(n.Values) != 1 { break }
				table, ok := n.Values[0].(*ast.CompositeLit)
				if !ok { break }
				for _, element := range table.Elts {
					pair, ok := element.(*ast.KeyValueExpr)
					if !ok { continue }
					key, text := value(pair.Key), value(pair.Value)
					switch n.Names[0].Name {
					case "configOptionLabels": add("config.option."+key+".label", text, pair)
					case "chartFieldDescriptions": add("chart.field."+key+".description", text, pair)
					case "chartLimitationIDs": add(text, key, pair)
					}
				}
			case *ast.CompositeLit:
				fields := map[string]string{}
				for _, element := range n.Elts { if pair, ok := element.(*ast.KeyValueExpr); ok { if key, ok := pair.Key.(*ast.Ident); ok { fields[key.Name] = value(pair.Value) } } }
				if fields["Name"] != "" && fields["Description"] != "" && fields["Category"] != "" && name == "handlers.go" {
					add("config.option."+fields["Name"]+".description", fields["Description"], n)
					category := strings.ToLower(strings.NewReplacer("/", "-", " ", "-").Replace(fields["Category"]))
					add("config.category."+category, fields["Category"], n)
				}
				if name == "features.go" && fields["Name"] != "" && fields["Title"] != "" { add("feature."+fields["Name"]+".title", fields["Title"], n); add("feature."+fields["Name"]+".description", fields["Description"], n) }
			case *ast.CallExpr:
				if selector, ok := n.Fun.(*ast.SelectorExpr); ok && selector.Sel.Name == "message" && len(n.Args) >= 2 { add(value(n.Args[0]), value(n.Args[1]), n) }
				if function, ok := n.Fun.(*ast.Ident); ok && function.Name == "requestUIMessage" && len(n.Args) >= 3 { add(value(n.Args[1]), value(n.Args[2]), n) }
			}
			return true
		})
	}
	return result
}

func literal(expr ast.Expr) (string, bool) {
	switch value := expr.(type) {
	case *ast.BasicLit:
		if value.Kind == token.STRING {
			text, err := strconv.Unquote(value.Value)
			return text, err == nil
		}
	case *ast.BinaryExpr:
		if value.Op == token.ADD {
			left, a := literal(value.X)
			right, b := literal(value.Y)
			return left + right, a && b
		}
	}
	return "", false
}

func main() {
	root := os.Args[1]
	if len(os.Args) > 2 && os.Args[2] == "--backend-ids" { if err := json.NewEncoder(os.Stdout).Encode(backendIDs(root)); err != nil { panic(err) }; return }
	fset := token.NewFileSet()
	var result []item
	err := filepath.WalkDir(filepath.Join(root, "internal", "decoder"), func(path string, entry os.DirEntry, err error) error {
		if err != nil { return err }
		if entry.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") { return nil }
		file, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil { return err }
		add := func(expr ast.Expr, kind string) {
			if text, ok := literal(expr); ok && strings.TrimSpace(text) != "" {
				relative, _ := filepath.Rel(root, path)
				result = append(result, item{Source: text, File: filepath.ToSlash(relative), Line: fset.Position(expr.Pos()).Line, Kind: kind})
			}
		}
		ast.Inspect(file, func(node ast.Node) bool {
			switch value := node.(type) {
			case *ast.KeyValueExpr:
				if key, ok := value.Key.(*ast.Ident); ok && key.Name == "Description" { add(value.Value, "decoder-or-harvester-description") }
			case *ast.CallExpr:
				if name, ok := value.Fun.(*ast.Ident); ok && (name.Name == "newPacketDecoder" || name.Name == "newGoPacketDecoder" || name.Name == "newAccumulatingPacketDecoder") && len(value.Args) > 2 { add(value.Args[2], "packet-decoder-description") }
			}
			return true
		})
		return nil
	})
	if err != nil { panic(err) }
	if err = json.NewEncoder(os.Stdout).Encode(result); err != nil { panic(err) }
}
