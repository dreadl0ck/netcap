package firewallaudit

import (
	"errors"

	"github.com/dreadl0ck/netcap/internal/policy"
	"github.com/expr-lang/expr/ast"
	"github.com/expr-lang/expr/parser"
)

type capabilityCheck struct {
	fields     map[string]bool
	records    map[string]bool
	referenced map[string]bool
	err        error
}

func (c *capabilityCheck) Visit(node *ast.Node) {
	switch n := (*node).(type) {
	case *ast.IdentifierNode:
		if n.Value == "Body" {
			c.err = errors.New("firewallaudit: Body is not an audit capability; use discovered Fields")
		}
	case *ast.MemberNode:
		if id, ok := n.Node.(*ast.IdentifierNode); ok && id.Value == "Attributes" {
			key, ok := n.Property.(*ast.StringNode)
			if !ok || (key.Value != "audit.schema_version" && key.Value != "audit.truncated") {
				c.err = errors.New("firewallaudit: unknown audit attribute")
			}
		}
		if id, ok := n.Node.(*ast.IdentifierNode); ok && id.Value == "Fields" {
			key, ok := n.Property.(*ast.StringNode)
			if !ok || !c.fields[key.Value] {
				c.err = errors.New("firewallaudit: unknown or dynamic audit field; consult schema")
			}
		}
	case *ast.BinaryNode:
		if n.Operator != "==" && n.Operator != "!=" && n.Operator != "in" {
			return
		}
		check := func(a, b ast.Node) {
			if id, ok := a.(*ast.IdentifierNode); ok && id.Value == "RecordType" {
				var names []string
				switch value := b.(type) {
				case *ast.StringNode:
					names = append(names, value.Value)
				case *ast.ArrayNode:
					for _, node := range value.Nodes {
						if s, ok := node.(*ast.StringNode); ok {
							names = append(names, s.Value)
						}
					}
				}
				for _, name := range names {
					if !c.records[name] {
						c.err = errors.New("firewallaudit: unknown audit RecordType; consult schema")
					}
					if c.referenced != nil && n.Operator != "!=" {
						c.referenced[name] = true
					}
				}
			}
		}
		check(n.Left, n.Right)
		check(n.Right, n.Left)
	}
}

func validateCapabilities(b policy.Bundle) error {
	c := &capabilityCheck{fields: map[string]bool{}, records: map[string]bool{}}
	for _, s := range capabilities.Records {
		c.records[s.RecordType] = true
		for _, f := range s.Fields {
			c.fields[f.Path] = true
		}
	}
	for _, r := range b.Rules {
		expressions := []string{r.Expression}
		if r.Sequence != nil {
			expressions = append(expressions, r.Sequence.Steps...)
		}
		for _, source := range expressions {
			if source == "" {
				continue
			}
			tree, err := new(parser.Parser).Parse(source, nil)
			if err != nil {
				return errors.New("firewallaudit: invalid expression")
			}
			ast.Walk(&tree.Node, c)
			if c.err != nil {
				return c.err
			}
			// When record names are explicit, keys must exist in that named
			// surface, not merely in an unrelated decoder's schema.
			refs := &capabilityCheck{fields: c.fields, records: c.records, referenced: map[string]bool{}}
			ast.Walk(&tree.Node, refs)
			if len(refs.referenced) > 0 {
				fields := map[string]bool{}
				for _, s := range capabilities.Records {
					if refs.referenced[s.RecordType] {
						for _, f := range s.Fields {
							fields[f.Path] = true
						}
					}
				}
				refs.fields = fields
				ast.Walk(&tree.Node, refs)
				if refs.err != nil {
					return refs.err
				}
			}
		}
	}
	return nil
}
