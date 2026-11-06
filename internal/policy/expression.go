package policy

import (
	"errors"
	"reflect"
	"regexp"
	"regexp/syntax"

	"github.com/expr-lang/expr"
	"github.com/expr-lang/expr/ast"
	"github.com/expr-lang/expr/conf"
	"github.com/expr-lang/expr/parser"
	"github.com/expr-lang/expr/vm"
)

var safeBuiltins = map[string]bool{"len": true, "lower": true, "upper": true, "trim": true}

const MaxEvaluationWork uint64 = 128 << 20

var ErrWorkBudget = errors.New("policy: evaluation work budget exceeded")

type expressionCost struct{ units uint64 }

func (v *expressionCost) Visit(node *ast.Node) {
	v.units++
	if n, ok := (*node).(*ast.BinaryNode); ok && n.Operator == "matches" {
		pattern := n.Right.(*ast.StringNode).Value
		re, _ := syntax.Parse(pattern, syntax.Perl)
		p, _ := syntax.Compile(re.Simplify())
		v.units += uint64(len(p.Inst))
	}
}

func programCost(source string) uint64 {
	tree, _ := new(parser.Parser).Parse(source, nil)
	v := &expressionCost{}
	ast.Walk(&tree.Node, v)
	return v.units
}

func compileExpression(source string) (*vm.Program, error) {
	if len(source) == 0 || len(source) > MaxExpressionBytes {
		return nil, errors.New("expression must contain 1..4096 bytes")
	}
	c := conf.CreateNew()
	c.MaxNodes = 256
	tree, err := new(parser.Parser).Parse(source, c)
	if err != nil {
		return nil, errors.New("invalid expression syntax")
	}
	if err := checkNode(tree.Node, 0); err != nil {
		return nil, err
	}
	opts := []expr.Option{expr.Env(Event{}), expr.AsBool(), expr.WarnOnAny(), expr.MaxNodes(256), expr.Optimize(false), expr.DisableAllBuiltins()}
	for _, name := range []string{"len", "lower", "upper", "trim"} {
		opts = append(opts, expr.EnableBuiltin(name))
	}
	program, err := expr.Compile(source, opts...)
	if err != nil {
		return nil, errors.New("expression type check failed")
	}
	return program, nil
}

// Reject iteration, dynamic calls/regex, allocation operators, arithmetic,
// variables, ranges and comprehensions before the expr optimizer can run them.
func checkNode(node ast.Node, depth int) error {
	if depth > 32 {
		return errors.New("expression nesting exceeds 32")
	}
	children := []ast.Node{}
	switch n := node.(type) {
	case *ast.NilNode, *ast.BoolNode, *ast.IntegerNode, *ast.StringNode:
	case *ast.IdentifierNode:
		field, ok := reflect.TypeOf(Event{}).FieldByName(n.Value)
		if !ok || field.PkgPath != "" {
			return errors.New("unknown expression field")
		}
	case *ast.UnaryNode:
		if n.Operator != "!" && n.Operator != "not" && n.Operator != "-" {
			return errors.New("unsupported unary operator")
		}
		children = append(children, n.Node)
	case *ast.BinaryNode:
		switch n.Operator {
		case "and", "or", "&&", "||", "==", "!=", "<", "<=", ">", ">=", "contains", "startsWith", "endsWith", "in":
		case "matches":
			pattern, ok := n.Right.(*ast.StringNode)
			if !ok || len(pattern.Value) > 256 {
				return errors.New("regex must be a literal of at most 256 bytes")
			}
			if _, err := regexp.Compile(pattern.Value); err != nil {
				return errors.New("invalid regular expression")
			}
			re, err := syntax.Parse(pattern.Value, syntax.Perl)
			if err != nil {
				return errors.New("invalid regular expression")
			}
			p, err := syntax.Compile(re.Simplify())
			if err != nil || len(p.Inst) > 4096 {
				return errors.New("regular expression program exceeds limit")
			}
		default:
			return errors.New("unsupported binary operator")
		}
		children = append(children, n.Left, n.Right)
	case *ast.MemberNode:
		if n.Method {
			return errors.New("method calls are unsupported")
		}
		children = append(children, n.Node, n.Property)
	case *ast.BuiltinNode:
		if !safeBuiltins[n.Name] {
			return errors.New("unsupported expression builtin")
		}
		children = append(children, n.Arguments...)
	case *ast.ArrayNode:
		if len(n.Nodes) > 64 {
			return errors.New("array literal exceeds 64 entries")
		}
		children = append(children, n.Nodes...)
	default:
		return errors.New("unsupported expression construct")
	}
	for _, child := range children {
		if err := checkNode(child, depth+1); err != nil {
			return err
		}
	}
	return nil
}
