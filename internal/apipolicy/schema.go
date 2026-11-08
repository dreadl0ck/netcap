package apipolicy

import (
	"bytes"
	"encoding/json"
	"io"
	"math/big"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

// ParseJSON rejects duplicate members and bounds work before schema evaluation.
func ParseJSON(data []byte) (any, error) {
	if len(data) > MaxBytes || !utf8.Valid(data) {
		return nil, ErrInvalid
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.UseNumber()
	nodes := 0
	v, err := value(d, 0, &nodes)
	if err != nil {
		return nil, ErrInvalid
	}
	if _, err := d.Token(); err != io.EOF {
		return nil, ErrInvalid
	}
	return v, nil
}

func value(d *json.Decoder, depth int, nodes *int) (any, error) {
	*nodes++
	if depth > MaxDepth || *nodes > MaxNodes {
		return nil, ErrInvalid
	}
	t, err := d.Token()
	if err != nil {
		return nil, ErrInvalid
	}
	switch x := t.(type) {
	case json.Delim:
		switch x {
		case '{':
			m := map[string]any{}
			for d.More() {
				k, err := d.Token()
				if err != nil {
					return nil, ErrInvalid
				}
				key, ok := k.(string)
				if !ok {
					return nil, ErrInvalid
				}
				if _, exists := m[key]; exists {
					return nil, ErrInvalid
				}
				v, err := value(d, depth+1, nodes)
				if err != nil {
					return nil, err
				}
				m[key] = v
			}
			end, err := d.Token()
			if err != nil || end != json.Delim('}') {
				return nil, ErrInvalid
			}
			return m, nil
		case '[':
			a := []any{}
			for d.More() {
				if len(a) >= 1024 {
					return nil, ErrInvalid
				}
				v, err := value(d, depth+1, nodes)
				if err != nil {
					return nil, err
				}
				a = append(a, v)
			}
			end, err := d.Token()
			if err != nil || end != json.Delim(']') {
				return nil, ErrInvalid
			}
			return a, nil
		default:
			return nil, ErrInvalid
		}
	case json.Number:
		if !boundedNumber(string(x)) {
			return nil, ErrInvalid
		}
	}
	return t, nil
}

func boundedNumber(s string) bool {
	if len(s) > 80 {
		return false
	}
	parts := strings.FieldsFunc(s, func(r rune) bool { return r == 'e' || r == 'E' })
	if len(parts) == 2 {
		e, err := strconv.Atoi(parts[1])
		if err != nil || e < -128 || e > 128 {
			return false
		}
	}
	return len(parts[0]) <= 64
}

type validator struct {
	schema *jsonschema.Schema
	cost   int
}

// The bounded profile is Draft 2020-12 without dynamic refs, content decoding,
// unevaluated*, or custom vocabularies. Unsupported assertions fail bootstrap.
func compileSchema(v any, openAPI30 bool) (*validator, error) {
	cost := 0
	v, err := schemaProfile(v, openAPI30, 0, &cost)
	if err != nil {
		return nil, err
	}
	c := jsonschema.NewCompiler()
	c.DefaultDraft(jsonschema.Draft2020)
	c.UseLoader(denyLoader{})
	const resource = "urn:netcap:api:schema"
	if err := c.AddResource(resource, v); err != nil {
		return nil, ErrInvalid
	}
	s, err := c.Compile(resource)
	if err != nil {
		return nil, ErrInvalid
	}
	return &validator{schema: s, cost: cost}, nil
}

type denyLoader struct{}

func (denyLoader) Load(string) (any, error) { return nil, ErrInvalid }

func schemaProfile(v any, oas30 bool, depth int, cost *int) (any, error) {
	*cost++
	if depth > 16 || *cost > 512 {
		return nil, ErrInvalid
	}
	if _, ok := v.(bool); ok {
		return v, nil
	}
	m, ok := v.(map[string]any)
	if !ok {
		return nil, ErrInvalid
	}
	out := map[string]any{}
	for k, x := range m {
		if oas30 && strings.Contains(" const $defs dependentSchemas contains minContains maxContains prefixItems if then else propertyNames ", " "+k+" ") {
			return nil, ErrInvalid
		}
		switch k {
		case "$schema":
			if x != "https://json-schema.org/draft/2020-12/schema" {
				return nil, ErrInvalid
			}
		case "readOnly", "writeOnly":
			if x != false {
				return nil, ErrInvalid
			}
		case "title", "description", "default", "examples", "deprecated", "example", "xml", "externalDocs":
			// Annotations do not change validation or synthesize missing values.
		case "format":
			// OAS binary is an annotation; it never enables file/content decoding.
			if x != "binary" {
				return nil, ErrInvalid
			}
		case "nullable":
			if !oas30 {
				return nil, ErrInvalid
			}
			if _, ok := x.(bool); !ok {
				return nil, ErrInvalid
			}
		case "type":
			valid := func(s any) bool {
				t, ok := s.(string)
				return ok && strings.Contains(" null boolean object array number integer string ", " "+t+" ")
			}
			if a, ok := x.([]any); ok {
				if oas30 || len(a) == 0 || len(a) > 7 {
					return nil, ErrInvalid
				}
				seen := map[any]bool{}
				for _, t := range a {
					if !valid(t) || seen[t] {
						return nil, ErrInvalid
					}
					seen[t] = true
				}
			} else if !valid(x) {
				return nil, ErrInvalid
			}
			out[k] = x
		case "properties", "patternProperties", "$defs", "dependentSchemas":
			children, ok := x.(map[string]any)
			if !ok {
				return nil, ErrInvalid
			}
			result := map[string]any{}
			for name, child := range children {
				if k == "patternProperties" && !safePattern(name) {
					return nil, ErrInvalid
				}
				y, err := schemaProfile(child, oas30, depth+1, cost)
				if err != nil {
					return nil, err
				}
				result[name] = y
			}
			out[k] = result
		case "items", "additionalProperties", "contains", "not", "if", "then", "else", "propertyNames":
			y, err := schemaProfile(x, oas30, depth+1, cost)
			if err != nil {
				return nil, err
			}
			out[k] = y
		case "allOf", "anyOf", "oneOf", "prefixItems":
			a, ok := x.([]any)
			if !ok || len(a) == 0 || len(a) > 16 {
				return nil, ErrInvalid
			}
			result := []any{}
			for _, child := range a {
				y, err := schemaProfile(child, oas30, depth+1, cost)
				if err != nil {
					return nil, err
				}
				result = append(result, y)
			}
			out[k] = result
		case "pattern":
			p, ok := x.(string)
			if !ok || !safePattern(p) {
				return nil, ErrInvalid
			}
			out[k] = x
		case "minimum", "maximum", "multipleOf", "exclusiveMinimum", "exclusiveMaximum":
			if oas30 && (k == "exclusiveMinimum" || k == "exclusiveMaximum") {
				if _, ok := x.(bool); !ok {
					return nil, ErrInvalid
				}
				continue
			}
			n, ok := x.(json.Number)
			if !ok || !boundedNumber(string(n)) {
				return nil, ErrInvalid
			}
			if k == "multipleOf" {
				r, ok := new(big.Rat).SetString(string(n))
				if !ok || r.Sign() <= 0 {
					return nil, ErrInvalid
				}
			}
			out[k] = x
		case "minLength", "maxLength", "minItems", "maxItems", "minProperties", "maxProperties", "minContains", "maxContains":
			n, ok := x.(json.Number)
			if !ok {
				return nil, ErrInvalid
			}
			i, err := strconv.Atoi(string(n))
			if err != nil || i < 0 || i > MaxBytes {
				return nil, ErrInvalid
			}
			out[k] = x
		case "required":
			a, ok := x.([]any)
			if !ok {
				return nil, ErrInvalid
			}
			seen := map[string]bool{}
			for _, v := range a {
				s, ok := v.(string)
				if !ok || seen[s] {
					return nil, ErrInvalid
				}
				seen[s] = true
			}
			out[k] = x
		case "uniqueItems":
			if _, ok := x.(bool); !ok {
				return nil, ErrInvalid
			}
			out[k] = x
		case "const", "enum":
			if k == "enum" {
				a, ok := x.([]any)
				if !ok || len(a) == 0 || len(a) > 64 {
					return nil, ErrInvalid
				}
			}
			out[k] = x
		default:
			return nil, ErrInvalid
		}
	}
	if oas30 {
		for _, pair := range [][2]string{{"exclusiveMinimum", "minimum"}, {"exclusiveMaximum", "maximum"}} {
			if m[pair[0]] == true {
				n, ok := m[pair[1]]
				if !ok {
					return nil, ErrInvalid
				}
				delete(out, pair[1])
				out[pair[0]] = n
			}
		}
		if m["nullable"] == true {
			t, ok := m["type"].(string)
			if !ok {
				return nil, ErrInvalid
			}
			out["type"] = []any{t, "null"}
		}
	}
	return out, nil
}

func safePattern(s string) bool {
	if len(s) > 256 {
		return false
	}
	_, err := regexp.Compile(s)
	return err == nil
}

func (v *validator) check(data []byte) error {
	instance, err := ParseJSON(data)
	if err != nil {
		return err
	}
	nodes := countNodes(instance)
	if nodes*v.cost > 262144 || int64(len(data))*int64(nodes) > 16<<20 || int64(len(data))*int64(v.cost) > 16<<20 {
		return ErrInvalid
	}
	if v.schema.Validate(instance) != nil {
		return ErrInvalid
	}
	return nil
}

func countNodes(x any) int {
	n := 1
	switch v := x.(type) {
	case map[string]any:
		for _, c := range v {
			n += countNodes(c)
		}
	case []any:
		for _, c := range v {
			n += countNodes(c)
		}
	}
	return n
}
