package mcp

import (
	"encoding/json"
	"reflect"
	"strings"

	mcplib "github.com/mark3labs/mcp-go/mcp"
)

// The SDK reflects []byte as integer arrays; encoding/json uses base64 strings.
// Use the actual wire representation, including nullable slices/maps.
func wireInputSchema[T any]() mcplib.ToolOption {
	return func(tool *mcplib.Tool) { tool.RawInputSchema, _ = json.Marshal(wireSchema(reflect.TypeFor[T]())) }
}

func wireSchema(t reflect.Type) map[string]any {
	if t == reflect.TypeFor[json.RawMessage]() {
		return map[string]any{}
	}
	if t.Kind() == reflect.Pointer {
		return map[string]any{"anyOf": []any{wireSchema(t.Elem()), map[string]any{"type": "null"}}}
	}
	switch t.Kind() {
	case reflect.Struct:
		props := map[string]any{}
		required := []string{}
		for i := 0; i < t.NumField(); i++ {
			f := t.Field(i)
			if f.PkgPath != "" {
				continue
			}
			tag := strings.Split(f.Tag.Get("json"), ",")
			if tag[0] == "-" {
				continue
			}
			name := tag[0]
			if name == "" {
				name = f.Name
			}
			property := wireSchema(f.Type)
			if len(tag) > 1 && tag[len(tag)-1] == "string" {
				property = map[string]any{"type": "string"}
			}
			enums := []string{}
			for _, option := range strings.Split(f.Tag.Get("jsonschema"), ",") {
				if value, ok := strings.CutPrefix(option, "enum="); ok {
					enums = append(enums, value)
				}
			}
			if len(enums) > 0 {
				property["enum"] = enums
			}
			props[name] = property
			optional := strings.Contains(f.Tag.Get("json"), ",omitempty")
			if strings.HasSuffix(t.PkgPath(), "/internal/policy") && strings.HasSuffix(t.Name(), "Event") {
				optional = name != "protocol" || t.Name() != "Event"
			}
			if !optional {
				required = append(required, name)
			}
		}
		return map[string]any{"type": "object", "properties": props, "required": required, "additionalProperties": false}
	case reflect.Slice:
		if t.Elem().Kind() == reflect.Uint8 {
			return map[string]any{"type": []string{"string", "null"}, "contentEncoding": "base64"}
		}
		return map[string]any{"type": []string{"array", "null"}, "items": wireSchema(t.Elem())}
	case reflect.Array:
		return map[string]any{"type": "array", "items": wireSchema(t.Elem()), "minItems": t.Len(), "maxItems": t.Len()}
	case reflect.Map:
		return map[string]any{"type": []string{"object", "null"}, "additionalProperties": wireSchema(t.Elem())}
	case reflect.String:
		return map[string]any{"type": "string"}
	case reflect.Bool:
		return map[string]any{"type": "boolean"}
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return map[string]any{"type": "integer"}
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return map[string]any{"type": "integer", "minimum": 0}
	case reflect.Float32, reflect.Float64:
		return map[string]any{"type": "number"}
	default:
		return map[string]any{}
	}
}
