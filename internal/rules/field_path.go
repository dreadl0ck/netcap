package rules

import (
	"fmt"
	"reflect"
	"strings"
)

// Field paths name an exported field, optionally followed by fields of a
// nested struct: "SrcIP" or "Questions.Name". A step through a slice or array
// uses its first element, so "Questions.Name" is the first DNS query name.
const maxFieldPathDepth = 4

func scalarKind(k reflect.Kind) bool {
	switch k {
	case reflect.String,
		reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return true
	}
	return false
}

func derefType(t reflect.Type) reflect.Type {
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	return t
}

// fieldPathType resolves path on t and returns the scalar leaf type.
func fieldPathType(t reflect.Type, path string) (reflect.Type, error) {
	steps := strings.Split(path, ".")
	if path == "" || len(steps) > maxFieldPathDepth {
		return nil, fmt.Errorf("field path %q must have 1 to %d steps", path, maxFieldPathDepth)
	}
	t = derefType(t)
	for i, step := range steps {
		if i > 0 && (t.Kind() == reflect.Slice || t.Kind() == reflect.Array) {
			t = derefType(t.Elem())
		}
		if t.Kind() != reflect.Struct {
			return nil, fmt.Errorf("field path %q: %s is not a struct", path, strings.Join(steps[:i], "."))
		}
		f, ok := t.FieldByName(step)
		if !ok || !f.IsExported() {
			return nil, fmt.Errorf("field %q does not exist", path)
		}
		t = derefType(f.Type)
	}
	if !scalarKind(t.Kind()) {
		return nil, fmt.Errorf("field %q is a %s, which cannot form a key", path, t.Kind())
	}
	return t, nil
}

// fieldPathValue renders path on v as a string, or "" when any step is
// missing, nil, empty or not scalar.
func fieldPathValue(v reflect.Value, path string) string {
	steps := strings.Split(path, ".")
	if path == "" || len(steps) > maxFieldPathDepth {
		return ""
	}
	for i, step := range steps {
		for v.Kind() == reflect.Pointer || v.Kind() == reflect.Interface {
			if v.IsNil() {
				return ""
			}
			v = v.Elem()
		}
		if i > 0 && (v.Kind() == reflect.Slice || v.Kind() == reflect.Array) {
			if v.Len() == 0 {
				return ""
			}
			v = v.Index(0)
			for v.Kind() == reflect.Pointer || v.Kind() == reflect.Interface {
				if v.IsNil() {
					return ""
				}
				v = v.Elem()
			}
		}
		if v.Kind() != reflect.Struct {
			return ""
		}
		f, ok := v.Type().FieldByName(step)
		if !ok || !f.IsExported() {
			return ""
		}
		v = v.FieldByIndex(f.Index)
	}
	for v.Kind() == reflect.Pointer {
		if v.IsNil() {
			return ""
		}
		v = v.Elem()
	}
	switch v.Kind() {
	case reflect.String:
		return v.String()
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return fmt.Sprintf("%d", v.Int())
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return fmt.Sprintf("%d", v.Uint())
	}
	return ""
}
