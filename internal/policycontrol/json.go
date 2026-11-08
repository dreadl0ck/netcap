package policycontrol

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"reflect"
	"strings"
)

// Validate before decoding into structs or SDK maps, which discard duplicate keys.
func uniqueJSON(raw []byte) error {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	var value func(int) error
	value = func(depth int) error {
		if depth > 64 {
			return errors.New("JSON nesting exceeds limit")
		}
		t, err := d.Token()
		if err != nil {
			return err
		}
		switch t {
		case json.Delim('{'):
			seen := map[string]bool{}
			for d.More() {
				key, err := d.Token()
				if err != nil {
					return err
				}
				k, ok := key.(string)
				if !ok || seen[k] {
					return errors.New("duplicate JSON key")
				}
				seen[k] = true
				if err := value(depth + 1); err != nil {
					return err
				}
			}
			_, err = d.Token()
		case json.Delim('['):
			for d.More() {
				if err := value(depth + 1); err != nil {
					return err
				}
			}
			_, err = d.Token()
		}
		return err
	}
	if err := value(0); err != nil {
		return err
	}
	if _, err := d.Token(); err != io.EOF {
		return errors.New("expected one JSON value")
	}
	return nil
}

func decodeRequest(raw []byte, request *Request) error {
	if err := uniqueJSON(raw); err != nil {
		return err
	}
	if len(bytes.TrimSpace(raw)) == 0 || bytes.TrimSpace(raw)[0] != '{' {
		return errors.New("expected JSON object")
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return err
	}
	if _, event := fields["event"]; event {
		if _, events := fields["events"]; events {
			return errors.New("use event or events, not both")
		}
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err := exactFields(raw, reflect.TypeOf(*request)); err != nil {
		return err
	}
	return d.Decode(request)
}

// encoding/json otherwise accepts case-folded struct keys, including aliases
// such as both "revision" and "Revision" in a single object.
func exactFields(raw []byte, typ reflect.Type) error {
	if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return nil
	}
	switch typ.Kind() {
	case reflect.Struct:
		var object map[string]json.RawMessage
		if err := json.Unmarshal(raw, &object); err != nil {
			return err
		}
		fields := map[string]reflect.Type{}
		for i := range typ.NumField() {
			f := typ.Field(i)
			name := strings.Split(f.Tag.Get("json"), ",")[0]
			if name == "" {
				name = f.Name
			}
			fields[name] = f.Type
		}
		for key, value := range object {
			field, ok := fields[key]
			if !ok {
				return errors.New("unknown JSON field: " + key)
			}
			if err := exactFields(value, field); err != nil {
				return err
			}
		}
	case reflect.Slice:
		var array []json.RawMessage
		if err := json.Unmarshal(raw, &array); err != nil {
			return err
		}
		for _, value := range array {
			if err := exactFields(value, typ.Elem()); err != nil {
				return err
			}
		}
	}
	return nil
}

// Derive event schemas from the same model REST decodes; protocol fields must
// not disappear from tools/list when policy.Event gains another protocol.
func jsonSchema(typ reflect.Type) map[string]any {
	switch typ.Kind() {
	case reflect.Struct:
		properties := map[string]any{}
		for i := range typ.NumField() {
			f := typ.Field(i)
			name := strings.Split(f.Tag.Get("json"), ",")[0]
			if name == "" {
				name = f.Name
			}
			properties[name] = jsonSchema(f.Type)
		}
		return map[string]any{"type": "object", "properties": properties, "additionalProperties": false}
	case reflect.Slice:
		return map[string]any{"type": "array", "items": jsonSchema(typ.Elem())}
	case reflect.Map:
		return map[string]any{"type": "object", "additionalProperties": jsonSchema(typ.Elem())}
	case reflect.Bool:
		return map[string]any{"type": "boolean"}
	case reflect.Int:
		return map[string]any{"type": "integer"}
	default:
		return map[string]any{"type": "string"}
	}
}
