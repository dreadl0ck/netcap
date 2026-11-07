package policy

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"strings"

	"gopkg.in/yaml.v2"
)

// Parse accepts exactly one YAML or JSON object, rejecting unknown and duplicate
// keys at every schema level. YAML mappings are decoded lazily so aliases cannot
// expand arbitrary object graphs. Compile performs semantic validation.
func Parse(data []byte) (Bundle, error) {
	var b Bundle
	if len(data) == 0 || len(data) > MaxBundleBytes {
		return b, errors.New("policy: bundle must contain 1..1048576 bytes")
	}
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 {
		return b, errors.New("policy: empty bundle")
	}
	if trimmed[0] == '{' || trimmed[0] == '[' {
		data = trimmed
		d := json.NewDecoder(bytes.NewReader(data))
		if err := uniqueJSON(d, 0); err != nil {
			return b, fmt.Errorf("policy: invalid JSON: %w", err)
		}
		if _, err := d.Token(); err != io.EOF {
			return b, errors.New("policy: trailing JSON data")
		}
		d = json.NewDecoder(bytes.NewReader(data))
		d.DisallowUnknownFields()
		if err := d.Decode(&b); err != nil {
			return Bundle{}, fmt.Errorf("policy: invalid JSON schema: %w", err)
		}
	} else {
		if err := checkYAMLFeatures(data); err != nil {
			return Bundle{}, err
		}
		d := yaml.NewDecoder(bytes.NewReader(data))
		d.SetStrict(true)
		var parsed yamlValue
		if err := d.Decode(&parsed); err != nil {
			return Bundle{}, fmt.Errorf("policy: invalid YAML schema: %w", err)
		}
		if err := decodeYAML(parsed, reflect.ValueOf(&b).Elem(), 0); err != nil {
			return Bundle{}, fmt.Errorf("policy: invalid YAML schema: %w", err)
		}
		var extra yamlValue
		if err := d.Decode(&extra); err != io.EOF {
			return Bundle{}, errors.New("policy: expected exactly one YAML document")
		}
	}
	if len(b.Rules) > MaxRules {
		return Bundle{}, errors.New("policy: too many rules")
	}
	return b, nil
}

// Raw syntax counts bound the parser tree without interpreting quoted text.
func checkYAMLFeatures(data []byte) error {
	breaks, tokens := 0, 0
	for _, ch := range string(data) {
		if strings.ContainsRune("\n\r\u0085\u2028\u2029", ch) {
			breaks++
		}
		if strings.ContainsRune("[{:,-", ch) {
			tokens++
		}
		if breaks > 32768 || tokens > 32768 {
			return errors.New("policy: YAML structural token limit exceeded")
		}
	}
	return nil
}

type yamlValue struct{ decode func(interface{}) error }

func (v *yamlValue) UnmarshalYAML(decode func(interface{}) error) error {
	v.decode = decode
	return nil
}

// Strict map decoding tracks duplicates across merges; struct decoding does not.
// Lazy values prevent aliases from expanding arbitrary nested object graphs.
func decodeYAML(raw yamlValue, dst reflect.Value, depth int) error {
	if depth > 8 {
		return errors.New("schema nesting exceeds 8")
	}
	if raw.decode == nil {
		if dst.Kind() == reflect.Ptr || dst.Kind() == reflect.Slice {
			return nil
		}
		return errors.New("unexpected null value")
	}
	if dst.Kind() == reflect.Ptr {
		dst.Set(reflect.New(dst.Type().Elem()))
		return decodeYAML(raw, dst.Elem(), depth+1)
	}
	switch dst.Kind() {
	case reflect.Struct:
		var fields map[string]yamlValue
		if err := raw.decode(&fields); err != nil {
			return err
		}
		for name, value := range fields {
			index := -1
			for i := 0; i < dst.NumField(); i++ {
				if strings.Split(dst.Type().Field(i).Tag.Get("yaml"), ",")[0] == name {
					index = i
					break
				}
			}
			if index == -1 {
				return errors.New("unknown YAML field")
			}
			if err := decodeYAML(value, dst.Field(index), depth+1); err != nil {
				return err
			}
		}
	case reflect.Slice:
		var values []yamlValue
		if err := raw.decode(&values); err != nil {
			return err
		}
		limit := MaxRules
		if dst.Type().Elem().Kind() == reflect.String {
			limit = 16
		}
		if len(values) > limit {
			return errors.New("YAML array exceeds schema limit")
		}
		dst.Set(reflect.MakeSlice(dst.Type(), len(values), len(values)))
		for i, v := range values {
			if err := decodeYAML(v, dst.Index(i), depth+1); err != nil {
				return err
			}
		}
	default:
		return raw.decode(dst.Addr().Interface())
	}
	return nil
}

func uniqueJSON(d *json.Decoder, depth int) error {
	if depth > 16 {
		return errors.New("nesting exceeds 16")
	}
	t, err := d.Token()
	if err != nil {
		return err
	}
	delim, ok := t.(json.Delim)
	if !ok {
		return nil
	}
	keys := make(map[string]bool)
	for d.More() {
		if delim == '{' {
			key, err := d.Token()
			if err != nil {
				return err
			}
			s, ok := key.(string)
			if !ok || keys[s] {
				return errors.New("duplicate or invalid object key")
			}
			if !jsonKeyAllowed(depth, s) {
				return errors.New("unknown or incorrectly cased object key")
			}
			keys[s] = true
		}
		if err := uniqueJSON(d, depth+1); err != nil {
			return err
		}
	}
	_, err = d.Token()
	return err
}

func jsonKeyAllowed(depth int, key string) bool {
	var allowed []string
	switch depth {
	case 0:
		allowed = []string{"version", "id", "mode", "default", "rules", "defaults"}
	case 1:
		allowed = []string{"request", "response"}
	case 2:
		allowed = []string{"id", "phase", "expression", "action", "status", "priority", "enabled", "threshold", "sequence", "effects"}
	case 3:
		allowed = []string{"count", "window", "group_by", "group_by_fields", "mode", "distinct", "name", "steps"}
	case 4:
		allowed = []string{"kind", "duration", "target", "scope", "profile"}
	default:
		return false
	}
	for _, name := range allowed {
		if key == name {
			return true
		}
	}
	return false
}
