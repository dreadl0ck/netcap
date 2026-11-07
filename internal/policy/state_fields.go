package policy

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"reflect"
	"strconv"
	"strings"
)

var ErrMissingStateField = errors.New("policy: state field unavailable")

func mapField(field string) (string, string, bool) {
	for _, prefix := range []string{"Attributes.", "Fields."} {
		if strings.HasPrefix(field, prefix) {
			return strings.TrimSuffix(prefix, "."), strings.TrimPrefix(field, prefix), true
		}
	}
	return "", "", false
}

func validScalarField(field string) bool {
	if _, key, ok := mapField(field); ok {
		return len(key) <= 128 && validID.MatchString(key)
	}
	if field == "Body" || len(field) > 128 {
		return false
	}
	t := reflect.TypeOf(Event{})
	for _, name := range strings.Split(field, ".") {
		if t.Kind() != reflect.Struct {
			return false
		}
		f, ok := t.FieldByName(name)
		if !ok || f.PkgPath != "" {
			return false
		}
		t = f.Type
	}
	return t.Kind() == reflect.String || t.Kind() == reflect.Int || t.Kind() == reflect.Bool
}

func validateGrouping(single string, fields []string) error {
	if len(fields) > 4 || (single != "" && len(fields) > 0) {
		return errors.New("group_by and group_by_fields are exclusive; tuple maximum is 4")
	}
	if single != "" {
		fields = []string{single}
	}
	seen := make(map[string]bool)
	for _, field := range fields {
		if !validScalarField(field) || seen[field] {
			return errors.New("unsupported or duplicate state grouping field")
		}
		seen[field] = true
	}
	return nil
}

func scalarValue(e Event, field string) (string, string, bool) {
	if root, key, ok := mapField(field); ok {
		values := e.Attributes
		if root == "Fields" {
			values = e.Fields
		}
		value, present := values[key]
		return "string", value, present
	}
	v := reflect.ValueOf(e)
	for _, name := range strings.Split(field, ".") {
		v = v.FieldByName(name)
	}
	switch v.Kind() {
	case reflect.String:
		return "string", v.String(), true
	case reflect.Int:
		return "int", strconv.FormatInt(v.Int(), 10), true
	case reflect.Bool:
		return "bool", strconv.FormatBool(v.Bool()), true
	default:
		return "", "", false
	}
}

func hashPart(h hash.Hash, value string) {
	var size [8]byte
	binary.BigEndian.PutUint64(size[:], uint64(len(value)))
	_, _ = h.Write(size[:])
	_, _ = h.Write([]byte(value))
}

func stateKey(id, single string, fields []string, e Event) ([32]byte, error) {
	h := sha256.New()
	hashPart(h, id)
	if single != "" {
		fields = []string{single}
	}
	for _, field := range fields {
		kind, value, present := scalarValue(e, field)
		if !present {
			return [32]byte{}, fmt.Errorf("%w: %s", ErrMissingStateField, field)
		}
		hashPart(h, field)
		hashPart(h, kind)
		hashPart(h, value)
	}
	var key [32]byte
	copy(key[:], h.Sum(nil))
	return key, nil
}

func groupKey(id, field string, e Event) [32]byte {
	key, _ := stateKey(id, field, nil, e)
	return key
}
