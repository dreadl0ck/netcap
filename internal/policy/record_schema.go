package policy

import (
	"errors"
	"strconv"
)

// ScalarType describes a native audit field's textual encoding. The event stays
// scalar-only; schemas are adapter-owned and never execute legacy rule code.
type ScalarType string

const (
	StringField ScalarType = "string"
	IntField    ScalarType = "int"
	BoolField   ScalarType = "bool"
)

type RecordSchema struct {
	RecordType string
	Fields     map[string]ScalarType
}

// Validate checks native record mappings before policy evaluation. Missing fields
// are permitted (partial records); unknown fields and noncanonical scalars fail.
// Expressions access Fields["name"] as strings, including numeric encodings.
func (s RecordSchema) Validate(e Event) error {
	if !validID.MatchString(s.RecordType) || e.RecordType != s.RecordType || len(s.Fields) > 128 {
		return errors.New("policy: invalid or mismatched record schema")
	}
	for name, kind := range s.Fields {
		if len(name) == 0 || len(name) > 128 || (kind != StringField && kind != IntField && kind != BoolField) {
			return errors.New("policy: invalid scalar field schema")
		}
	}
	for name, value := range e.Fields {
		kind, ok := s.Fields[name]
		if !ok {
			return errors.New("policy: unknown record field")
		}
		switch kind {
		case IntField:
			n, err := strconv.ParseInt(value, 10, 64)
			if err != nil || strconv.FormatInt(n, 10) != value {
				return errors.New("policy: invalid integer record field")
			}
		case BoolField:
			if value != "true" && value != "false" {
				return errors.New("policy: invalid boolean record field")
			}
		}
	}
	if e.Phase == "" {
		e.Phase = "request"
	}
	return validateEvent(e)
}
