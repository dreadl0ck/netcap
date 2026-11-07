package apipolicy

import (
	"encoding/base64"
	"encoding/json"
	"strconv"
	"strings"

	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protodesc"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/descriptorpb"
	"google.golang.org/protobuf/types/dynamicpb"
)

// FieldPolicy validates typed protobuf values. Missing presence-aware fields are
// distinct from explicit default values; implicit-presence scalars use defaults.
// Enum names are strings; unknown enum numbers remain numbers. Bytes are base64.
type FieldPolicy struct {
	Required bool `json:"required,omitempty"`
	Schema   any  `json:"schema"`
}
type MethodPolicy struct {
	Request  map[string]FieldPolicy `json:"request"`
	Response map[string]FieldPolicy `json:"response,omitempty"`
}
type fieldRule struct {
	fields   []protoreflect.FieldDescriptor
	required bool
	schema   *validator
}
type grpcMethod struct {
	descriptor        protoreflect.MethodDescriptor
	request, response []fieldRule
}

func (b *Bundle) compileGRPC(data []byte, policies map[string]MethodPolicy, resources map[string]any) error {
	if len(data) == 0 || len(data) > MaxBytes {
		return ErrInvalid
	}
	set := &descriptorpb.FileDescriptorSet{}
	if err := (proto.UnmarshalOptions{RecursionLimit: MaxDepth}).Unmarshal(data, set); err != nil {
		return ErrInvalid
	}
	if len(set.File) == 0 || len(set.File) > 64 {
		return ErrInvalid
	}
	// Only compiled proto2/proto3 descriptors are accepted; editions need a
	// separate compatibility review rather than silently assuming proto3 rules.
	for _, f := range set.File {
		if f.GetSyntax() != "" && f.GetSyntax() != "proto2" && f.GetSyntax() != "proto3" {
			return ErrInvalid
		}
	}
	files, err := protodesc.NewFiles(set)
	if err != nil {
		return ErrInvalid
	}
	for path, p := range policies {
		parts := strings.Split(path, "/")
		if len(parts) != 3 || parts[0] != "" || parts[1] == "" || parts[2] == "" {
			return ErrInvalid
		}
		d, err := files.FindDescriptorByName(protoreflect.FullName(parts[1] + "." + parts[2]))
		if err != nil {
			return ErrInvalid
		}
		md, ok := d.(protoreflect.MethodDescriptor)
		if !ok {
			return ErrInvalid
		}
		m := &grpcMethod{descriptor: md}
		m.request, err = compileFields(md.Input(), p.Request, resources)
		if err != nil {
			return err
		}
		m.response, err = compileFields(md.Output(), p.Response, resources)
		if err != nil {
			return err
		}
		b.methods[path] = m
	}
	return nil
}

func compileFields(message protoreflect.MessageDescriptor, policies map[string]FieldPolicy, resources map[string]any) ([]fieldRule, error) {
	if len(policies) > 64 {
		return nil, ErrInvalid
	}
	rules := []fieldRule{}
	for path, p := range policies {
		segments := strings.Split(path, ".")
		if len(segments) > 16 {
			return nil, ErrInvalid
		}
		rule := fieldRule{required: p.Required}
		current := message
		for i, name := range segments {
			f := current.Fields().ByName(protoreflect.Name(name))
			if f == nil {
				return nil, ErrInvalid
			}
			rule.fields = append(rule.fields, f)
			if i < len(segments)-1 {
				if f.Message() == nil || f.IsList() || f.IsMap() {
					return nil, ErrInvalid
				}
				current = f.Message()
			}
		}
		budget := 2048
		schema, err := expand(p.Schema, "", resources, map[string]bool{}, 0, &budget)
		if err != nil {
			return nil, err
		}
		rule.schema, err = compileSchema(schema, false)
		if err != nil {
			return nil, err
		}
		rules = append(rules, rule)
	}
	return rules, nil
}

// GRPCMethod is the call-header gate. Unknown methods require explicit POST
// passthrough. It runs before opening an origin stream.
func (b *Bundle) GRPCMethod(path string) error {
	if canonicalPath(path) && (b.methods[path] != nil || b.passthrough[Binding{Method: "POST", Path: path}]) {
		return nil
	}
	return ErrInvalid
}

// ValidateGRPC must run on each complete decompressed message before releasing
// its frame. It never remarshal/replaces the wire, so unknown fields survive.
func (b *Bundle) ValidateGRPC(path string, response bool, data []byte) error {
	m := b.methods[path]
	if m == nil {
		return b.GRPCMethod(path)
	}
	if len(data) > MaxBytes {
		return ErrInvalid
	}
	descriptor, rules := m.descriptor.Input(), m.request
	if response {
		descriptor, rules = m.descriptor.Output(), m.response
	}
	nodes := 0
	if err := checkWire(data, descriptor, 0, &nodes); err != nil {
		return err
	}
	msg := dynamicpb.NewMessage(descriptor)
	if err := (proto.UnmarshalOptions{DiscardUnknown: false, RecursionLimit: MaxDepth}).Unmarshal(data, msg); err != nil {
		return ErrInvalid
	}
	nodes = 0
	if _, err := messageValue(msg, 0, &nodes); err != nil {
		return err
	}
	for _, rule := range rules {
		var current protoreflect.Message = msg
		present := true
		var f protoreflect.FieldDescriptor
		for i, field := range rule.fields {
			f = field
			if f.HasPresence() && !current.Has(f) {
				present = false
				break
			}
			if i < len(rule.fields)-1 {
				current = current.Get(f).Message()
			}
		}
		if !present {
			if rule.required {
				return ErrInvalid
			}
			continue
		}
		n := 0
		x, err := fieldValue(f, current.Get(f), 0, &n)
		if err != nil {
			return err
		}
		encoded, err := json.Marshal(x)
		if err != nil {
			return ErrInvalid
		}
		if err := rule.schema.check(encoded); err != nil {
			return err
		}
	}
	return nil
}

// Bound allocations before dynamic decoding, including packed scalar lists.
// Groups are outside this profile; length-delimited unknown fields stay opaque.
func checkWire(data []byte, md protoreflect.MessageDescriptor, depth int, nodes *int) error {
	if depth > MaxDepth {
		return ErrInvalid
	}
	for len(data) > 0 {
		*nodes++
		if *nodes > MaxNodes {
			return ErrInvalid
		}
		number, kind, n := protowire.ConsumeTag(data)
		if n < 0 || kind == protowire.StartGroupType || kind == protowire.EndGroupType {
			return ErrInvalid
		}
		data = data[n:]
		f := md.Fields().ByNumber(number)
		if kind == protowire.BytesType {
			payload, n := protowire.ConsumeBytes(data)
			if n < 0 {
				return ErrInvalid
			}
			if f != nil && f.Message() != nil {
				if err := checkWire(payload, f.Message(), depth+1, nodes); err != nil {
					return err
				}
			} else if f != nil && f.IsList() && f.Kind() != protoreflect.StringKind && f.Kind() != protoreflect.BytesKind {
				for len(payload) > 0 {
					*nodes++
					width := 0
					switch f.Kind() {
					case protoreflect.DoubleKind, protoreflect.Fixed64Kind, protoreflect.Sfixed64Kind:
						_, width = protowire.ConsumeFixed64(payload)
					case protoreflect.FloatKind, protoreflect.Fixed32Kind, protoreflect.Sfixed32Kind:
						_, width = protowire.ConsumeFixed32(payload)
					default:
						_, width = protowire.ConsumeVarint(payload)
					}
					if width < 0 || *nodes > MaxNodes {
						return ErrInvalid
					}
					payload = payload[width:]
				}
			}
			data = data[n:]
		} else {
			n := protowire.ConsumeFieldValue(number, kind, data)
			if n < 0 {
				return ErrInvalid
			}
			data = data[n:]
		}
	}
	return nil
}

func messageValue(m protoreflect.Message, depth int, nodes *int) (any, error) {
	*nodes++
	if depth > MaxDepth || *nodes > MaxNodes {
		return nil, ErrInvalid
	}
	out := map[string]any{}
	fields := m.Descriptor().Fields()
	for i := 0; i < fields.Len(); i++ {
		f := fields.Get(i)
		if f.HasPresence() && !m.Has(f) {
			continue
		}
		x, err := fieldValue(f, m.Get(f), depth+1, nodes)
		if err != nil {
			return nil, err
		}
		out[string(f.Name())] = x
	}
	return out, nil
}

func fieldValue(f protoreflect.FieldDescriptor, v protoreflect.Value, depth int, nodes *int) (any, error) {
	*nodes++
	if depth > MaxDepth || *nodes > MaxNodes {
		return nil, ErrInvalid
	}
	if f.IsMap() {
		m := v.Map()
		if m.Len() > 1024 {
			return nil, ErrInvalid
		}
		out := map[string]any{}
		var failure error
		m.Range(func(k protoreflect.MapKey, v protoreflect.Value) bool {
			x, err := scalarValue(f.MapValue(), v, depth+1, nodes)
			if err != nil {
				failure = err
				return false
			}
			out[k.String()] = x
			return true
		})
		return out, failure
	}
	if f.IsList() {
		l := v.List()
		if l.Len() > 1024 {
			return nil, ErrInvalid
		}
		out := make([]any, l.Len())
		for i := 0; i < l.Len(); i++ {
			x, err := scalarValue(f, l.Get(i), depth+1, nodes)
			if err != nil {
				return nil, err
			}
			out[i] = x
		}
		return out, nil
	}
	return scalarValue(f, v, depth, nodes)
}

func scalarValue(f protoreflect.FieldDescriptor, v protoreflect.Value, depth int, nodes *int) (any, error) {
	*nodes++
	if depth > MaxDepth || *nodes > MaxNodes {
		return nil, ErrInvalid
	}
	switch f.Kind() {
	case protoreflect.MessageKind, protoreflect.GroupKind:
		return messageValue(v.Message(), depth+1, nodes)
	case protoreflect.BytesKind:
		return base64.StdEncoding.EncodeToString(v.Bytes()), nil
	case protoreflect.EnumKind:
		if e := f.Enum().Values().ByNumber(v.Enum()); e != nil {
			return string(e.Name()), nil
		}
		return json.Number(strconv.FormatInt(int64(v.Enum()), 10)), nil
	case protoreflect.Int32Kind, protoreflect.Int64Kind, protoreflect.Sint32Kind, protoreflect.Sint64Kind, protoreflect.Sfixed32Kind, protoreflect.Sfixed64Kind:
		return json.Number(strconv.FormatInt(v.Int(), 10)), nil
	case protoreflect.Uint32Kind, protoreflect.Uint64Kind, protoreflect.Fixed32Kind, protoreflect.Fixed64Kind:
		return json.Number(strconv.FormatUint(v.Uint(), 10)), nil
	default:
		return v.Interface(), nil
	}
}
