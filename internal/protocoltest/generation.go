package protocoltest

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
)

type GenerationSpec struct {
	Version   int             `json:"version"`
	Bytes     bool            `json:"bytes"`
	Grammar   *Grammar        `json:"grammar,omitempty"`
	BuildSeed bool            `json:"buildSeed"`
	Fields    []FieldMutation `json:"fields,omitempty"`
	States    []StateMutation `json:"states,omitempty"`
}
type FieldMutation struct {
	Name   string   `json:"name"`
	Values [][]byte `json:"values,omitempty"`
}
type StateMutation struct {
	Action string `json:"action"`
	Step   int    `json:"step"`
}
type GeneratedCase struct {
	ID                  string   `json:"id"`
	Kind                string   `json:"kind"`
	Exchange            Exchange `json:"exchange"`
	SendStep            int      `json:"sendStep"`
	ResponseStep        int      `json:"responseStep"`
	ConfigurationSHA256 string   `json:"configurationSHA256"`
}
type GeneratedCorpus struct {
	Version             int                `json:"version"`
	GenerationVersion   string             `json:"generationVersion"`
	Metadata            ExperimentMetadata `json:"metadata"`
	ConfigurationSHA256 string             `json:"configurationSHA256"`
	Cases               []GeneratedCase    `json:"cases"`
}

func configHash(v any) string {
	b, _ := json.Marshal(v)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func caseHash(c GeneratedCase) string { c.ConfigurationSHA256 = ""; return configHash(c) }

// GrammarSeed constructs one fully specified, non-overlapping fixed-width
// layout. Nested/TLV expansion and unspecified bytes are deliberately refused.
func GrammarSeed(g Grammar) ([]byte, error) {
	if g.Version != 1 || len(g.Fields) > 128 || g.MaxFrames < 1 || g.MaxFrames > 4096 {
		return nil, fmt.Errorf("invalid grammar seed version/limits")
	}
	if err := g.Framing.Validate(); err != nil {
		return nil, err
	}
	size := 0
	for _, f := range g.Fields {
		if f.Offset < 0 || f.Length < 1 || f.Offset > 65536-f.Length || len(f.Expected) != f.Length {
			return nil, fmt.Errorf("seed fields require bounded offsets and exact expected bytes")
		}
		size = max(size, f.Offset+f.Length)
	}
	prefix := 0
	switch g.Framing.Kind {
	case "length-prefix":
		prefix = g.Framing.LengthBytes
		size = max(size, prefix)
	case "fixed":
		size = g.Framing.FixedSize
	case "delimiter":
		size += len(g.Framing.Delimiter)
	default:
		return nil, fmt.Errorf("unsupported grammar seed framing")
	}
	if size < 1 || size > min(65536, g.Framing.MaxBytes) {
		return nil, fmt.Errorf("grammar seed exceeds budget")
	}
	data := make([]byte, size)
	set := make([]bool, size)
	for i := 0; i < prefix; i++ {
		set[i] = true
	}
	if g.Framing.Kind == "delimiter" {
		copy(data[size-len(g.Framing.Delimiter):], g.Framing.Delimiter)
		for i := size - len(g.Framing.Delimiter); i < size; i++ {
			set[i] = true
		}
	}
	for _, f := range g.Fields {
		if f.Offset > size || f.Length > size-f.Offset {
			return nil, fmt.Errorf("field outside seed")
		}
		for i := 0; i < f.Length; i++ {
			at := f.Offset + i
			if set[at] {
				return nil, fmt.Errorf("overlapping seed field %s", f.Name)
			}
			set[at] = true
			data[at] = f.Expected[i]
		}
	}
	for _, s := range set {
		if !s {
			return nil, fmt.Errorf("grammar seed contains unspecified bytes")
		}
	}
	if prefix > 0 {
		var err error
		data, err = MutateFrame(data, g.Framing, Mutation{RepairLength: true})
		if err != nil {
			return nil, err
		}
	}
	report, err := g.Interpret(data)
	if err != nil {
		return nil, err
	}
	if len(report.Frames) != 1 {
		return nil, fmt.Errorf("seed must be exactly one frame")
	}
	return data, nil
}

func GenerateCampaign(spec Campaign) (GeneratedCorpus, error) {
	out := GeneratedCorpus{Version: 1, GenerationVersion: GenerationVersion, Metadata: spec.Metadata, ConfigurationSHA256: configHash(spec)}
	if err := spec.Metadata.Validate(); err != nil {
		return out, err
	}
	if err := spec.Control.Validate(); err != nil {
		return out, err
	}
	if spec.MaxCases < 1 || spec.MaxCases > 1024 || spec.SendStep < 0 || spec.SendStep >= len(spec.Control.Steps) || spec.ResponseStep < spec.SendStep || spec.ResponseStep >= len(spec.Control.Steps) || !spec.Control.Steps[spec.ResponseStep].Receive || spec.Control.Steps[spec.SendStep].SendVariable != "" {
		return out, fmt.Errorf("invalid generation limits or selectors; variable send mutation unsupported")
	}
	gen := GenerationSpec{Version: 1, Bytes: true}
	if spec.Generation != nil {
		gen = *spec.Generation
	}
	if gen.Version != 1 || len(gen.Fields) > 64 || len(gen.States) > 64 {
		return out, fmt.Errorf("unsupported generation version or excessive mutations")
	}
	base := spec.Control
	base.Steps = append([]Step(nil), base.Steps...)
	if gen.BuildSeed {
		if gen.Grammar == nil {
			return out, fmt.Errorf("seed construction requires grammar")
		}
		b, err := GrammarSeed(*gen.Grammar)
		if err != nil {
			return out, err
		}
		base.Steps[spec.SendStep].Send = b
		base.Steps[spec.SendStep].SendPresent = true
	}
	seed := base.Steps[spec.SendStep].Send
	if len(seed) == 0 || len(seed) > 65536 {
		return out, fmt.Errorf("generation requires 1..65536 seed bytes")
	}
	total := 0
	add := func(id, kind string, e Exchange, send, response int) error {
		if len(out.Cases) >= spec.MaxCases {
			return fmt.Errorf("corpus case budget exceeded")
		}
		e.Steps = append([]Step(nil), e.Steps...)
		if kind != "control" {
			e.Steps[response].Expect = nil
			e.Steps[response].ExpectPresent = false
			e.Steps[response].Contains = nil
		}
		cost := 0
		for _, s := range e.Steps {
			cost += len(s.Send) + len(s.Expect) + len(s.Contains)
		}
		if cost > 1<<20-total {
			return fmt.Errorf("corpus payload budget exceeded")
		}
		total += cost
		if err := e.Validate(); err != nil {
			return err
		}
		c := GeneratedCase{ID: id, Kind: kind, Exchange: e, SendStep: send, ResponseStep: response}
		c.ConfigurationSHA256 = caseHash(c)
		out.Cases = append(out.Cases, c)
		return nil
	}
	if err := add("control", "control", base, spec.SendStep, spec.ResponseStep); err != nil {
		return out, err
	}
	withInput := func(input []byte) Exchange {
		e := base
		e.Steps = append([]Step(nil), base.Steps...)
		e.Steps[spec.SendStep].Send = bytes.Clone(input)
		e.Steps[spec.SendStep].SendPresent = true
		return e
	}
	if gen.Bytes {
		cases, err := MutationCorpus(seed, spec.MaxCases, 1<<20)
		if err != nil {
			return out, err
		}
		for _, c := range cases[1:] {
			if err = add(c.ID, "byte", withInput(c.Input), spec.SendStep, spec.ResponseStep); err != nil {
				return out, err
			}
		}
	}
	if len(gen.Fields) > 0 {
		if gen.Grammar == nil {
			return out, fmt.Errorf("field mutations require grammar")
		}
		report, err := gen.Grammar.Interpret(seed)
		if err != nil {
			return out, err
		}
		if len(report.Frames) != 1 {
			return out, fmt.Errorf("field generation supports one seed frame")
		}
		if configHash(gen.Grammar.Framing) != configHash(base.Framing) {
			return out, fmt.Errorf("grammar and exchange framing differ")
		}
		seen := map[string]bool{}
		for _, mutation := range gen.Fields {
			if seen[mutation.Name] {
				return out, fmt.Errorf("duplicate field mutation %q", mutation.Name)
			}
			seen[mutation.Name] = true
			var field *FieldSpec
			for i := range gen.Grammar.Fields {
				if gen.Grammar.Fields[i].Name == mutation.Name {
					field = &gen.Grammar.Fields[i]
					break
				}
			}
			if field == nil {
				return out, fmt.Errorf("unknown field %q", mutation.Name)
			}
			values := mutation.Values
			if len(values) == 0 {
				if field.Kind != "unsigned" && field.Kind != "signed" {
					return out, fmt.Errorf("non-integer field requires explicit values")
				}
				for _, n := range []uint64{0, 1, ^uint64(0), uint64(1) << uint(8*field.Length-1)} {
					var b [8]byte
					if field.ByteOrder == "little" {
						binary.LittleEndian.PutUint64(b[:], n)
						values = append(values, bytes.Clone(b[:field.Length]))
					} else {
						binary.BigEndian.PutUint64(b[:], n)
						values = append(values, bytes.Clone(b[8-field.Length:]))
					}
				}
			}
			if len(values) > 64 {
				return out, fmt.Errorf("field value budget exceeded")
			}
			for i, value := range values {
				if len(value) != field.Length {
					return out, fmt.Errorf("variable-width field generation unsupported")
				}
				input := bytes.Clone(seed)
				copy(input[field.Offset:], value)
				if err = add(fmt.Sprintf("field-%s-%d", field.Name, i), "field", withInput(input), spec.SendStep, spec.ResponseStep); err != nil {
					return out, err
				}
			}
		}
	}
	for i, m := range gen.States {
		if m.Step < 0 || m.Step >= spec.SendStep {
			return out, fmt.Errorf("state mutations must select setup steps before sendStep")
		}
		e := base
		e.Steps = append([]Step(nil), base.Steps...)
		send, response := spec.SendStep, spec.ResponseStep
		switch m.Action {
		case "omit":
			e.Steps = append(e.Steps[:m.Step], e.Steps[m.Step+1:]...)
			send--
			response--
		case "duplicate":
			steps := append([]Step(nil), e.Steps[:m.Step+1]...)
			steps = append(steps, e.Steps[m.Step:]...)
			e.Steps = steps
			send++
			response++
		case "swap-next":
			if m.Step+1 >= spec.SendStep {
				return out, fmt.Errorf("swap must stay in setup steps")
			}
			e.Steps[m.Step], e.Steps[m.Step+1] = e.Steps[m.Step+1], e.Steps[m.Step]
		default:
			return out, fmt.Errorf("unsupported state mutation %q", m.Action)
		}
		if err := add(fmt.Sprintf("state-%d-%s-%d", i, m.Action, m.Step), "state", e, send, response); err != nil {
			return out, err
		}
	}
	return out, nil
}
