package protocoltest

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strconv"
	"unicode/utf8"
)

type FieldSpec struct {
	Name       string `json:"name"`
	Offset     int    `json:"offset"`
	Length     int    `json:"length"`
	Kind       string `json:"kind"`
	ByteOrder  string `json:"byteOrder,omitempty"`
	Expected   []byte `json:"expected,omitempty"`
	Hypothesis string `json:"hypothesis"`
}

type Grammar struct {
	Version   int         `json:"version"`
	Framing   Framing     `json:"framing"`
	Fields    []FieldSpec `json:"fields"`
	MaxFrames int         `json:"maxFrames"`
}

type InterpretedField struct {
	Name       string `json:"name"`
	Offset     int    `json:"offset"`
	Length     int    `json:"length"`
	Raw        []byte `json:"raw"`
	Value      string `json:"value"`
	Hypothesis string `json:"hypothesis"`
}

type InterpretedFrame struct {
	Index  int                `json:"index"`
	Offset int                `json:"offset"`
	Length int                `json:"length"`
	SHA256 string             `json:"sha256"`
	Fields []InterpretedField `json:"fields"`
}

type GrammarReport struct {
	Version     int                `json:"version"`
	InputSHA256 string             `json:"inputSHA256"`
	Frames      []InterpretedFrame `json:"frames"`
	Limitations []string           `json:"limitations"`
}

func (g Grammar) Interpret(data []byte) (GrammarReport, error) {
	report := GrammarReport{Version: 1, Frames: []InterpretedFrame{}, Limitations: []string{"fields are analyst-declared hypotheses; successful parsing does not prove protocol semantics", "input must be one contiguous directional stream; consult capture/stream loss metadata before interpreting"}}
	if g.Version != 1 || g.MaxFrames < 1 || g.MaxFrames > 4096 || len(g.Fields) > 128 || len(data) > 16<<20 {
		return report, fmt.Errorf("invalid grammar version or resource limits")
	}
	if err := g.Framing.Validate(); err != nil {
		return report, err
	}
	names := map[string]bool{}
	for _, field := range g.Fields {
		if field.Name == "" || len(field.Name) > 128 || names[field.Name] || field.Offset < 0 || field.Length < 0 || field.Length > 4096 || len(field.Hypothesis) > 2048 {
			return report, fmt.Errorf("invalid grammar field %q", field.Name)
		}
		names[field.Name] = true
		switch field.Kind {
		case "bytes", "utf8":
		case "unsigned", "signed":
			if field.Length != 1 && field.Length != 2 && field.Length != 4 && field.Length != 8 {
				return report, fmt.Errorf("integer field %s needs 1,2,4 or 8 bytes", field.Name)
			}
			if field.ByteOrder != "big" && field.ByteOrder != "little" {
				return report, fmt.Errorf("integer byte order required")
			}
		default:
			return report, fmt.Errorf("unsupported field kind %q", field.Kind)
		}
	}
	hash := sha256.Sum256(data)
	report.InputSHA256 = hex.EncodeToString(hash[:])
	reader := bytes.NewReader(data)
	for reader.Len() > 0 {
		if len(report.Frames) >= g.MaxFrames {
			return report, fmt.Errorf("grammar frame limit exceeded")
		}
		offset := len(data) - reader.Len()
		frame, err := g.Framing.Read(reader)
		if err != nil {
			return report, fmt.Errorf("frame %d at byte %d: %w", len(report.Frames), offset, err)
		}
		digest := sha256.Sum256(frame)
		entry := InterpretedFrame{Index: len(report.Frames), Offset: offset, Length: len(frame), SHA256: hex.EncodeToString(digest[:]), Fields: []InterpretedField{}}
		for _, field := range g.Fields {
			if field.Offset > len(frame) || field.Length > len(frame)-field.Offset {
				return report, fmt.Errorf("field %s exceeds frame %d", field.Name, entry.Index)
			}
			raw := frame[field.Offset : field.Offset+field.Length]
			if field.Expected != nil && !bytes.Equal(raw, field.Expected) {
				return report, fmt.Errorf("field %s assertion failed in frame %d", field.Name, entry.Index)
			}
			value := hex.EncodeToString(raw)
			if field.Kind == "utf8" {
				if !utf8.Valid(raw) {
					return report, fmt.Errorf("field %s contains invalid UTF-8", field.Name)
				}
				value = string(raw)
			}
			if field.Kind == "signed" || field.Kind == "unsigned" {
				var padded [8]byte
				var number uint64
				if field.ByteOrder == "big" {
					copy(padded[8-len(raw):], raw)
					number = binary.BigEndian.Uint64(padded[:])
				} else {
					copy(padded[:], raw)
					number = binary.LittleEndian.Uint64(padded[:])
				}
				value = strconv.FormatUint(number, 10)
				if field.Kind == "signed" {
					shift := uint(64 - 8*len(raw))
					value = strconv.FormatInt(int64(number<<shift)>>shift, 10)
				}
			}
			entry.Fields = append(entry.Fields, InterpretedField{Name: field.Name, Offset: offset + field.Offset, Length: field.Length, Raw: append([]byte(nil), raw...), Value: value, Hypothesis: field.Hypothesis})
		}
		report.Frames = append(report.Frames, entry)
	}
	return report, nil
}

type FieldDifference struct {
	Frame  int    `json:"frame"`
	Field  string `json:"field"`
	Before string `json:"before"`
	After  string `json:"after"`
}
type GrammarComparison struct {
	Before      GrammarReport     `json:"before"`
	After       GrammarReport     `json:"after"`
	Differences []FieldDifference `json:"differences"`
	Alignment   string            `json:"alignment"`
}

func (g Grammar) Compare(before, after []byte) (GrammarComparison, error) {
	result := GrammarComparison{Differences: []FieldDifference{}, Alignment: "frame ordinal and declared field name; inserted/deleted messages may shift alignment"}
	var err error
	result.Before, err = g.Interpret(before)
	if err != nil {
		return result, err
	}
	result.After, err = g.Interpret(after)
	if err != nil {
		return result, err
	}
	for i := 0; i < max(len(result.Before.Frames), len(result.After.Frames)); i++ {
		if i >= len(result.Before.Frames) {
			result.Differences = append(result.Differences, FieldDifference{Frame: i, Field: "frame", After: "present"})
			continue
		}
		if i >= len(result.After.Frames) {
			result.Differences = append(result.Differences, FieldDifference{Frame: i, Field: "frame", Before: "present"})
			continue
		}
		a, b := result.Before.Frames[i], result.After.Frames[i]
		if a.SHA256 != b.SHA256 {
			result.Differences = append(result.Differences, FieldDifference{Frame: i, Field: "frame-sha256", Before: a.SHA256, After: b.SHA256})
		}
		for j, field := range a.Fields {
			other := b.Fields[j]
			if !bytes.Equal(field.Raw, other.Raw) {
				result.Differences = append(result.Differences, FieldDifference{Frame: i, Field: field.Name, Before: field.Value, After: other.Value})
			}
		}
	}
	return result, nil
}
