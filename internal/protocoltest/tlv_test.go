package protocoltest

import (
	"bytes"
	"errors"
	"testing"
)

func tlvHypothesis() TLVSpec {
	return TLVSpec{TypeBytes: 1, LengthBytes: 1, ByteOrder: "big", NestedTypes: []uint64{16}, LeafKind: "bytes", MaxDepth: 3, MaxEntries: 16, MaxValueBytes: 64}
}
func tlvGrammar(s TLVSpec) Grammar {
	return Grammar{Version: 1, Framing: Framing{Kind: "length-prefix", LengthBytes: 1, ByteOrder: "big", MaxBytes: 128}, MaxFrames: 8, Fields: []FieldSpec{{Name: "records", Offset: 1, Kind: "tlv", TLV: &s, Hypothesis: "type 16 contains nested TLVs; lengths exclude headers"}}}
}
func tlvFrame(body []byte) []byte { return append([]byte{byte(len(body))}, body...) }

func TestTLVVariableLengthNestedOffsetsAndCompleteConsumption(t *testing.T) {
	s := tlvHypothesis()
	g := tlvGrammar(s)
	body := []byte{16, 7, 1, 1, 'A', 2, 2, 'B', 'C', 3, 0}
	input := tlvFrame(body)
	r, err := g.Interpret(append(bytes.Clone(input), input...))
	if err != nil || len(r.Frames) != 2 {
		t.Fatal(r, err)
	}
	for i, frame := range r.Frames {
		field := frame.Fields[0]
		if !bytes.Equal(field.Raw, body) || len(field.Entries) != 2 || len(field.Entries[0].Children) != 2 || field.Entries[0].Children[1].Offset != i*len(input)+6 || string(field.Entries[0].Children[1].Value) != "BC" || field.Entries[1].Length != 2 {
			t.Fatalf("TLV evidence %+v", field)
		}
	}
	changed := bytes.Clone(input)
	changed[8] = 'Z'
	comparison, err := g.Compare(input, changed)
	if err != nil || len(comparison.Differences) != 2 || comparison.Differences[1].Before == comparison.Differences[1].After {
		t.Fatal("TLV comparison lost changed value", comparison, err)
	}
	variable := Grammar{Version: 1, Framing: g.Framing, MaxFrames: 1, Fields: []FieldSpec{{Name: "text", Offset: 2, Kind: "utf8", LengthFrom: &LengthField{Offset: 1, Width: 1, ByteOrder: "big"}}}}
	vr, err := variable.Interpret([]byte{3, 2, 'H', 'I'})
	if err != nil || vr.Frames[0].Fields[0].Value != "HI" || vr.Frames[0].Fields[0].Length != 2 {
		t.Fatal("variable field", vr, err)
	}
	if _, err = variable.Interpret([]byte{3, 3, 'H', 'I'}); err == nil {
		t.Fatal("variable field overrun accepted")
	}
	variable.Fields[0].LengthFrom.Adjustment = -3
	if _, err = variable.Interpret([]byte{3, 2, 'H', 'I'}); err == nil {
		t.Fatal("negative variable length accepted")
	}
	little := s
	little.TypeBytes = 2
	little.LengthBytes = 2
	little.ByteOrder = "little"
	little.LengthIncludesHeader = true
	little.NestedTypes = nil
	g = tlvGrammar(little)
	lr, err := g.Interpret(tlvFrame([]byte{0x34, 0x12, 6, 0, 0, 255}))
	if err != nil || lr.Frames[0].Fields[0].Entries[0].Type != 0x1234 || !bytes.Equal(lr.Frames[0].Fields[0].Entries[0].Value, []byte{0, 255}) {
		t.Fatal("little endian/header-inclusive TLV", lr, err)
	}
}

func TestTLVRejectsTruncationEncodingAndFiniteLimits(t *testing.T) {
	empty := tlvHypothesis()
	empty.MaxDepth = 1
	if _, err := tlvGrammar(empty).Interpret(tlvFrame([]byte{16, 0})); err != nil {
		t.Fatal("empty container invents a nesting level", err)
	}
	for _, bad := range [][]byte{{1}, {1, 3, 'A'}, {1, 0, 2}, {16, 1, 1}} {
		input := tlvFrame(bad)
		original := bytes.Clone(input)
		if _, err := tlvGrammar(tlvHypothesis()).Interpret(input); err == nil {
			t.Fatalf("accepted malformed %x", input)
		}
		if !bytes.Equal(input, original) {
			t.Fatal("parser changed raw evidence")
		}
	}
	for _, limit := range []string{"depth", "entries", "value"} {
		s := tlvHypothesis()
		body := []byte{16, 3, 1, 1, 'A'}
		switch limit {
		case "depth":
			s.MaxDepth = 1
		case "entries":
			s.MaxEntries = 1
		case "value":
			s.MaxValueBytes = 2
		}
		if _, err := tlvGrammar(s).Interpret(tlvFrame(body)); !errors.Is(err, ErrBudgetExceeded) {
			t.Fatalf("%s not classified as harness stop: %v", limit, err)
		}
	}
	s := tlvHypothesis()
	s.LeafKind = "utf8"
	if _, err := tlvGrammar(s).Interpret(tlvFrame([]byte{1, 1, 255})); err == nil || errors.Is(err, ErrBudgetExceeded) {
		t.Fatal("invalid UTF-8 should be hypothesis rejection", err)
	}
	s.MaxDepth = 9
	if _, err := tlvGrammar(s).Interpret(nil); err == nil {
		t.Fatal("unbounded nesting accepted")
	}
	if _, err := (LengthField{Offset: 0, Width: 2, ByteOrder: "big"}).Resolve([]byte{255, 255}); !errors.Is(err, ErrBudgetExceeded) {
		t.Fatal("variable length budget", err)
	}
}
