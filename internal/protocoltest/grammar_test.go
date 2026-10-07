package protocoltest

import (
	"testing"
)

func TestGrammarStrictFieldsAndControlledComparison(t *testing.T) {
	g := Grammar{Version: 1, MaxFrames: 10, Framing: Framing{Kind: "length-prefix", LengthBytes: 2, ByteOrder: "big", MaxBytes: 64}, Fields: []FieldSpec{
		{Name: "length", Offset: 0, Length: 2, Kind: "unsigned", ByteOrder: "big", Hypothesis: "body length"},
		{Name: "opcode", Offset: 2, Length: 1, Kind: "unsigned", ByteOrder: "big", Hypothesis: "operation selector"},
		{Name: "signed", Offset: 3, Length: 2, Kind: "signed", ByteOrder: "little", Hypothesis: "signed status"},
		{Name: "text", Offset: 5, Length: 2, Kind: "utf8", Hypothesis: "display text"},
	}}
	a := []byte{0, 5, 1, 255, 255, 'O', 'K'}
	b := []byte{0, 5, 2, 254, 255, 'N', 'O'}
	report, err := g.Interpret(append(append([]byte(nil), a...), b...))
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Frames) != 2 || report.Frames[0].Fields[2].Value != "-1" || report.Frames[1].Fields[2].Value != "-2" || report.Frames[1].Fields[3].Offset != 12 {
		t.Fatalf("field/endian/offset mismatch: %+v", report)
	}
	comparison, err := g.Compare(a, b)
	if err != nil {
		t.Fatal(err)
	}
	if len(comparison.Differences) != 4 {
		t.Fatalf("comparison lost changes: %+v", comparison)
	}
	if _, err := g.Interpret(a[:len(a)-1]); err == nil {
		t.Fatal("truncated grammar accepted")
	}
	g.Fields[1].Expected = []byte{2}
	if _, err := g.Interpret(a); err == nil {
		t.Fatal("failed field assertion accepted")
	}
}
