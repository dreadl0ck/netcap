package types

import (
	"encoding/json"
	"slices"
	"testing"

	"github.com/gogo/protobuf/proto"
)

func TestIMAPObservationExports(t *testing.T) {
	m := &IMAP{Command: "CAPABILITY", Notes: "after-rst; endpoint delivery unconfirmed"}
	wire, err := proto.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	var decoded IMAP
	if err := proto.Unmarshal(wire, &decoded); err != nil || decoded.Notes != m.Notes {
		t.Fatalf("protobuf lost qualification: %v / %v", &decoded, err)
	}
	text, err := decoded.JSON()
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]any
	if err := json.Unmarshal([]byte(text), &fields); err != nil || fields["Notes"] != m.Notes {
		t.Fatalf("JSON lost qualification: %s / %v", text, err)
	}
	index := slices.Index(m.CSVHeader(), "Notes")
	if index < 0 || m.CSVRecord()[index] != m.Notes || len(m.CSVRecord()) != len(m.CSVHeader()) {
		t.Fatal("CSV fields lost or misaligned qualification")
	}
}
