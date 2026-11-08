package types

import (
	"encoding/json"
	"testing"

	"github.com/gogo/protobuf/proto"

	"github.com/dreadl0ck/netcap/internal/encoder"
)

func TestConnectionEvidenceRoundTripAndJSONPurity(t *testing.T) {
	encoder.SetConfig(&encoder.Config{MinMax: true})
	t.Cleanup(func() { encoder.SetConfig(nil) })
	c := &Connection{TimestampFirst: 1700000000000000001, TimestampLast: 1700000000000000003, TotalSize: 2147483647, SrcMAC: "02:00:00:00:00:01", DstMAC: "02:00:00:00:00:02", SrcIP: "192.0.2.1", DstIP: "192.0.2.2", SrcPort: "12345", DstPort: "80",
		TotalSize64: 6000000000, AppPayloadSize64: 5000000000, NumPackets64: 3000000000, ObservationID: "fixture-observation", SnapshotSequence: 3,
		CounterSemantics: "tuple-cumulative", LegacyCountersSaturated: true,
		NetworkScope: "if:2/vxlan:fixture:7", Normalization: "complete", ReassembledDatagrams: 2,
		Encapsulations: []*Encapsulation{{Protocol: "vxlan", SrcIP: "192.0.2.3", DstIP: "192.0.2.4", Identifier: 7}}}
	want := proto.Clone(c)
	encoded, err := proto.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	var decoded Connection
	if err := proto.Unmarshal(encoded, &decoded); err != nil {
		t.Fatal(err)
	}
	if !proto.Equal(c, &decoded) {
		t.Fatal("wire round trip lost evidence semantics")
	}
	first, err := c.JSON()
	if err != nil {
		t.Fatal(err)
	}
	second, err := c.JSON()
	if err != nil {
		t.Fatal(err)
	}
	if first != second || !proto.Equal(c, want) {
		t.Fatal("JSON serialization changed observation timestamps")
	}
	if len(c.CSVHeader()) != len(c.CSVRecord()) || len(c.CSVHeader()) != len(c.Encode()) {
		t.Fatal("connection exports lost field alignment")
	}
	values := map[string]string{}
	for i, header := range c.CSVHeader() {
		values[header] = c.CSVRecord()[i]
	}
	var path []*Encapsulation
	if err := json.Unmarshal([]byte(values["Encapsulations"]), &path); err != nil || len(path) != 1 || !proto.Equal(path[0], c.Encapsulations[0]) {
		t.Fatalf("CSV lost tunnel evidence: %v", err)
	}
	if values["NetworkScope"] != c.NetworkScope || values["ReassembledDatagrams"] != "2" || values["Normalization"] != "complete" {
		t.Fatal("CSV lost scoped datagram attribution", values)
	}
	var exported map[string]json.RawMessage
	if err := json.Unmarshal([]byte(first), &exported); err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"NetworkScope", "Encapsulations", "ReassembledDatagrams", "Normalization"} {
		if len(exported[field]) == 0 {
			t.Fatalf("JSON omitted %s", field)
		}
	}
}

func TestFileEvidenceRoundTripAndJSONPurity(t *testing.T) {
	encoder.SetConfig(&encoder.Config{MinMax: true})
	t.Cleanup(func() { encoder.SetConfig(nil) })
	f := &File{Timestamp: 1700000000000000001, CompletenessReason: "unattributed-stream-gap", StreamMissingBytes: 42, StreamInitialLossUnknown: true}
	want := proto.Clone(f)
	encoded, err := proto.Marshal(f)
	if err != nil {
		t.Fatal(err)
	}
	var decoded File
	if err := proto.Unmarshal(encoded, &decoded); err != nil {
		t.Fatal(err)
	}
	if !proto.Equal(f, &decoded) {
		t.Fatal("file wire round trip lost loss metadata")
	}
	first, err := f.JSON()
	if err != nil {
		t.Fatal(err)
	}
	second, err := f.JSON()
	if err != nil {
		t.Fatal(err)
	}
	if first != second || !proto.Equal(f, want) {
		t.Fatal("file JSON serialization changed event time")
	}
	if len(f.CSVHeader()) != len(f.CSVRecord()) || len(f.CSVHeader()) != len(f.Encode()) {
		t.Fatal("file exports lost field alignment")
	}
}
