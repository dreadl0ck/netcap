package types

import (
	"encoding/json"
	"reflect"
	"testing"

	"github.com/dreadl0ck/netcap/internal/encoder"
	"github.com/gogo/protobuf/proto"
)

func TestAlertAggregationWireJSONCSV(t *testing.T) {
	a := &Alert{Timestamp: 0, Name: "network.scan", AggregateKey: "scope-and-subject", Count: 42, FirstSeen: 0, LastSeen: 1234567890, Examples: []string{`{"at":0,"sample":"a,b"}`, `{"at":1234567890}`}}
	data, err := proto.Marshal(a)
	if err != nil {
		t.Fatal(err)
	}
	var decoded Alert
	if err := proto.Unmarshal(data, &decoded); err != nil || !reflect.DeepEqual(a, &decoded) {
		t.Fatal("wire roundtrip", &decoded, err)
	}
	text, err := a.JSON()
	if err != nil {
		t.Fatal(err)
	}
	var obj map[string]json.RawMessage
	if err := json.Unmarshal([]byte(text), &obj); err != nil {
		t.Fatal(err)
	}
	var examples []string
	if err := json.Unmarshal(obj["Examples"], &examples); err != nil || !reflect.DeepEqual(a.Examples, examples) {
		t.Fatal("JSON examples lost", text, err)
	}
	if string(obj["Count"]) != `"42"` || string(obj["LastSeen"]) != `"1234"` || a.LastSeen != 1234567890 {
		t.Fatal("JSON units/count or receiver mutation", text, a)
	}
	encoder.SetConfig(&encoder.Config{ZScore: true})
	header, row := a.CSVHeader(), a.CSVRecord()
	if len(header) != len(row) || len(header) != len(a.Encode()) {
		t.Fatal("column mismatch")
	}
	fields := map[string]string{}
	for i, h := range header {
		fields[h] = row[i]
	}
	if fields["Count"] != "42" || fields["AggregateKey"] != a.AggregateKey || fields["FirstSeen"] != formatTimestamp(0) || fields["LastSeen"] != formatTimestamp(a.LastSeen) {
		t.Fatal(fields)
	}
	if err := json.Unmarshal([]byte(fields["Examples"]), &examples); err != nil || !reflect.DeepEqual(a.Examples, examples) {
		t.Fatal(fields, err)
	}
	a.Inc()
	var legacy Alert
	if err := proto.Unmarshal([]byte{8, 1}, &legacy); err != nil || legacy.Timestamp != 1 || legacy.Count != 0 {
		t.Fatal("legacy alert compatibility", &legacy, err)
	}
}
