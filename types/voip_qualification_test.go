package types

import (
	"strings"
	"testing"

	"github.com/dreadl0ck/netcap/internal/encoder"
	"github.com/gogo/protobuf/proto"
)

func TestVoIPQualificationSerialization(t *testing.T) {
	encoder.SetConfig(&encoder.Config{ZScore: true})
	for _, record := range []interface {
		proto.Message
		CSVHeader() []string
		CSVRecord() []string
		Encode() []string
		JSON() (string, error)
	}{
		&SIP{TCPObservation: "after-rst"},
		&RTP{AssociationQualification: "sip-association-capacity"},
	} {
		wire, err := proto.Marshal(record)
		if err != nil {
			t.Fatal(err)
		}
		copy := proto.Clone(record)
		copy.Reset()
		if err := proto.Unmarshal(wire, copy); err != nil || !proto.Equal(record, copy) {
			t.Fatalf("protobuf: %v, %v", copy, err)
		}
		field, value := "TCPObservation", "after-rst"
		if _, ok := record.(*RTP); ok {
			field, value = "AssociationQualification", "sip-association-capacity"
		}
		found := false
		csv, encoded := record.CSVRecord(), record.Encode()
		for i, h := range record.CSVHeader() {
			if h == field {
				found = true
				if csv[i] != value || encoded[i] == "" {
					t.Fatalf("CSV/encoded qualification: %T", record)
				}
			}
		}
		if !found {
			t.Fatalf("missing field %s", field)
		}
		json, err := record.JSON()
		if err != nil || !strings.Contains(json, value) {
			t.Fatalf("JSON: %s %v", json, err)
		}
	}
}
