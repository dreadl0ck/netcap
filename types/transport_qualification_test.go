package types

import (
	"strings"
	"testing"

	"github.com/gogo/protobuf/proto"
)

func TestTLSTransportQualificationSerialization(t *testing.T) {
	for _, record := range []interface {
		proto.Message
		CSVHeader() []string
		CSVRecord() []string
		JSON() (string, error)
	}{
		&TLSRecord{TCPObservation: "after-rst"},
		&TLSCertificate{TCPObservation: "after-rst"},
		&TLSClientHello{ReassemblyStatus: "after-rst; endpoint delivery unconfirmed"},
		&TLSServerHello{ReassemblyStatus: "after-rst; endpoint delivery unconfirmed"},
	} {
		wire, err := proto.Marshal(record)
		if err != nil {
			t.Fatal(err)
		}
		copy := proto.Clone(record)
		copy.Reset()
		if err := proto.Unmarshal(wire, copy); err != nil || !proto.Equal(record, copy) {
			t.Fatalf("protobuf qualification lost: %v, %v", copy, err)
		}
		if len(record.CSVHeader()) != len(record.CSVRecord()) || !strings.Contains(strings.Join(record.CSVRecord(), ","), "after-rst") {
			t.Fatalf("CSV qualification lost: %T", record)
		}
		json, err := record.JSON()
		if err != nil || !strings.Contains(json, "after-rst") {
			t.Fatalf("JSON qualification lost: %T, %v", record, err)
		}
	}
}
