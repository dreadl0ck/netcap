package rules

import (
	"bytes"
	"reflect"
	"testing"

	"github.com/dreadl0ck/netcap/types"
	"github.com/gogo/protobuf/proto"
)

func TestCanonicalRuleRecordPreservesMapBearingRecords(t *testing.T) {
	fields := map[string]string{"fixture-z": "\xff", "fixture-a": "first", "fixture-b": "second", "fixture-c": "third"}
	for _, record := range []proto.Message{
		&types.LinkFrame{Fields: fields},
		&types.HTTP{RequestHeader: fields, ResponseHeader: fields, Parameters: fields},
		&types.USB{Fields: fields},
		&types.Host{Protocols: map[string]*types.Protocol{"tcp": {Packets: 2}, "udp": {Packets: 3}, "icmp": {Packets: 4}}, SNIs: map[string]int64{"a": 1, "b": 2, "c": 3}},
		&types.Mail{Body: []*types.MailPart{{ID: "first", Header: fields}, {ID: "second", Header: fields}}},
		&types.Syslog{StructuredData: []*types.SyslogStructuredData{{ID: "first", Parameters: fields}, {ID: "second", Parameters: fields}}},
		&types.QUICClientHello{TagValues: fields},
		&types.Protobuf{Fields: fields, SchemaFields: fields, FieldAlternatives: fields},
	} {
		t.Run(reflect.TypeOf(record).Elem().Name(), func(t *testing.T) {
			want, err := canonicalRuleRecord(record)
			if err != nil {
				t.Fatal(err)
			}
			for range 64 {
				got, err := canonicalRuleRecord(record)
				if err != nil || !bytes.Equal(got, want) {
					t.Fatalf("unstable encoding: %v", err)
				}
			}
			roundTrip := reflect.New(reflect.TypeOf(record).Elem()).Interface().(proto.Message)
			if err := proto.Unmarshal(want, roundTrip); err != nil || !proto.Equal(record, roundTrip) {
				t.Fatalf("canonical encoding changed the record: %v", err)
			}
		})
	}
}
