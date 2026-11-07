package types

import (
	"encoding/json"
	"reflect"
	"testing"

	"github.com/dreadl0ck/netcap/internal/encoder"
	"github.com/gogo/protobuf/proto"
)

func TestSSLv2Exports(t *testing.T) {
	encoder.SetConfig(&encoder.Config{ZScore: true})
	for _, record := range []interface {
		proto.Message
		CSVHeader() []string
		CSVRecord() []string
		Encode() []string
		JSON() (string, error)
	}{
		&TLSClientHello{Timestamp: 1e9, HelloFormat: "SSLv2", HandshakeVersion: 0x303, SSLv2CipherSpecs: []uint32{0x010080, 0xffffff}, SSLv2Challenge: []byte{0, 1, 0xff}},
		&TLSServerHello{Timestamp: 1e9, HelloFormat: "SSLv2", Version: 2, SSLv2CipherSpecs: []uint32{0x010080, 0xffffff}, SSLv2ConnectionID: []byte{0, 1, 0xff}, SSLv2SessionIDHit: true, SSLv2CertificateType: 1},
	} {
		wire, err := proto.Marshal(record)
		if err != nil {
			t.Fatal(err)
		}
		out := reflect.New(reflect.TypeOf(record).Elem()).Interface().(proto.Message)
		if err := proto.Unmarshal(wire, out); err != nil || !proto.Equal(record, out) {
			t.Fatalf("protobuf round trip: %v %v", out, err)
		}
		header, row := record.CSVHeader(), record.CSVRecord()
		if len(header) != len(row) || len(record.Encode()) != len(header) {
			t.Fatal("export column mismatch")
		}
		values := map[string]string{}
		for i, key := range header {
			values[key] = row[i]
		}
		if values["HelloFormat"] != "SSLv2" || values["SSLv2CipherSpecs"] == "" {
			t.Fatal(values)
		}
		if values["SSLv2Challenge"] != "0001ff" && values["SSLv2ConnectionID"] != "0001ff" {
			t.Fatal("lost legacy bytes", values)
		}
		encoded, err := record.JSON()
		if err != nil {
			t.Fatal(err)
		}
		var data map[string]any
		if err := json.Unmarshal([]byte(encoded), &data); err != nil {
			t.Fatal(err)
		}
		if data["HelloFormat"] != "SSLv2" || len(data["SSLv2CipherSpecs"].([]any)) != 2 {
			t.Fatal(data)
		}
	}
}
