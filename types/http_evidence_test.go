package types

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"reflect"
	"testing"

	"github.com/dreadl0ck/netcap/internal/encoder"

	"github.com/gogo/protobuf/jsonpb"
	"github.com/gogo/protobuf/proto"
)

func TestHTTPEvidenceExports(t *testing.T) {
	encoder.SetConfig(&encoder.Config{MinMax: true})
	t.Cleanup(func() { encoder.SetConfig(nil) })
	record := &HTTP{Timestamp: 123, Method: "GET", Proto: "HTTP/2.0", HTTP2StreamID: 3, RawRequestLine: []byte("GET /a\xff HTTP/1.1\r\n"), RawResponseLine: []byte("HTTP/1.1 200 OK\r\n"), RequestHeaders: []*HTTPHeaderEvidence{{Name: []byte("x"), Value: []byte{0xff}, Raw: []byte("x: \xff\r\n")}, {Name: []byte("x"), Value: []byte("duplicate")}}, ParseQualifications: []string{"duplicate-header"}, ResponseTrailers: []*HTTPHeaderEvidence{{Name: []byte("digest"), Value: []byte("fixture")}}}
	want := proto.Clone(record)
	first, err := record.JSON()
	if err != nil {
		t.Fatal(err)
	}
	second, err := record.JSON()
	if err != nil || first != second || !proto.Equal(record, want) {
		t.Fatal("JSON mutated evidence", err)
	}
	wire, err := proto.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	var decoded HTTP
	if err = proto.Unmarshal(wire, &decoded); err != nil || !proto.Equal(record, &decoded) {
		t.Fatal(err, &decoded)
	}
	for _, marshal := range []func() ([]byte, error){func() ([]byte, error) { return json.Marshal(record) }, func() ([]byte, error) {
		var b bytes.Buffer
		err := (&jsonpb.Marshaler{OrigName: true}).Marshal(&b, record)
		return b.Bytes(), err
	}} {
		data, err := marshal()
		if err != nil || !bytes.Contains(data, []byte(base64.StdEncoding.EncodeToString(record.RawRequestLine))) || !bytes.Contains(data, []byte("HTTP2StreamID")) {
			t.Fatal(string(data), err)
		}
	}
	if len(record.CSVHeader()) != len(record.CSVRecord()) || len(record.Encode()) != len(record.CSVHeader()) {
		t.Fatal("export column mismatch")
	}
	values := map[string]string{}
	for i, name := range record.CSVHeader() {
		values[name] = record.CSVRecord()[i]
	}
	var headers []*HTTPHeaderEvidence
	if err := json.Unmarshal([]byte(values["RequestHeaders"]), &headers); err != nil || !reflect.DeepEqual(headers, record.RequestHeaders) || values["HTTP2StreamID"] != "3" {
		t.Fatal(values, err)
	}
	// The original tags remain readable independently of the new evidence fields.
	legacy := []byte{0x08, 0x7b, 0x1a, 0x03, 'G', 'E', 'T'}
	if err := proto.Unmarshal(legacy, &decoded); err != nil || decoded.Timestamp != 123 || decoded.Method != "GET" {
		t.Fatal(&decoded, err)
	}
}
