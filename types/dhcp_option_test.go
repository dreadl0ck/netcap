package types

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/gogo/protobuf/proto"
)

func TestDHCPOptionLosslessExports(t *testing.T) {
	raw := make([]byte, 256)
	for i := range raw {
		raw[i] = byte(i)
	}
	data, encoding := DHCPOptionPresentation(raw)
	if encoding != "hex" || len(data) != 512 {
		t.Fatalf("binary presentation: %q %q", data, encoding)
	}
	v4 := &DHCPv4{Options: []*DHCPOption{{Type: 43, Length: 256, Data: data, RawData: raw, DataEncoding: encoding}}}
	v6 := &DHCPv6{Options: []*DHCPv6Option{{Code: 17, Length: 256, Data: data, RawData: raw, DataEncoding: encoding}}}
	for _, record := range []AuditRecord{v4, v6} {
		message := record.(proto.Message)
		wire, err := proto.Marshal(message)
		if err != nil {
			t.Fatal(err)
		}
		clone := proto.Clone(message)
		clone.Reset()
		if err = proto.Unmarshal(wire, clone); err != nil {
			t.Fatal(err)
		}
		if !proto.Equal(message, clone) {
			t.Fatal("protobuf lost option bytes")
		}
		text, err := record.JSON()
		if err != nil {
			t.Fatal(err)
		}
		var decoded struct {
			Options []struct {
				RawData      []byte
				Data         string
				DataEncoding string
			}
		}
		if err = json.Unmarshal([]byte(text), &decoded); err != nil {
			t.Fatal(err)
		}
		if len(decoded.Options) != 1 || !bytes.Equal(decoded.Options[0].RawData, raw) || decoded.Options[0].Data != data || decoded.Options[0].DataEncoding != encoding {
			t.Fatalf("JSON lost option evidence: %s", text)
		}
		csv := record.CSVRecord()
		if len(csv) != len(record.CSVHeader()) || !strings.Contains(csv[len(csv)-1], data) {
			t.Fatalf("CSV options missing: %v", csv)
		}
	}
}

func TestDHCPOptionPresentation(t *testing.T) {
	for _, tc := range []struct{ raw, data, encoding string }{
		{"", "", "utf-8"},
		{"printer.local", "printer.local", "utf-8"},
		{"café", "café", "utf-8"},
		{"\xff\x00", "ff00", "hex"},
		{"\x01hello", "0168656c6c6f", "hex"},
	} {
		data, encoding := DHCPOptionPresentation([]byte(tc.raw))
		if data != tc.data || encoding != tc.encoding {
			t.Fatalf("%x: got %q/%s", tc.raw, data, encoding)
		}
	}
	// Historical field 3 remains readable without new fields 4 and 5.
	old := &DHCPOption{}
	if err := proto.Unmarshal([]byte{0x1a, 0x03, 'o', 'l', 'd'}, old); err != nil || old.Data != "old" || len(old.RawData) != 0 {
		t.Fatalf("legacy option: %+v, %v", old, err)
	}
}

func FuzzDHCPOptionRoundTrip(f *testing.F) {
	f.Add([]byte{0xff, 0x00, 0x80, 'a'})
	f.Add([]byte("hostname"))
	f.Fuzz(func(t *testing.T, raw []byte) {
		data, encoding := DHCPOptionPresentation(raw)
		o := &DHCPOption{Data: data, RawData: raw, DataEncoding: encoding}
		wire, err := proto.Marshal(o)
		if err != nil {
			t.Fatal(err)
		}
		decoded := &DHCPOption{}
		if err = proto.Unmarshal(wire, decoded); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(raw, decoded.RawData) {
			t.Fatal("lost bytes")
		}
	})
}
