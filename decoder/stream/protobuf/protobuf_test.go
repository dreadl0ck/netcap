/*
 * NETCAP - Traffic Analysis Framework
 * Copyright (c) Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
 * License: GNU General Public License v3.0
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

package protobuf

import (
	"bytes"
	"os"
	"testing"
)

// Test data samples.
var (
	// Valid protobuf: field 1 varint=150, field 2 string="test", field 3 varint=0
	validProtobufData = []byte{
		0x08, 0x96, 0x01, // field 1, varint, value 150
		0x12, 0x04, 0x74, 0x65, 0x73, 0x74, // field 2, length-delimited, "test"
		0x18, 0x00, // field 3, varint, value 0
	}

	// All 0xFF — invalid wire types, no varint pattern
	invalidData = []byte{
		0xFF, 0xFF, 0xFF, 0xFF,
		0x00, 0x00, 0x00, 0x00,
	}

	// Plain HTTP text — low structural match for protobuf
	httpData = []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
)

func TestIsProtobufData(t *testing.T) {
	tests := []struct {
		name     string
		data     []byte
		expected bool
	}{
		{"valid protobuf", validProtobufData, true},
		{"invalid data", invalidData, false},
		{"HTTP text", httpData, false},
		{"empty", []byte{}, false},
		{"single byte", []byte{0x08}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsProtobufData(tt.data); got != tt.expected {
				t.Errorf("IsProtobufData() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestDecodeMessages(t *testing.T) {
	tests := []struct {
		name      string
		data      []byte
		wantErr   bool
		wantCount int
	}{
		{"valid message", validProtobufData, false, 1},
		{"empty", []byte{}, true, 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			msgs, err := DecodeMessages(tt.data)
			if (err != nil) != tt.wantErr {
				t.Errorf("DecodeMessages() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !tt.wantErr && len(msgs) != tt.wantCount {
				t.Errorf("DecodeMessages() got %d messages, want %d", len(msgs), tt.wantCount)
			}
		})
	}
}

func TestDecodeMessagesFieldValues(t *testing.T) {
	msgs, err := DecodeMessages(validProtobufData)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(msgs) != 1 {
		t.Fatalf("expected 1 message, got %d", len(msgs))
	}

	fields := msgs[0]

	// Verify wire order and values
	expected := []Field{
		{Number: 1, Type: "varint", Value: "150"},
		{Number: 2, Type: "string", Value: "test"},
		{Number: 3, Type: "varint", Value: "0"},
	}

	if len(fields) != len(expected) {
		t.Fatalf("got %d fields, want %d", len(fields), len(expected))
	}

	for i, want := range expected {
		got := fields[i]
		if got.Number != want.Number || got.Type != want.Type || got.Value != want.Value {
			t.Errorf("field[%d] = {%d %s %s}, want {%d %s %s}",
				i, got.Number, got.Type, got.Value, want.Number, want.Type, want.Value)
		}
	}
}

func TestReadVarint(t *testing.T) {
	tests := []struct {
		name     string
		data     []byte
		expected uint64
		hasError bool
	}{
		{"single byte", []byte{0x08}, 8, false},
		{"multi-byte (150)", []byte{0x96, 0x01}, 150, false},
		{"zero", []byte{0x00}, 0, false},
		{"empty", []byte{}, 0, true},
		{"incomplete continuation", []byte{0x96}, 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			buf := bytes.NewReader(tt.data)
			result, err := ReadVarint(buf)
			if tt.hasError && err == nil {
				t.Error("expected error but got none")
			}
			if !tt.hasError && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
			if !tt.hasError && result != tt.expected {
				t.Errorf("ReadVarint() = %d, want %d", result, tt.expected)
			}
		})
	}
}

func TestCalculateEntropy(t *testing.T) {
	tests := []struct {
		name       string
		data       []byte
		minEntropy float64
		maxEntropy float64
	}{
		{"uniform zeros", []byte{0, 0, 0, 0}, 0.0, 0.01},
		{"protobuf data", validProtobufData, 2.0, 6.0},
		{"all unique", []byte{0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0}, 2.5, 4.0},
		{"empty", []byte{}, 0.0, 0.0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := CalculateEntropy(tt.data)
			if e < tt.minEntropy || e > tt.maxEntropy {
				t.Errorf("CalculateEntropy() = %f, want [%f, %f]", e, tt.minEntropy, tt.maxEntropy)
			}
		})
	}
}

func TestDetectMessageType(t *testing.T) {
	tests := []struct {
		name     string
		fields   []Field
		expected string
	}{
		{
			"grpc request",
			[]Field{
				{Number: 1, Type: "string", Value: "POST"},
				{Number: 2, Type: "string", Value: "/api/v1/test"},
			},
			"grpc_request",
		},
		{
			"timestamp",
			[]Field{{Number: 1, Type: "varint", Value: "1609459200"}},
			"timestamped_message",
		},
		{
			"generic",
			[]Field{
				{Number: 1, Type: "string", Value: "value1"},
				{Number: 2, Type: "varint", Value: "42"},
			},
			"generic",
		},
		{"empty", []Field{}, "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := DetectMessageType(tt.fields); got != tt.expected {
				t.Errorf("DetectMessageType() = %s, want %s", got, tt.expected)
			}
		})
	}
}

func TestDetectServiceName(t *testing.T) {
	tests := []struct {
		name     string
		srcPort  int32
		dstPort  int32
		expected string
	}{
		{"HTTPS/gRPC 443", 443, 12345, "https/grpc"},
		{"HTTP 80", 80, 12345, "http"},
		{"gRPC 9090", 9090, 12345, "grpc"},
		{"gRPC 50051", 50051, 12345, "grpc"},
		{"custom 8080", 8080, 12345, "custom_service"},
		{"unknown", 12345, 54321, "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := DetectServiceName(tt.srcPort, tt.dstPort); got != tt.expected {
				t.Errorf("DetectServiceName() = %s, want %s", got, tt.expected)
			}
		})
	}
}

func TestIsPrintable(t *testing.T) {
	tests := []struct {
		name     string
		data     []byte
		expected bool
	}{
		{"printable", []byte("Hello World"), true},
		{"with null", []byte("Hello\x00World"), false},
		{"symbols", []byte("123!@#"), true},
		{"empty", []byte{}, true},
		{"binary", []byte{0xFF, 0xFE, 0xFD}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsPrintable(tt.data); got != tt.expected {
				t.Errorf("IsPrintable() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestParseMessageWithDeprecatedGroupTypes(t *testing.T) {
	data := []byte{
		0x08, 0x01, // field 1, varint, value 1
		0x1B,       // field 3, wire type 3 (start group) — should be skipped
		0x1C,       // field 3, wire type 4 (end group) — should be skipped
		0x10, 0x02, // field 2, varint, value 2
	}

	buf := bytes.NewReader(data)
	fields, err := ParseMessage(buf)
	if err != nil {
		t.Fatalf("ParseMessage with group types returned error: %v", err)
	}

	if len(fields) != 2 {
		t.Fatalf("got %d fields, want 2", len(fields))
	}
	if fields[0].Number != 1 || fields[0].Value != "1" {
		t.Errorf("field[0] = %+v, want {1 varint 1}", fields[0])
	}
	if fields[1].Number != 2 || fields[1].Value != "2" {
		t.Errorf("field[1] = %+v, want {2 varint 2}", fields[1])
	}
}

func TestPopulateFields(t *testing.T) {
	fields := []Field{
		{Number: 1, Type: "varint", Value: "42"},
		{Number: 2, Type: "string", Value: "hello"},
		{Number: 3, Type: "fixed32", Value: "7"},
	}

	out := make(map[string]string)
	var order []string

	PopulateFields(fields, out, &order)

	if out["varint_1"] != "42" {
		t.Errorf("varint_1 = %s, want 42", out["varint_1"])
	}
	if out["string_2"] != "hello" {
		t.Errorf("string_2 = %s, want hello", out["string_2"])
	}
	if out["fixed32_3"] != "7" {
		t.Errorf("fixed32_3 = %s, want 7", out["fixed32_3"])
	}

	// Verify order preserved
	expectedOrder := []string{"varint_1", "string_2", "fixed32_3"}
	if len(order) != len(expectedOrder) {
		t.Fatalf("order length = %d, want %d", len(order), len(expectedOrder))
	}
	for i, want := range expectedOrder {
		if order[i] != want {
			t.Errorf("order[%d] = %s, want %s", i, order[i], want)
		}
	}
}

func TestFieldOrderPreserved(t *testing.T) {
	// Parse and verify the wire order is preserved through the full pipeline
	msgs, err := DecodeMessages(validProtobufData)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	out := make(map[string]string)
	var order []string
	PopulateFields(msgs[0], out, &order)

	expectedOrder := []string{"varint_1", "string_2", "varint_3"}
	if len(order) != len(expectedOrder) {
		t.Fatalf("order length = %d, want %d", len(order), len(expectedOrder))
	}
	for i, want := range expectedOrder {
		if order[i] != want {
			t.Errorf("order[%d] = %s, want %s", i, order[i], want)
		}
	}
}

// --- Multi-interpretation tests ---

func TestVarintAlternatives(t *testing.T) {
	tests := []struct {
		name     string
		value    uint64
		wantKeys []string
	}{
		{
			"small value with bool",
			1,
			[]string{"sint64", "int64", "bool"},
		},
		{
			"zero with bool",
			0,
			[]string{"sint64", "int64", "bool"},
		},
		{
			"large value no bool",
			150,
			[]string{"sint64", "int64"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			alts := varintAlternatives(tt.value)
			for _, key := range tt.wantKeys {
				if _, ok := alts[key]; !ok {
					t.Errorf("missing key %q in alternatives", key)
				}
			}
		})
	}

	// Verify zigzag decoding: zigzag(1) = -1, zigzag(2) = 1, zigzag(3) = -2
	alts := varintAlternatives(1)
	if alts["sint64"] != "-1" {
		t.Errorf("zigzag(1) = %s, want -1", alts["sint64"])
	}
	alts = varintAlternatives(2)
	if alts["sint64"] != "1" {
		t.Errorf("zigzag(2) = %s, want 1", alts["sint64"])
	}
}

func TestFixed64Alternatives(t *testing.T) {
	alts := fixed64Alternatives(4614253070214989087) // math.Float64bits(3.14)
	if _, ok := alts["double"]; !ok {
		t.Error("missing double alternative")
	}
	if _, ok := alts["int64"]; !ok {
		t.Error("missing int64 alternative")
	}
}

func TestFixed32Alternatives(t *testing.T) {
	alts := fixed32Alternatives(1078523331) // math.Float32bits(3.14)
	if _, ok := alts["float"]; !ok {
		t.Error("missing float alternative")
	}
	if _, ok := alts["int32"]; !ok {
		t.Error("missing int32 alternative")
	}
}

func TestMultiInterpretationEnabled(t *testing.T) {
	// Enable alternatives
	SetShowAlternatives(true)
	defer SetShowAlternatives(false)

	msgs, err := DecodeMessages(validProtobufData)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Field 1 is varint 150 — should have alternatives
	field := msgs[0][0]
	if field.Alternatives == nil {
		t.Fatal("expected alternatives for varint field when showAlternatives=true")
	}
	if _, ok := field.Alternatives["sint64"]; !ok {
		t.Error("missing sint64 alternative")
	}
}

func TestMultiInterpretationDisabled(t *testing.T) {
	SetShowAlternatives(false)

	msgs, err := DecodeMessages(validProtobufData)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// No alternatives when disabled
	field := msgs[0][0]
	if field.Alternatives != nil {
		t.Error("expected nil alternatives when showAlternatives=false")
	}
}

func TestPopulateFieldsDoesNotIncludeAlternatives(t *testing.T) {
	fields := []Field{
		{
			Number:       1,
			Type:         "varint",
			Value:        "150",
			Alternatives: map[string]string{"sint64": "75", "int64": "150"},
		},
	}

	out := make(map[string]string)
	var order []string
	PopulateFields(fields, out, &order)

	if out["varint_1"] != "150" {
		t.Errorf("primary value = %s, want 150", out["varint_1"])
	}
	// Alternatives should NOT be in the primary Fields map
	if _, ok := out["varint_1.as_sint64"]; ok {
		t.Error("alternatives should not be stored in primary Fields map")
	}
	if _, ok := out["varint_1.as_int64"]; ok {
		t.Error("alternatives should not be stored in primary Fields map")
	}
}

// --- Packed repeated tests ---

func TestTryParsePackedVarints(t *testing.T) {
	// Two varints: 150 (0x96 0x01) and 300 (0xAC 0x02)
	data := []byte{0x96, 0x01, 0xAC, 0x02}
	result := tryParsePackedVarints(data)
	if result == nil {
		t.Fatal("expected packed varints")
	}
	if len(result) != 2 || result[0] != 150 || result[1] != 300 {
		t.Errorf("got %v, want [150, 300]", result)
	}
}

func TestTryParsePackedVarintsInvalid(t *testing.T) {
	// Single varint — not meaningful as packed
	if tryParsePackedVarints([]byte{0x01}) != nil {
		t.Error("single varint should not be packed")
	}
	// Incomplete varint
	if tryParsePackedVarints([]byte{0x80}) != nil {
		t.Error("incomplete varint should fail")
	}
}

func TestTryParsePackedFixed32(t *testing.T) {
	// Two little-endian uint32s: 1 and 2
	data := []byte{
		0x01, 0x00, 0x00, 0x00,
		0x02, 0x00, 0x00, 0x00,
	}
	result := tryParsePackedFixed32(data)
	if result == nil {
		t.Fatal("expected packed fixed32")
	}
	if len(result) != 2 || result[0] != 1 || result[1] != 2 {
		t.Errorf("got %v, want [1, 2]", result)
	}
}

func TestTryParsePackedFixed32Invalid(t *testing.T) {
	// Not aligned to 4 bytes
	if tryParsePackedFixed32([]byte{0x01, 0x02, 0x03}) != nil {
		t.Error("non-aligned data should fail")
	}
	// Too short (need at least 8 bytes for 2 values)
	if tryParsePackedFixed32([]byte{0x01, 0x00, 0x00, 0x00}) != nil {
		t.Error("single value should fail")
	}
}

func TestTryParsePackedFixed64(t *testing.T) {
	// Two little-endian uint64s: 1 and 2
	data := []byte{
		0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	}
	result := tryParsePackedFixed64(data)
	if result == nil {
		t.Fatal("expected packed fixed64")
	}
	if len(result) != 2 || result[0] != 1 || result[1] != 2 {
		t.Errorf("got %v, want [1, 2]", result)
	}
}

func TestPackedVarintInMessage(t *testing.T) {
	// Protobuf message with field 4 as packed repeated varints [1, 2, 3]
	// Tag: field 4, wire type 2 (length-delimited) = (4 << 3) | 2 = 0x22
	// Length: 3
	// Values: 1, 2, 3 (single-byte varints, but NOT printable ASCII)
	data := []byte{
		0x22, 0x03, 0x01, 0x02, 0x03,
	}

	msgs, err := DecodeMessages(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(msgs) != 1 || len(msgs[0]) != 1 {
		t.Fatalf("expected 1 message with 1 field, got %d messages", len(msgs))
	}

	f := msgs[0][0]
	if f.Type != "packed_varint" {
		t.Errorf("type = %s, want packed_varint", f.Type)
	}
	if f.Value != "[1, 2, 3]" {
		t.Errorf("value = %s, want [1, 2, 3]", f.Value)
	}
}

// --- Schema tests ---

func TestParseMessageTypeMappings(t *testing.T) {
	ParseMessageTypeMappings([]string{
		"50051:tutorial.AddressBook",
		"8080:api.Request",
		"invalid",
		"notaport:foo.Bar",
	})

	mt, ok := lookupMessageTypeByPort(50051)
	if !ok || mt != "tutorial.AddressBook" {
		t.Errorf("port 50051 = %q, want tutorial.AddressBook", mt)
	}
	mt, ok = lookupMessageTypeByPort(8080)
	if !ok || mt != "api.Request" {
		t.Errorf("port 8080 = %q, want api.Request", mt)
	}
	_, ok = lookupMessageTypeByPort(9999)
	if ok {
		t.Error("unexpected mapping for port 9999")
	}
}

func TestSchemaRegistryWithTestProto(t *testing.T) {
	// Create a temporary .proto file
	tmpDir := t.TempDir()
	protoContent := `syntax = "proto3";
package test;

enum PhoneType {
  MOBILE = 0;
  HOME = 1;
  WORK = 2;
}

message Person {
  string name = 1;
  int32 id = 2;
  string email = 3;
  PhoneType phone_type = 4;
}
`
	protoPath := tmpDir + "/test.proto"
	if err := os.WriteFile(protoPath, []byte(protoContent), 0o644); err != nil {
		t.Fatalf("failed to write test proto: %v", err)
	}

	reg, err := NewSchemaRegistry([]string{tmpDir})
	if err != nil {
		t.Fatalf("NewSchemaRegistry failed: %v", err)
	}

	if reg.FileCount() != 1 {
		t.Errorf("FileCount = %d, want 1", reg.FileCount())
	}
	if reg.MessageCount() != 1 {
		t.Errorf("MessageCount = %d, want 1", reg.MessageCount())
	}

	md, ok := reg.LookupMessage("test.Person")
	if !ok {
		t.Fatal("failed to look up test.Person")
	}

	if string(md.FullName()) != "test.Person" {
		t.Errorf("FullName = %s, want test.Person", md.FullName())
	}
}

func TestResolveFieldsWithSchema(t *testing.T) {
	// Create a temp proto and compile it
	tmpDir := t.TempDir()
	protoContent := `syntax = "proto3";
package test;

enum PhoneType {
  MOBILE = 0;
  HOME = 1;
  WORK = 2;
}

message Person {
  string name = 1;
  int32 id = 2;
  string email = 3;
  PhoneType phone_type = 4;
}
`
	if err := os.WriteFile(tmpDir+"/test.proto", []byte(protoContent), 0o644); err != nil {
		t.Fatalf("failed to write test proto: %v", err)
	}

	reg, err := NewSchemaRegistry([]string{tmpDir})
	if err != nil {
		t.Fatalf("NewSchemaRegistry failed: %v", err)
	}

	md, ok := reg.LookupMessage("test.Person")
	if !ok {
		t.Fatal("failed to look up test.Person")
	}

	// Simulate wire-format fields
	fields := []Field{
		{Number: 1, Type: "string", Value: "Alice"},
		{Number: 2, Type: "varint", Value: "42"},
		{Number: 3, Type: "string", Value: "alice@example.com"},
		{Number: 4, Type: "varint", Value: "2"},  // WORK enum
		{Number: 99, Type: "varint", Value: "7"},  // unknown field
	}

	named := ResolveFields(fields, md)

	if named["name"] != "Alice" {
		t.Errorf("name = %q, want Alice", named["name"])
	}
	if named["id"] != "42" {
		t.Errorf("id = %q, want 42", named["id"])
	}
	if named["email"] != "alice@example.com" {
		t.Errorf("email = %q, want alice@example.com", named["email"])
	}
	if named["phone_type"] != "WORK" {
		t.Errorf("phone_type = %q, want WORK", named["phone_type"])
	}
	// Unknown field kept with wire-format key
	if named["varint_99"] != "7" {
		t.Errorf("unknown field = %q, want 7", named["varint_99"])
	}
}

func TestLengthDelimitedAlternatives(t *testing.T) {
	SetShowAlternatives(true)
	defer SetShowAlternatives(false)

	// Binary data that parses as packed fixed32
	data := []byte{
		0x01, 0x00, 0x00, 0x00,
		0x02, 0x00, 0x00, 0x00,
	}

	alts := lengthDelimitedAlternatives(data)

	if _, ok := alts["bytes"]; !ok {
		t.Error("missing bytes alternative")
	}
	if _, ok := alts["packed_fixed32"]; !ok {
		t.Error("missing packed_fixed32 alternative")
	}
}

// Benchmarks

func BenchmarkIsProtobufData(b *testing.B) {
	for b.Loop() {
		IsProtobufData(validProtobufData)
	}
}

func BenchmarkDecodeMessages(b *testing.B) {
	for b.Loop() {
		DecodeMessages(validProtobufData)
	}
}

func BenchmarkCalculateEntropy(b *testing.B) {
	data := make([]byte, 1024)
	for i := range data {
		data[i] = byte(i % 256)
	}

	b.ResetTimer()
	for b.Loop() {
		CalculateEntropy(data)
	}
}
