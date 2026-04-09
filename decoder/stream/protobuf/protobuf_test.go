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
