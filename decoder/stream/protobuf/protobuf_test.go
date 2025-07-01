/*
 * NETCAP - Traffic Analysis Framework
 * Copyright (c) 2017-2020 Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

package protobuf

import (
	"bytes"
	"testing"
)

// Test data samples
var (
	// Valid protobuf data with varint encoding
	validProtobufData = []byte{
		0x08, 0x96, 0x01, // field 1, varint, value 150
		0x12, 0x04, 0x74, 0x65, 0x73, 0x74, // field 2, length-delimited, "test"
		0x18, 0x00, // field 3, varint, value 0
	}

	// Invalid data (should not be detected as protobuf)
	invalidData = []byte{
		0xFF, 0xFF, 0xFF, 0xFF, // Invalid wire types and patterns
		0x00, 0x00, 0x00, 0x00,
	}

	// HTTP data (should not be detected as protobuf)
	httpData = []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")

	// Binary data with some protobuf-like patterns
	mixedData = []byte{
		0x08, 0x01, // valid protobuf start
		0xFF, 0xFF, 0xFF, 0xFF, // invalid continuation
		0x12, 0x02, 0x41, 0x42, // field 2, "AB"
	}
)

func TestIsProtobufData(t *testing.T) {
	tests := []struct {
		name     string
		data     []byte
		expected bool
	}{
		{
			name:     "valid protobuf data",
			data:     validProtobufData,
			expected: true,
		},
		{
			name:     "invalid data",
			data:     invalidData,
			expected: false,
		},
		{
			name:     "HTTP data",
			data:     httpData,
			expected: false,
		},
		{
			name:     "mixed data",
			data:     mixedData,
			expected: false, // Mixed data might not meet all heuristics
		},
		{
			name:     "empty data",
			data:     []byte{},
			expected: false,
		},
		{
			name:     "single byte",
			data:     []byte{0x08},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isProtobufData(tt.data)
			if result != tt.expected {
				t.Errorf("isProtobufData() = %v, expected %v", result, tt.expected)
			}
		})
	}
}

func TestDecodeProtobufMessages(t *testing.T) {
	tests := []struct {
		name        string
		data        []byte
		expectError bool
		expectMsg   bool
	}{
		{
			name:        "valid protobuf message",
			data:        validProtobufData,
			expectError: false,
			expectMsg:   true,
		},
		{
			name:        "invalid data",
			data:        invalidData,
			expectError: true,
			expectMsg:   false,
		},
		{
			name:        "empty data",
			data:        []byte{},
			expectError: true,
			expectMsg:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			messages, err := decodeProtobufMessages(tt.data)
			
			if tt.expectError && err == nil {
				t.Errorf("expected error but got none")
			}
			if !tt.expectError && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
			if tt.expectMsg && len(messages) == 0 {
				t.Errorf("expected messages but got none")
			}
			if !tt.expectMsg && len(messages) > 0 {
				t.Errorf("expected no messages but got %d", len(messages))
			}
		})
	}
}

func TestReadVarint(t *testing.T) {
	tests := []struct {
		name     string
		data     []byte
		expected uint64
		hasError bool
	}{
		{
			name:     "single byte varint",
			data:     []byte{0x08},
			expected: 8,
			hasError: false,
		},
		{
			name:     "multi-byte varint",
			data:     []byte{0x96, 0x01}, // 150
			expected: 150,
			hasError: false,
		},
		{
			name:     "empty data",
			data:     []byte{},
			expected: 0,
			hasError: true,
		},
		{
			name:     "incomplete varint",
			data:     []byte{0x96}, // continuation bit set but no next byte
			expected: 0,
			hasError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			buf := bytes.NewReader(tt.data)
			result, err := readVarint(buf)
			
			if tt.hasError && err == nil {
				t.Errorf("expected error but got none")
			}
			if !tt.hasError && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
			if !tt.hasError && result != tt.expected {
				t.Errorf("readVarint() = %d, expected %d", result, tt.expected)
			}
		})
	}
}

func TestCalculateEntropy(t *testing.T) {
	tests := []struct {
		name     string
		data     []byte
		minEntropy float64
		maxEntropy float64
	}{
		{
			name:       "uniform data",
			data:       []byte{0x00, 0x00, 0x00, 0x00},
			minEntropy: 0.0,
			maxEntropy: 0.1,
		},
		{
			name:       "mixed data",
			data:       validProtobufData,
			minEntropy: 2.0,
			maxEntropy: 6.0,
		},
		{
			name:       "random-like data",
			data:       []byte{0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0},
			minEntropy: 2.5,
			maxEntropy: 4.0,
		},
		{
			name:       "empty data",
			data:       []byte{},
			minEntropy: 0.0,
			maxEntropy: 0.0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			entropy := calculateEntropy(tt.data)
			if entropy < tt.minEntropy || entropy > tt.maxEntropy {
				t.Errorf("calculateEntropy() = %f, expected between %f and %f", 
					entropy, tt.minEntropy, tt.maxEntropy)
			}
		})
	}
}

func TestDetectMessageType(t *testing.T) {
	tests := []struct {
		name     string
		message  map[string]interface{}
		expected string
	}{
		{
			name: "grpc-like message",
			message: map[string]interface{}{
				"field_1": "POST",
				"field_2": "/api/v1/test",
			},
			expected: "grpc_request",
		},
		{
			name: "timestamped message",
			message: map[string]interface{}{
				"field_1": uint64(1609459200), // Valid timestamp
			},
			expected: "timestamped_message",
		},
		{
			name: "generic message",
			message: map[string]interface{}{
				"field_1": "value1",
				"field_2": uint64(42),
			},
			expected: "generic",
		},
		{
			name:     "empty message",
			message:  map[string]interface{}{},
			expected: "unknown",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := detectMessageType(tt.message)
			if result != tt.expected {
				t.Errorf("detectMessageType() = %s, expected %s", result, tt.expected)
			}
		})
	}
}

func TestDetectServiceName(t *testing.T) {
	tests := []struct {
		name     string
		data     []byte
		srcPort  int32
		dstPort  int32
		expected string
	}{
		{
			name:     "HTTPS/gRPC port",
			data:     validProtobufData,
			srcPort:  443,
			dstPort:  12345,
			expected: "https/grpc",
		},
		{
			name:     "HTTP port",
			data:     validProtobufData,
			srcPort:  80,
			dstPort:  12345,
			expected: "http",
		},
		{
			name:     "gRPC port",
			data:     validProtobufData,
			srcPort:  9090,
			dstPort:  12345,
			expected: "grpc",
		},
		{
			name:     "custom service port",
			data:     validProtobufData,
			srcPort:  8080,
			dstPort:  12345,
			expected: "custom_service",
		},
		{
			name:     "unknown port",
			data:     validProtobufData,
			srcPort:  12345,
			dstPort:  54321,
			expected: "unknown",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := detectServiceName(tt.data, tt.srcPort, tt.dstPort)
			if result != tt.expected {
				t.Errorf("detectServiceName() = %s, expected %s", result, tt.expected)
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
		{
			name:     "printable ASCII",
			data:     []byte("Hello World"),
			expected: true,
		},
		{
			name:     "with non-printable",
			data:     []byte("Hello\x00World"),
			expected: false,
		},
		{
			name:     "numbers and symbols",
			data:     []byte("123!@#"),
			expected: true,
		},
		{
			name:     "empty data",
			data:     []byte{},
			expected: true,
		},
		{
			name:     "binary data",
			data:     []byte{0xFF, 0xFE, 0xFD},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isPrintable(tt.data)
			if result != tt.expected {
				t.Errorf("isPrintable() = %v, expected %v", result, tt.expected)
			}
		})
	}
}

// Benchmark tests
func BenchmarkIsProtobufData(b *testing.B) {
	for i := 0; i < b.N; i++ {
		isProtobufData(validProtobufData)
	}
}

func BenchmarkDecodeProtobufMessages(b *testing.B) {
	for i := 0; i < b.N; i++ {
		decodeProtobufMessages(validProtobufData)
	}
}

func BenchmarkCalculateEntropy(b *testing.B) {
	data := make([]byte, 1024)
	for i := range data {
		data[i] = byte(i % 256)
	}
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		calculateEntropy(data)
	}
}