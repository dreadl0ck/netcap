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

package quic

import (
	"encoding/hex"
	"testing"
)

// Test IETF QUIC version detection
func TestIsIETFQUICPacket(t *testing.T) {
	tests := []struct {
		name     string
		payload  string // hex encoded
		expected bool
	}{
		{
			name:     "IETF QUIC v1 Initial",
			payload:  "c000000001", // Long header, version 0x00000001
			expected: true,
		},
		{
			name:     "IETF QUIC v2 Initial",
			payload:  "c06b3343cf", // Long header, version 0x6b3343cf
			expected: true,
		},
		{
			name:     "Version Negotiation",
			payload:  "c000000000", // Long header, version 0
			expected: true,
		},
		{
			name:     "Short header with fixed bit",
			payload:  "40001122334455", // Short header with fixed bit set and DCID
			expected: true,
		},
		{
			name:     "Invalid short header",
			payload:  "00001122334455", // Short header without fixed bit
			expected: false,
		},
		{
			name:     "Too short",
			payload:  "c000",
			expected: false,
		},
		{
			name:     "Unknown version",
			payload:  "c0deadbeef",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			payload, err := hex.DecodeString(tt.payload)
			if err != nil {
				t.Fatalf("Failed to decode hex: %v", err)
			}

			result := IsIETFQUICPacket(payload)
			if result != tt.expected {
				t.Errorf("IsIETFQUICPacket() = %v, want %v", result, tt.expected)
			}
		})
	}
}

// Test gQUIC version detection
func TestIsGQUICPacket(t *testing.T) {
	tests := []struct {
		name     string
		payload  string // hex encoded
		expected bool
	}{
		{
			name:     "gQUIC Q043",
			payload:  "0d51303433" + "0000000000000000", // Public flags + 'Q043' + CID
			expected: true,
		},
		{
			name:     "gQUIC Q046",
			payload:  "0d51303436" + "0000000000000000",
			expected: true,
		},
		{
			name:     "Not gQUIC",
			payload:  "0d00000001" + "0000000000000000",
			expected: false,
		},
		{
			name:     "Too short",
			payload:  "0d51",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			payload, err := hex.DecodeString(tt.payload)
			if err != nil {
				t.Fatalf("Failed to decode hex: %v", err)
			}

			result := IsGQUICPacket(payload)
			if result != tt.expected {
				t.Errorf("IsGQUICPacket() = %v, want %v", result, tt.expected)
			}
		})
	}
}

// Test QUIC variable-length integer parsing
func TestParseQUICVarint(t *testing.T) {
	tests := []struct {
		name          string
		input         string // hex encoded
		expectedValue uint64
		expectedLen   int
	}{
		{
			name:          "1-byte (0)",
			input:         "00",
			expectedValue: 0,
			expectedLen:   1,
		},
		{
			name:          "1-byte (37)",
			input:         "25",
			expectedValue: 37,
			expectedLen:   1,
		},
		{
			name:          "1-byte (63)",
			input:         "3f",
			expectedValue: 63,
			expectedLen:   1,
		},
		{
			name:          "2-byte (494)",
			input:         "41ee",
			expectedValue: 494,
			expectedLen:   2,
		},
		{
			name:          "4-byte (large)",
			input:         "80000064",
			expectedValue: 100,
			expectedLen:   4,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			input, err := hex.DecodeString(tt.input)
			if err != nil {
				t.Fatalf("Failed to decode hex: %v", err)
			}

			value, length := parseQUICVarint(input)
			if value != tt.expectedValue {
				t.Errorf("value = %d, want %d", value, tt.expectedValue)
			}
			if length != tt.expectedLen {
				t.Errorf("length = %d, want %d", length, tt.expectedLen)
			}
		})
	}
}

// Test QUIC version string generation
func TestGetQUICVersionString(t *testing.T) {
	tests := []struct {
		version  uint32
		expected string
	}{
		{0x00000001, "IETF QUIC v1"},
		{0x6b3343cf, "IETF QUIC v2"},
		{0x00000000, "Version Negotiation"},
		{0xff000017, "IETF QUIC Draft"},
		{0x51303433, "gQUIC Q043"},
		{0xdeadbeef, "Unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			result := GetQUICVersionString(tt.version)
			if result != tt.expected {
				t.Errorf("GetQUICVersionString(0x%08x) = %s, want %s", tt.version, result, tt.expected)
			}
		})
	}
}

// Test JA4 fingerprint format for QUIC (should start with 'q')
func TestQUICJA4Format(t *testing.T) {
	// Verify that QUIC fingerprints start with 'q' instead of 't'
	// This is handled by the ja4 package when IsQUIC is true
	
	// Create a mock gQUIC fingerprint
	chlo := &GQUICClientHello{
		Version: "Q043",
		Tags:    []string{"PAD", "SNI", "VER", "AEAD", "KEXS"},
		TagValues: map[string]string{
			"AEAD": "AESG",
			"KEXS": "C255",
		},
	}

	fingerprint := computeGQUICFingerprint(chlo)
	
	// gQUIC fingerprint should start with "q_gquic_"
	if len(fingerprint) < 8 || fingerprint[:8] != "q_gquic_" {
		t.Errorf("gQUIC fingerprint should start with 'q_gquic_', got: %s", fingerprint)
	}
}

// Test CanDecodeQUIC function
func TestCanDecodeQUIC(t *testing.T) {
	tests := []struct {
		name     string
		payload  string
		expected bool
	}{
		{
			name:     "IETF QUIC Initial",
			payload:  "c000000001" + "0805" + "0102030405060708" + "00" + "4000",
			expected: true,
		},
		{
			name:     "gQUIC packet",
			payload:  "0d51303433" + "0000000000000000",
			expected: true,
		},
		{
			name:     "Not QUIC",
			payload:  "00112233445566778899",
			expected: false,
		},
		{
			name:     "Empty",
			payload:  "",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			payload, err := hex.DecodeString(tt.payload)
			if err != nil {
				t.Fatalf("Failed to decode hex: %v", err)
			}

			result := CanDecodeQUIC(payload)
			if result != tt.expected {
				t.Errorf("CanDecodeQUIC() = %v, want %v", result, tt.expected)
			}
		})
	}
}

// Test QUIC v2 header type parsing (RFC 9369)
// QUIC v2 swaps header type values: Retry=0, Initial=1, 0-RTT=2, Handshake=3
func TestParseIETFQUICInitialV2(t *testing.T) {
	// QUIC v2 Initial packet header with header type 1 (Initial for v2)
	// Build a QUIC v2 Initial packet with enough payload for parsing
	// Note: The payload includes some fake encrypted data since we can't 
	// decrypt without the proper keys. The parser should still extract header info.
	
	// Packet structure:
	// Byte 0: 0xd0 (Long header + Fixed bit + Type=01 for v2 Initial)
	// Bytes 1-4: Version (0x6b3343cf for v2)
	// Byte 5: DCID Length
	// Bytes 6-13: DCID
	// Byte 14: SCID Length
	// Byte 15: Token length (varint)
	// Bytes 16-17: Packet length (varint)
	// Bytes 18+: Encrypted payload (fake data)
	
	v2InitialPacket := []byte{
		0xd0,                   // Long header, fixed bit, type=1 (Initial for v2)
		0x6b, 0x33, 0x43, 0xcf, // QUIC v2 version
		0x08,                   // DCID length = 8
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, // DCID
		0x00,       // SCID length = 0
		0x00,       // Token length = 0 (varint)
		0x40, 0x14, // Packet length = 20 (varint: 0x4014 means 2-byte encoding with value 0x14=20)
	}
	// Add fake encrypted payload (20 bytes)
	fakePayload := make([]byte, 20)
	for i := range fakePayload {
		fakePayload[i] = byte(i)
	}
	v2InitialPacket = append(v2InitialPacket, fakePayload...)
	
	// This should be detected as IETF QUIC
	if !IsIETFQUICPacket(v2InitialPacket) {
		t.Error("QUIC v2 Initial packet should be detected as IETF QUIC")
	}
	
	// Parse the Initial packet - note: decryption will fail since we don't have real keys,
	// but we should still get header information
	result, err := ParseIETFQUICInitial(v2InitialPacket)
	if err != nil {
		t.Fatalf("Failed to parse QUIC v2 Initial: %v", err)
	}
	
	// Result should not be nil - even if decryption fails, we get header info
	if result == nil {
		t.Fatal("Expected non-nil result for QUIC v2 Initial (header info should be extracted)")
	}
	
	// Verify version
	if result.Version != 0x6b3343cf {
		t.Errorf("Expected version 0x6b3343cf, got 0x%08x", result.Version)
	}
	
	// Verify DCID
	expectedDCID := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
	if len(result.DCID) != len(expectedDCID) {
		t.Errorf("Expected DCID length %d, got %d", len(expectedDCID), len(result.DCID))
	}
	for i := range expectedDCID {
		if result.DCID[i] != expectedDCID[i] {
			t.Errorf("DCID mismatch at index %d: expected 0x%02x, got 0x%02x", i, expectedDCID[i], result.DCID[i])
		}
	}
}

// Test that QUIC v1 Retry packet is NOT mistakenly parsed as Initial
func TestParseIETFQUICRetryV1(t *testing.T) {
	// QUIC v1 Retry packet: header type = 3
	// First byte: 0xf0 = 1111 0000 (Form=1, Fixed=1, Type=11=Retry)
	v1RetryPacket := []byte{
		0xf0,                   // Long header, fixed bit, type=3 (Retry for v1)
		0x00, 0x00, 0x00, 0x01, // QUIC v1 version
		0x08,                   // DCID length = 8
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, // DCID
		0x00,       // SCID length = 0
	}
	
	// This should be detected as IETF QUIC
	if !IsIETFQUICPacket(v1RetryPacket) {
		t.Error("QUIC v1 Retry packet should be detected as IETF QUIC")
	}
	
	// But should NOT be parsed as Initial
	result, _ := ParseIETFQUICInitial(v1RetryPacket)
	if result != nil {
		t.Error("QUIC v1 Retry packet should not be parsed as Initial")
	}
}

// Benchmark QUIC detection
func BenchmarkIsIETFQUICPacket(b *testing.B) {
	// Typical IETF QUIC v1 Initial packet header
	payload, _ := hex.DecodeString("c000000001" + "08" + "0102030405060708" + "00" + "4100")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		IsIETFQUICPacket(payload)
	}
}

func BenchmarkIsGQUICPacket(b *testing.B) {
	// Typical gQUIC packet with Q043 version
	payload, _ := hex.DecodeString("0d51303433" + "0102030405060708")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		IsGQUICPacket(payload)
	}
}

