/*
 * NETCAP - Traffic Analysis Framework
 * Copyright (c) Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
 * License: GNU General Public License v3.0
 */

package ja4

import (
	"testing"
)

func TestComputeJA4T(t *testing.T) {
	tests := []struct {
		name     string
		data     *TCPFingerprintData
		expected string
	}{
		{
			name: "Windows 11 SYN",
			data: &TCPFingerprintData{
				WindowSize:  64240,
				Options:     []uint8{2, 1, 3, 1, 1, 4},
				MSS:         1460,
				WindowScale: 8,
				IsSYN:       true,
				IsSYNACK:    false,
			},
			expected: "64240_2-1-3-1-1-4_1460_8",
		},
		{
			name: "Unix with tunnel",
			data: &TCPFingerprintData{
				WindowSize:  29200,
				Options:     []uint8{2, 4, 8, 1, 3},
				MSS:         1424,
				WindowScale: 7,
				IsSYN:       true,
				IsSYNACK:    false,
			},
			expected: "29200_2-4-8-1-3_1424_7",
		},
		{
			name: "macOS",
			data: &TCPFingerprintData{
				WindowSize:  65535,
				Options:     []uint8{2, 4, 8, 1, 3},
				MSS:         1460,
				WindowScale: 6,
				IsSYN:       true,
				IsSYNACK:    false,
			},
			expected: "65535_2-4-8-1-3_1460_6",
		},
		{
			name: "iOS (ends with EOL)",
			data: &TCPFingerprintData{
				WindowSize:  65535,
				Options:     []uint8{2, 4, 8, 1, 3, 0},
				MSS:         1460,
				WindowScale: 6,
				IsSYN:       true,
				IsSYNACK:    false,
			},
			expected: "65535_2-4-8-1-3-0_1460_6",
		},
		{
			name: "SYN-ACK should return empty for JA4T",
			data: &TCPFingerprintData{
				WindowSize:  64240,
				Options:     []uint8{2, 1, 3, 1, 1, 4},
				MSS:         1460,
				WindowScale: 8,
				IsSYN:       true,
				IsSYNACK:    true,
			},
			expected: "",
		},
		{
			name: "No options",
			data: &TCPFingerprintData{
				WindowSize:  32768,
				Options:     []uint8{},
				MSS:         0,
				WindowScale: 0,
				IsSYN:       true,
				IsSYNACK:    false,
			},
			expected: "32768_0_0_0",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ComputeJA4T(tt.data)
			if result != tt.expected {
				t.Errorf("ComputeJA4T() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestComputeJA4TS(t *testing.T) {
	tests := []struct {
		name     string
		data     *TCPFingerprintData
		expected string
	}{
		{
			name: "Server SYN-ACK response",
			data: &TCPFingerprintData{
				WindowSize:  65535,
				Options:     []uint8{2, 4, 8, 1, 3},
				MSS:         1460,
				WindowScale: 8,
				IsSYN:       false,
				IsSYNACK:    true,
			},
			expected: "65535_2-4-8-1-3_1460_8",
		},
		{
			name: "SYN only should return empty for JA4TS",
			data: &TCPFingerprintData{
				WindowSize:  64240,
				Options:     []uint8{2, 1, 3, 1, 1, 4},
				MSS:         1460,
				WindowScale: 8,
				IsSYN:       true,
				IsSYNACK:    false,
			},
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ComputeJA4TS(tt.data)
			if result != tt.expected {
				t.Errorf("ComputeJA4TS() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestValidateJA4T(t *testing.T) {
	tests := []struct {
		fingerprint string
		valid       bool
	}{
		{"64240_2-1-3-1-1-4_1460_8", true},
		{"29200_2-4-8-1-3_1424_7", true},
		{"65535_2-4-8-1-3-0_1460_6", true},
		{"32768_0_0_0", true},
		{"invalid", false},
		{"64240_2-1-3-1-1-4_1460", false}, // Missing part
		{"", false},
	}

	for _, tt := range tests {
		t.Run(tt.fingerprint, func(t *testing.T) {
			result := ValidateJA4T(tt.fingerprint)
			if result != tt.valid {
				t.Errorf("ValidateJA4T(%q) = %v, want %v", tt.fingerprint, result, tt.valid)
			}
		})
	}
}

func TestParseJA4T(t *testing.T) {
	windowSize, mss, windowScale, options, ok := ParseJA4T("64240_2-1-3-1-1-4_1460_8")
	if !ok {
		t.Fatal("ParseJA4T failed")
	}
	if windowSize != 64240 {
		t.Errorf("windowSize = %d, want 64240", windowSize)
	}
	if mss != 1460 {
		t.Errorf("mss = %d, want 1460", mss)
	}
	if windowScale != 8 {
		t.Errorf("windowScale = %d, want 8", windowScale)
	}
	expectedOpts := []int{2, 1, 3, 1, 1, 4}
	if len(options) != len(expectedOpts) {
		t.Errorf("options length = %d, want %d", len(options), len(expectedOpts))
	}
	for i, opt := range options {
		if opt != expectedOpts[i] {
			t.Errorf("options[%d] = %d, want %d", i, opt, expectedOpts[i])
		}
	}
}

func TestGetOSHint(t *testing.T) {
	tests := []struct {
		name     string
		data     *TCPFingerprintData
		contains string
	}{
		{
			name: "Windows (no timestamp)",
			data: &TCPFingerprintData{
				Options: []uint8{2, 1, 3, 1, 1, 4},
			},
			contains: "Windows",
		},
		{
			name: "Unix with timestamp",
			data: &TCPFingerprintData{
				Options:    []uint8{2, 4, 8, 1, 3},
				WindowSize: 29200,
			},
			contains: "Unix",
		},
		{
			name: "iOS with EOL",
			data: &TCPFingerprintData{
				Options:    []uint8{2, 4, 8, 1, 3, 0},
				WindowSize: 65535,
			},
			contains: "iOS",
		},
		{
			name: "macOS/BSD",
			data: &TCPFingerprintData{
				Options:    []uint8{2, 4, 8, 1, 3},
				WindowSize: 65535,
			},
			contains: "macOS",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := GetOSHint(tt.data)
			if result == "" {
				t.Error("GetOSHint returned empty string")
			}
		})
	}
}

func TestExtractTCPOptionsFromPacket(t *testing.T) {
	// Test with MSS, NOP, Window Scale, NOP, NOP, SACK Permitted
	// Option 2 (MSS): kind=2, len=4, data=0x05b4 (1460)
	// Option 1 (NOP): kind=1
	// Option 3 (WS): kind=3, len=3, data=0x08
	// Option 1 (NOP): kind=1
	// Option 1 (NOP): kind=1
	// Option 4 (SACK): kind=4, len=2
	optionData := []byte{
		2, 4, 0x05, 0xb4, // MSS = 1460
		1,          // NOP
		3, 3, 0x08, // Window Scale = 8
		1,    // NOP
		1,    // NOP
		4, 2, // SACK Permitted
	}

	options := ExtractTCPOptionsFromPacket(optionData)
	expected := []uint8{2, 1, 3, 1, 1, 4}

	if len(options) != len(expected) {
		t.Errorf("options length = %d, want %d", len(options), len(expected))
	}
	for i, opt := range options {
		if opt != expected[i] {
			t.Errorf("options[%d] = %d, want %d", i, opt, expected[i])
		}
	}
}
