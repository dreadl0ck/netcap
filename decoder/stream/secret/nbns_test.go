/*
 * NETCAP - Traffic Analysis Framework
 * Copyright (c) Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
 * License: GNU General Public License v3.0
 */

package secret

import "testing"

// TestIsValidNBNSName tests the name validation function
func TestIsValidNBNSName(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected bool
	}{
		// Valid NetBIOS names
		{"Valid hostname", "WORKSTATION1", true},
		{"Valid with hyphen", "PC-01", true},
		{"Valid with underscore", "PC_01", true},
		{"Valid domain", "MYDOMAIN", true},
		{"Valid short name", "PC", true},
		{"Valid mixed case", "MyServer", true},

		// Invalid names - too short/long
		{"Too short", "A", false},
		{"Empty", "", false},
		{"Too long", "VERYLONGHOSTNAME1", false},

		// Invalid names - bad characters
		{"Quote character", `Sent" 20 list`, false},
		{"Pipe character", "TEST|NAME", false},
		{"Bracket character", "TEST[1]", false},
		{"Slash character", "TEST/NAME", false},
		{"Colon character", "TEST:NAME", false},

		// Invalid names - garbage detection
		{"Garbage with digits", "030sM4003004004", false},
		{"Mostly digits", "123456789012345", false},
		{"Long consecutive digits", "AB12345678901", false},

		// Edge cases
		{"Starts with digit", "1SERVER", true},
		{"All uppercase", "MYSERVER", true},
		{"Numbers at end", "SERVER01", true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := isValidNBNSName(tc.input)
			if result != tc.expected {
				t.Errorf("isValidNBNSName(%q) = %v, expected %v", tc.input, result, tc.expected)
			}
		})
	}
}

// TestLooksLikeGarbage tests the garbage detection function
func TestLooksLikeGarbage(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected bool // true = is garbage
	}{
		// Not garbage - valid names
		{"Valid hostname", "WORKSTATION1", false},
		{"Valid domain", "MYDOMAIN", false},
		{"Valid with numbers", "SERVER01", false},
		{"Valid hyphenated", "PC-01", false},

		// Garbage - excessive digits
		{"Excessive digits", "030sM4003004004", true},
		{"Long digit sequence", "AB0001234567", true},
		{"Mostly numbers", "12345678901234", true},

		// Garbage - case transitions
		{"Random case mix", "aBcDeFgHiJ", true},
		{"Alternating case", "AbCdEfGhIj", true},

		// Garbage - repeating characters
		{"Repeating U", "UUUUUUUUUUUUUUU", true},
		{"Repeating A", "AAAAAAA", true},

		// Garbage - hex-like strings
		{"Hex string", "E04784589605A88", true},
		{"Hex mixed", "7450b10d1897", true},

		// Garbage - random lowercase with digits
		{"Random lowercase", "zcxczc1c1c2ewc3", true},

		// Not garbage - normal patterns
		{"CamelCase", "MyServer", false},
		{"All caps", "MYSERVER", false},
		{"All lower", "myserver", false},
		{"Empty string", "", true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := looksLikeGarbage(tc.input)
			if result != tc.expected {
				t.Errorf("looksLikeGarbage(%q) = %v, expected %v", tc.input, result, tc.expected)
			}
		})
	}
}

// TestIsValidEncodedNBNSData tests the encoded data validation
func TestIsValidEncodedNBNSData(t *testing.T) {
	tests := []struct {
		name     string
		data     []byte
		offset   int
		length   int
		expected bool
	}{
		{
			"Valid encoded data",
			[]byte("ABCDEFGHIJKLMNOP"),
			0, 16, true,
		},
		{
			"Valid full name",
			[]byte("EOGFGJFCCACACACACACACACACACACACA"),
			0, 32, true,
		},
		{
			"Invalid - lowercase",
			[]byte("abcdefghijklmnop"),
			0, 16, false,
		},
		{
			"Invalid - outside range",
			[]byte("QRSTUVWXYZABCDEF"),
			0, 16, false,
		},
		{
			"Invalid - too short",
			[]byte("ABCD"),
			0, 16, false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := isValidEncodedNBNSData(tc.data, tc.offset, tc.length)
			if result != tc.expected {
				t.Errorf("isValidEncodedNBNSData() = %v, expected %v", result, tc.expected)
			}
		})
	}
}

// TestFalsePositiveCases specifically tests the false positives from the screenshots
func TestFalsePositiveCases(t *testing.T) {
	falsePositives := []string{
		// Original false positives
		`030sM4003004004`, // Garbage with digit sequences
		`Sent" 20 list`,   // Contains invalid quote character

		// New false positives from screenshot
		`UUUUUUUUUUUUUUU`,   // Repeating characters
		`E04784589605A88`,   // Hex-like string
		`zcxczc1c1c2ewc3`,   // Random lowercase with digits
		`7450b10d1897`,      // Hex-like with lowercase
		"nobody\x00invalid", // Contains null character (non-printable)
	}

	for _, fp := range falsePositives {
		t.Run(fp, func(t *testing.T) {
			if isValidNBNSName(fp) {
				t.Errorf("Expected %q to be rejected as invalid NBNS name", fp)
			}
		})
	}
}

// Note: Port filtering is now handled centrally by the harvester engine (HarvesterPortFilter setting)
// See harvester_test.go for port filtering tests

