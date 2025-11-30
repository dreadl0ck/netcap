/*
 * NETCAP - Traffic Analysis Framework
 * Copyright (c) Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
 * License: GNU General Public License v3.0
 */

package ja4

import (
	"testing"
)

func TestComputeJA4X(t *testing.T) {
	tests := []struct {
		name     string
		data     *CertificateFingerprintData
		validate bool
	}{
		{
			name: "Standard certificate",
			data: &CertificateFingerprintData{
				IssuerRDNs:    []string{"550406", "55040a", "550403"},
				SubjectRDNs:   []string{"550406", "55040a", "550403"},
				ExtensionOIDs: []string{"551d0f", "551d25", "551d11"},
			},
			validate: true,
		},
		{
			name: "Empty certificate",
			data: &CertificateFingerprintData{
				IssuerRDNs:    []string{},
				SubjectRDNs:   []string{},
				ExtensionOIDs: []string{},
			},
			validate: true, // All zeros hash
		},
		{
			name: "Self-signed pattern",
			data: &CertificateFingerprintData{
				IssuerRDNs:    []string{"550403"},
				SubjectRDNs:   []string{"550403"},
				ExtensionOIDs: []string{"551d0f"},
			},
			validate: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ComputeJA4X(tt.data)
			if result == "" {
				t.Error("ComputeJA4X returned empty string")
			}
			if tt.validate && !ValidateJA4X(result) {
				t.Errorf("ComputeJA4X result %q is not valid", result)
			}
		})
	}
}

func TestComputeJA4XRaw(t *testing.T) {
	data := &CertificateFingerprintData{
		IssuerRDNs:    []string{"550406", "55040a", "550403"},
		SubjectRDNs:   []string{"550406", "55040a", "550403"},
		ExtensionOIDs: []string{"551d0f", "551d25", "551d11"},
	}

	result := ComputeJA4XRaw(data)
	expected := "550406,55040a,550403_550406,55040a,550403_551d0f,551d25,551d11"

	if result != expected {
		t.Errorf("ComputeJA4XRaw() = %q, want %q", result, expected)
	}
}

func TestValidateJA4X(t *testing.T) {
	tests := []struct {
		fingerprint string
		valid       bool
	}{
		{"aae71e8db6d7_aae71e8db6d7_aae71e8db6d7", true},
		{"000000000000_000000000000_000000000000", true},
		{"2166164053c1_2166164053c1_30d204a01551", true},
		{"invalid", false},
		{"abc_def_ghi", false},          // Too short
		{"aae71e8db6d7_aae71e8db6d7", false}, // Missing part
		{"", false},
	}

	for _, tt := range tests {
		t.Run(tt.fingerprint, func(t *testing.T) {
			result := ValidateJA4X(tt.fingerprint)
			if result != tt.valid {
				t.Errorf("ValidateJA4X(%q) = %v, want %v", tt.fingerprint, result, tt.valid)
			}
		})
	}
}

func TestIsSelfSignedByJA4X(t *testing.T) {
	tests := []struct {
		fingerprint string
		selfSigned  bool
	}{
		{"aae71e8db6d7_aae71e8db6d7_aae71e8db6d7", true},   // Issuer == Subject
		{"000000000000_000000000000_000000000000", true},   // Empty (technically self-signed)
		{"2166164053c1_2166164053c1_30d204a01551", true},   // Known self-signed pattern
		{"aae71e8db6d7_bbb71e8db6d7_aae71e8db6d7", false},  // Different issuer/subject
		{"invalid", false},
	}

	for _, tt := range tests {
		t.Run(tt.fingerprint, func(t *testing.T) {
			result := IsSelfSignedByJA4X(tt.fingerprint)
			if result != tt.selfSigned {
				t.Errorf("IsSelfSignedByJA4X(%q) = %v, want %v", tt.fingerprint, result, tt.selfSigned)
			}
		})
	}
}

func TestTruncatedSHA256ForJA4X(t *testing.T) {
	// Test that the hash of known extension OIDs matches expected
	extensionOIDs := "551d0f,551d25,551d11"
	result := truncatedSHA256(extensionOIDs)

	// Should be 12 hex characters
	if len(result) != 12 {
		t.Errorf("truncatedSHA256 length = %d, want 12", len(result))
	}

	// Known hash value
	expected := "aae71e8db6d7"
	if result != expected {
		t.Errorf("truncatedSHA256(%q) = %q, want %q", extensionOIDs, result, expected)
	}
}

