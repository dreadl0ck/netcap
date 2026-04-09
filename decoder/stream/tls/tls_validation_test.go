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

package tls

import (
	"crypto/x509"
	"testing"
)

// TestIsWeakSignatureAlgorithm tests detection of weak signature algorithms
func TestIsWeakSignatureAlgorithm(t *testing.T) {
	tests := []struct {
		name      string
		algorithm x509.SignatureAlgorithm
		expected  bool
	}{
		{
			name:      "MD2WithRSA (weak)",
			algorithm: x509.MD2WithRSA,
			expected:  true,
		},
		{
			name:      "MD5WithRSA (weak)",
			algorithm: x509.MD5WithRSA,
			expected:  true,
		},
		{
			name:      "SHA1WithRSA (weak)",
			algorithm: x509.SHA1WithRSA,
			expected:  true,
		},
		{
			name:      "DSAWithSHA1 (weak)",
			algorithm: x509.DSAWithSHA1,
			expected:  true,
		},
		{
			name:      "ECDSAWithSHA1 (weak)",
			algorithm: x509.ECDSAWithSHA1,
			expected:  true,
		},
		{
			name:      "SHA256WithRSA (strong)",
			algorithm: x509.SHA256WithRSA,
			expected:  false,
		},
		{
			name:      "SHA384WithRSA (strong)",
			algorithm: x509.SHA384WithRSA,
			expected:  false,
		},
		{
			name:      "SHA512WithRSA (strong)",
			algorithm: x509.SHA512WithRSA,
			expected:  false,
		},
		{
			name:      "ECDSAWithSHA256 (strong)",
			algorithm: x509.ECDSAWithSHA256,
			expected:  false,
		},
		{
			name:      "ECDSAWithSHA384 (strong)",
			algorithm: x509.ECDSAWithSHA384,
			expected:  false,
		},
		{
			name:      "ECDSAWithSHA512 (strong)",
			algorithm: x509.ECDSAWithSHA512,
			expected:  false,
		},
		{
			name:      "DSAWithSHA256 (strong)",
			algorithm: x509.DSAWithSHA256,
			expected:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isWeakSignatureAlgorithm(tt.algorithm)
			if result != tt.expected {
				t.Errorf("isWeakSignatureAlgorithm(%v) = %v, expected %v",
					tt.algorithm, result, tt.expected)
			}
		})
	}
}

// TestIsShortKeySize tests detection of short/weak key sizes
func TestIsShortKeySize(t *testing.T) {
	tests := []struct {
		name      string
		algorithm x509.PublicKeyAlgorithm
		keySize   int32
		expected  bool
	}{
		// RSA tests (minimum: 2048 bits)
		{
			name:      "RSA 512 bits (weak)",
			algorithm: x509.RSA,
			keySize:   512,
			expected:  true,
		},
		{
			name:      "RSA 1024 bits (weak)",
			algorithm: x509.RSA,
			keySize:   1024,
			expected:  true,
		},
		{
			name:      "RSA 2048 bits (acceptable)",
			algorithm: x509.RSA,
			keySize:   2048,
			expected:  false,
		},
		{
			name:      "RSA 3072 bits (strong)",
			algorithm: x509.RSA,
			keySize:   3072,
			expected:  false,
		},
		{
			name:      "RSA 4096 bits (strong)",
			algorithm: x509.RSA,
			keySize:   4096,
			expected:  false,
		},
		// DSA tests (minimum: 2048 bits)
		{
			name:      "DSA 1024 bits (weak)",
			algorithm: x509.DSA,
			keySize:   1024,
			expected:  true,
		},
		{
			name:      "DSA 2048 bits (acceptable)",
			algorithm: x509.DSA,
			keySize:   2048,
			expected:  false,
		},
		{
			name:      "DSA 3072 bits (strong)",
			algorithm: x509.DSA,
			keySize:   3072,
			expected:  false,
		},
		// ECDSA tests (minimum: 224 bits)
		{
			name:      "ECDSA 192 bits (weak)",
			algorithm: x509.ECDSA,
			keySize:   192,
			expected:  true,
		},
		{
			name:      "ECDSA 224 bits (acceptable)",
			algorithm: x509.ECDSA,
			keySize:   224,
			expected:  false,
		},
		{
			name:      "ECDSA 256 bits (strong)",
			algorithm: x509.ECDSA,
			keySize:   256,
			expected:  false,
		},
		{
			name:      "ECDSA 384 bits (strong)",
			algorithm: x509.ECDSA,
			keySize:   384,
			expected:  false,
		},
		{
			name:      "ECDSA 521 bits (strong)",
			algorithm: x509.ECDSA,
			keySize:   521,
			expected:  false,
		},
		// Unknown algorithm (should return false)
		{
			name:      "Unknown algorithm",
			algorithm: x509.PublicKeyAlgorithm(999),
			keySize:   1024,
			expected:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isShortKeySize(tt.algorithm, tt.keySize)
			if result != tt.expected {
				t.Errorf("isShortKeySize(%v, %d) = %v, expected %v",
					tt.algorithm, tt.keySize, result, tt.expected)
			}
		})
	}
}

// TestCertificateValidationScenarios tests various real-world certificate validation scenarios
func TestCertificateValidationScenarios(t *testing.T) {
	scenarios := []struct {
		name           string
		sigAlg         x509.SignatureAlgorithm
		pubKeyAlg      x509.PublicKeyAlgorithm
		keySize        int32
		expectWeak     bool
		expectShortKey bool
		description    string
	}{
		{
			name:           "Modern secure certificate",
			sigAlg:         x509.SHA256WithRSA,
			pubKeyAlg:      x509.RSA,
			keySize:        2048,
			expectWeak:     false,
			expectShortKey: false,
			description:    "RSA-2048 with SHA256 (common, secure)",
		},
		{
			name:           "Legacy weak certificate",
			sigAlg:         x509.SHA1WithRSA,
			pubKeyAlg:      x509.RSA,
			keySize:        1024,
			expectWeak:     true,
			expectShortKey: true,
			description:    "RSA-1024 with SHA1 (old, insecure)",
		},
		{
			name:           "High security certificate",
			sigAlg:         x509.SHA512WithRSA,
			pubKeyAlg:      x509.RSA,
			keySize:        4096,
			expectWeak:     false,
			expectShortKey: false,
			description:    "RSA-4096 with SHA512 (very secure)",
		},
		{
			name:           "ECC certificate",
			sigAlg:         x509.ECDSAWithSHA256,
			pubKeyAlg:      x509.ECDSA,
			keySize:        256,
			expectWeak:     false,
			expectShortKey: false,
			description:    "ECDSA-256 with SHA256 (modern, efficient)",
		},
		{
			name:           "Weak ECC certificate",
			sigAlg:         x509.ECDSAWithSHA1,
			pubKeyAlg:      x509.ECDSA,
			keySize:        192,
			expectWeak:     true,
			expectShortKey: true,
			description:    "ECDSA-192 with SHA1 (weak)",
		},
		{
			name:           "Good key with weak signature",
			sigAlg:         x509.MD5WithRSA,
			pubKeyAlg:      x509.RSA,
			keySize:        2048,
			expectWeak:     true,
			expectShortKey: false,
			description:    "RSA-2048 with MD5 (weak hash)",
		},
		{
			name:           "Strong signature with weak key",
			sigAlg:         x509.SHA384WithRSA,
			pubKeyAlg:      x509.RSA,
			keySize:        1024,
			expectWeak:     false,
			expectShortKey: true,
			description:    "RSA-1024 with SHA384 (weak key)",
		},
	}

	for _, scenario := range scenarios {
		t.Run(scenario.name, func(t *testing.T) {
			t.Logf("Testing: %s", scenario.description)

			hasWeak := isWeakSignatureAlgorithm(scenario.sigAlg)
			if hasWeak != scenario.expectWeak {
				t.Errorf("Weak signature check failed: got %v, expected %v",
					hasWeak, scenario.expectWeak)
			}

			hasShort := isShortKeySize(scenario.pubKeyAlg, scenario.keySize)
			if hasShort != scenario.expectShortKey {
				t.Errorf("Short key check failed: got %v, expected %v",
					hasShort, scenario.expectShortKey)
			}
		})
	}
}
