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
	"math/big"
	"slices"
	"testing"

	"github.com/dreadl0ck/netcap/internal/decoder/core"
)

// TestExtractKeyUsage tests the extraction of key usage flags
func TestExtractKeyUsage(t *testing.T) {
	tests := []struct {
		name     string
		usage    x509.KeyUsage
		expected []string
	}{
		{
			name:     "No usage",
			usage:    0,
			expected: []string{},
		},
		{
			name:     "DigitalSignature only",
			usage:    x509.KeyUsageDigitalSignature,
			expected: []string{"DigitalSignature"},
		},
		{
			name:     "Multiple usages",
			usage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
			expected: []string{"DigitalSignature", "KeyEncipherment"},
		},
		{
			name:     "All standard usages",
			usage:    x509.KeyUsageDigitalSignature | x509.KeyUsageContentCommitment | x509.KeyUsageKeyEncipherment | x509.KeyUsageDataEncipherment | x509.KeyUsageKeyAgreement | x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
			expected: []string{"DigitalSignature", "ContentCommitment", "KeyEncipherment", "DataEncipherment", "KeyAgreement", "CertSign", "CRLSign"},
		},
		{
			name:     "CertSign and CRLSign (CA)",
			usage:    x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
			expected: []string{"CertSign", "CRLSign"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractKeyUsage(tt.usage)

			if len(result) != len(tt.expected) {
				t.Errorf("Expected %d usages, got %d", len(tt.expected), len(result))
				t.Logf("Expected: %v", tt.expected)
				t.Logf("Got: %v", result)
				return
			}

			// Check each expected usage is present
			for _, exp := range tt.expected {
				found := slices.Contains(result, exp)
				if !found {
					t.Errorf("Expected usage %q not found in result: %v", exp, result)
				}
			}
		})
	}
}

// TestExtractExtKeyUsage tests the extraction of extended key usage
func TestExtractExtKeyUsage(t *testing.T) {
	tests := []struct {
		name     string
		usages   []x509.ExtKeyUsage
		expected []string
	}{
		{
			name:     "No usage",
			usages:   []x509.ExtKeyUsage{},
			expected: []string{},
		},
		{
			name:     "ServerAuth only",
			usages:   []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			expected: []string{"ServerAuth"},
		},
		{
			name:     "ClientAuth only",
			usages:   []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
			expected: []string{"ClientAuth"},
		},
		{
			name:     "ServerAuth and ClientAuth",
			usages:   []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
			expected: []string{"ServerAuth", "ClientAuth"},
		},
		{
			name:     "Multiple usages",
			usages:   []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageCodeSigning, x509.ExtKeyUsageEmailProtection},
			expected: []string{"ServerAuth", "ClientAuth", "CodeSigning", "EmailProtection"},
		},
		{
			name:     "OCSP Signing",
			usages:   []x509.ExtKeyUsage{x509.ExtKeyUsageOCSPSigning},
			expected: []string{"OCSPSigning"},
		},
		{
			name:     "Time Stamping",
			usages:   []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping},
			expected: []string{"TimeStamping"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractExtKeyUsage(tt.usages)

			if len(result) != len(tt.expected) {
				t.Errorf("Expected %d ext usages, got %d", len(tt.expected), len(result))
				t.Logf("Expected: %v", tt.expected)
				t.Logf("Got: %v", result)
				return
			}

			// Check order is preserved
			for i, exp := range tt.expected {
				if result[i] != exp {
					t.Errorf("Expected usage[%d] = %q, got %q", i, exp, result[i])
				}
			}
		})
	}
}

// TestFormatSerialNumber tests serial number formatting
func TestFormatSerialNumber(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "Nil serial",
			input:    "",
			expected: "",
		},
		{
			name:     "Small serial",
			input:    "123",
			expected: "7B",
		},
		{
			name:     "Large serial",
			input:    "1234567890",
			expected: "499602D2",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.input == "" {
				result := formatSerialNumber(nil)
				if result != tt.expected {
					t.Errorf("Expected %q, got %q", tt.expected, result)
				}
				return
			}

			// Parse the input as a decimal number
			var serial big.Int
			serial.SetString(tt.input, 10)

			result := formatSerialNumber(&serial)
			if result != tt.expected {
				t.Errorf("Expected %q, got %q", tt.expected, result)
			}
		})
	}
}

// TestTLSReaderNew tests the New method of tlsReader
func TestTLSReaderNew(t *testing.T) {
	conv := &core.ConversationInfo{
		Ident:      "test-conv",
		ClientIP:   "192.168.1.1",
		ServerIP:   "192.168.1.2",
		ClientPort: 54321,
		ServerPort: 443,
	}

	reader := &tlsReader{}
	newReader := reader.New(conv)

	if newReader == nil {
		t.Fatal("New() returned nil")
	}

	tlsR, ok := newReader.(*tlsReader)
	if !ok {
		t.Fatal("New() did not return *tlsReader")
	}

	if tlsR.conversation != conv {
		t.Error("New() did not set conversation correctly")
	}
}
