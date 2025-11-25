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

package tls

import (
	"crypto/x509"
	"math/big"
	"testing"
	"time"

	"github.com/dreadl0ck/netcap/decoder/core"
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
				found := false
				for _, res := range result {
					if res == exp {
						found = true
						break
					}
				}
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

// TestParseTLSRecords tests TLS record parsing logic
func TestParseTLSRecords(t *testing.T) {
	tests := []struct {
		name        string
		data        []byte
		description string
	}{
		{
			name: "Empty data",
			data: []byte{},
			description: "Should handle empty input gracefully",
		},
		{
			name: "Single TLS record - ClientHello",
			data: []byte{
				0x16,       // Content Type: Handshake
				0x03, 0x03, // TLS Version 1.2
				0x00, 0x05, // Length: 5 bytes
				0x01,             // Handshake Type: ClientHello
				0x00, 0x00, 0x01, // Handshake Length: 1 byte
				0x00, // Handshake data
			},
			description: "Should parse a valid ClientHello record",
		},
		{
			name: "Multiple TLS records",
			data: []byte{
				// First record - ClientHello
				0x16,       // Content Type: Handshake
				0x03, 0x03, // TLS Version 1.2
				0x00, 0x05, // Length: 5 bytes
				0x01,             // Handshake Type: ClientHello
				0x00, 0x00, 0x01, // Handshake Length: 1 byte
				0x00, // Handshake data
				// Second record - ServerHello
				0x16,       // Content Type: Handshake
				0x03, 0x03, // TLS Version 1.2
				0x00, 0x05, // Length: 5 bytes
				0x02,             // Handshake Type: ServerHello
				0x00, 0x00, 0x01, // Handshake Length: 1 byte
				0x00, // Handshake data
			},
			description: "Should parse multiple TLS records",
		},
		{
			name: "Non-handshake record",
			data: []byte{
				0x17,       // Content Type: Application Data
				0x03, 0x03, // TLS Version 1.2
				0x00, 0x05, // Length: 5 bytes
				0x01, 0x02, 0x03, 0x04, 0x05, // Application data
			},
			description: "Should skip non-handshake records",
		},
		{
			name: "Truncated record",
			data: []byte{
				0x16,       // Content Type: Handshake
				0x03, 0x03, // TLS Version 1.2
				0x00, 0xFF, // Length: 255 bytes (but data is truncated)
				0x01, // Handshake Type
			},
			description: "Should handle truncated records gracefully",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a mock TLS reader
			reader := &tlsReader{
				conversation: &core.ConversationInfo{
					Ident:             "test-conv",
					ClientIP:          "192.168.1.1",
					ServerIP:          "192.168.1.2",
					ClientPort:        54321,
					ServerPort:        443,
					FirstClientPacket: time.Now(),
					Data:              core.DataFragments{},
				},
			}

			// This should not panic
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("parseTLSRecords panicked: %v", r)
				}
			}()

			reader.parseTLSRecords(tt.data)
			t.Logf("Test completed: %s", tt.description)
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

