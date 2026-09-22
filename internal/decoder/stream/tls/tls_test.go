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
	"testing"
)

// TestTLSCanDecode tests the CanDecode function with sample TLS handshake data
func TestTLSCanDecode(t *testing.T) {
	tests := []struct {
		name     string
		client   []byte
		server   []byte
		expected bool
	}{
		{
			name: "Valid TLS 1.2 ClientHello",
			client: []byte{
				0x16,       // Content Type: Handshake
				0x03, 0x03, // TLS Version 1.2
				0x00, 0x05, // Length
				0x01,             // Handshake Type: ClientHello
				0x00, 0x00, 0x01, // Handshake Length
				0x00, // Handshake data placeholder
			},
			server:   []byte{},
			expected: true,
		},
		{
			name:   "Valid TLS 1.2 ServerHello",
			client: []byte{},
			server: []byte{
				0x16,       // Content Type: Handshake
				0x03, 0x03, // TLS Version 1.2
				0x00, 0x05, // Length
				0x02,             // Handshake Type: ServerHello
				0x00, 0x00, 0x01, // Handshake Length
				0x00, // Handshake data placeholder
			},
			expected: true,
		},
		{
			name: "Valid TLS 1.3 ClientHello",
			client: []byte{
				0x16,       // Content Type: Handshake
				0x03, 0x04, // TLS Version 1.3
				0x00, 0x05, // Length
				0x01,             // Handshake Type: ClientHello
				0x00, 0x00, 0x01, // Handshake Length
				0x00, // Handshake data placeholder
			},
			server:   []byte{},
			expected: true,
		},
		{
			name: "Valid TLS 1.0 ClientHello",
			client: []byte{
				0x16,       // Content Type: Handshake
				0x03, 0x01, // TLS Version 1.0
				0x00, 0x05, // Length
				0x01,             // Handshake Type: ClientHello
				0x00, 0x00, 0x01, // Handshake Length
				0x00, // Handshake data placeholder
			},
			server:   []byte{},
			expected: true,
		},
		{
			name: "Invalid - HTTP traffic",
			client: []byte(
				"GET / HTTP/1.1\r\n" +
					"Host: example.com\r\n" +
					"\r\n",
			),
			server:   []byte("HTTP/1.1 200 OK\r\n"),
			expected: false,
		},
		{
			name:     "Invalid - Empty buffers",
			client:   []byte{},
			server:   []byte{},
			expected: false,
		},
		{
			name: "Invalid - Too short",
			client: []byte{
				0x16,       // Content Type: Handshake
				0x03, 0x03, // TLS Version 1.2
			},
			server:   []byte{},
			expected: false,
		},
		{
			name: "Invalid - Wrong content type",
			client: []byte{
				0x17,       // Content Type: Application Data (not Handshake)
				0x03, 0x03, // TLS Version 1.2
				0x00, 0x05, // Length
				0x01,             // Would be handshake type
				0x00, 0x00, 0x01, // Would be length
				0x00,
			},
			server:   []byte{},
			expected: false,
		},
		{
			name: "Invalid - Wrong TLS version",
			client: []byte{
				0x16,       // Content Type: Handshake
				0x03, 0x05, // Invalid TLS Version (0x0305)
				0x00, 0x05, // Length
				0x01,             // Handshake Type: ClientHello
				0x00, 0x00, 0x01, // Handshake Length
				0x00,
			},
			server:   []byte{},
			expected: false,
		},
		{
			name: "Invalid - Wrong handshake type",
			client: []byte{
				0x16,       // Content Type: Handshake
				0x03, 0x03, // TLS Version 1.2
				0x00, 0x05, // Length
				0xFF,             // Invalid Handshake Type
				0x00, 0x00, 0x01, // Handshake Length
				0x00,
			},
			server:   []byte{},
			expected: false,
		},
		{
			name: "Valid - Both ClientHello and ServerHello",
			client: []byte{
				0x16,       // Content Type: Handshake
				0x03, 0x03, // TLS Version 1.2
				0x00, 0x05, // Length
				0x01,             // Handshake Type: ClientHello
				0x00, 0x00, 0x01, // Handshake Length
				0x00,
			},
			server: []byte{
				0x16,       // Content Type: Handshake
				0x03, 0x03, // TLS Version 1.2
				0x00, 0x05, // Length
				0x02,             // Handshake Type: ServerHello
				0x00, 0x00, 0x01, // Handshake Length
				0x00,
			},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := Decoder.CanDecodeStream(tt.client, tt.server)
			if result != tt.expected {
				t.Errorf("CanDecode() = %v, expected %v", result, tt.expected)
				t.Logf("Client data (hex): % X", tt.client)
				t.Logf("Server data (hex): % X", tt.server)
			}
		})
	}
}

// TestIsTLSHandshake tests the isTLSHandshake helper function
func TestIsTLSHandshake(t *testing.T) {
	tests := []struct {
		name     string
		data     []byte
		expected bool
	}{
		{
			name: "Valid TLS 1.2 handshake",
			data: []byte{
				0x16,       // Content Type: Handshake
				0x03, 0x03, // TLS Version 1.2
				0x00, 0x05, // Length
				0x01,             // Handshake Type
				0x00, 0x00, 0x01, // Handshake Length
			},
			expected: true,
		},
		{
			name: "Valid TLS 1.3 handshake",
			data: []byte{
				0x16,       // Content Type: Handshake
				0x03, 0x04, // TLS Version 1.3
				0x00, 0x05, // Length
				0x01, // Handshake Type
			},
			expected: true,
		},
		{
			name: "Valid TLS 1.0 handshake",
			data: []byte{
				0x16,       // Content Type: Handshake
				0x03, 0x00, // TLS Version 1.0
				0x00, 0x05, // Length
				0x01, // Handshake Type
			},
			expected: true,
		},
		{
			name:     "Too short",
			data:     []byte{0x16, 0x03, 0x03},
			expected: false,
		},
		{
			name:     "Empty",
			data:     []byte{},
			expected: false,
		},
		{
			name: "Wrong content type",
			data: []byte{
				0x17,       // Content Type: Application Data
				0x03, 0x03, // TLS Version 1.2
				0x00, 0x05, // Length
			},
			expected: false,
		},
		{
			name: "Invalid TLS version",
			data: []byte{
				0x16,       // Content Type: Handshake
				0x04, 0x03, // Invalid version
				0x00, 0x05, // Length
			},
			expected: false,
		},
		{
			name: "TLS version out of range",
			data: []byte{
				0x16,       // Content Type: Handshake
				0x03, 0x05, // TLS Version > 1.3
				0x00, 0x05, // Length
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isTLSHandshake(tt.data)
			if result != tt.expected {
				t.Errorf("isTLSHandshake() = %v, expected %v", result, tt.expected)
				t.Logf("Data (hex): % X", tt.data)
			}
		})
	}
}

// TestTLSConstants verifies the TLS constants are correct
func TestTLSConstants(t *testing.T) {
	if recordTypeHandshake != 0x16 {
		t.Errorf("recordTypeHandshake = 0x%02X, expected 0x16", recordTypeHandshake)
	}
	if handshakeTypeClientHello != 0x01 {
		t.Errorf("handshakeTypeClientHello = 0x%02X, expected 0x01", handshakeTypeClientHello)
	}
	if handshakeTypeServerHello != 0x02 {
		t.Errorf("handshakeTypeServerHello = 0x%02X, expected 0x02", handshakeTypeServerHello)
	}
	if handshakeTypeCertificate != 0x0b {
		t.Errorf("handshakeTypeCertificate = 0x%02X, expected 0x0b", handshakeTypeCertificate)
	}
}

// Note: Full PCAP file tests with certificate extraction are in tls_pcap_test.go
