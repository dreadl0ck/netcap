/*
 * NETCAP - Traffic Analysis Framework
 * Copyright (c) Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
 * License: GNU General Public License v3.0
 */

package ja4

import (
	"strings"
	"testing"
)

func TestComputeJA4(t *testing.T) {
	tests := []struct {
		name     string
		data     *ClientHelloData
		wantA    string // JA4_a part
		validate bool   // Whether result should pass validation
	}{
		{
			name: "Chrome TLS 1.3",
			data: &ClientHelloData{
				Version: 0x0303, // TLS 1.2 in handshake
				CipherSuites: []uint16{
					0x1301, 0x1302, 0x1303, // TLS 1.3 ciphers
					0xc02b, 0xc02f, 0xc02c, 0xc030, // TLS 1.2 ciphers
					0xcca9, 0xcca8,
					0x0a0a, // GREASE - should be filtered
				},
				Extensions: []uint16{
					0x0000, // SNI - should be filtered from JA4_c
					0x0017, 0x0023, 0x000d, 0x0005, 0x0033, 0x002b,
					0x002d, 0x0010, // ALPN - should be filtered from JA4_c
					0x001b, 0x0029,
					0x1a1a, // GREASE - should be filtered
				},
				SNI:           "example.com",
				ALPNs:         []string{"h2", "http/1.1"},
				SupportedVers: 0x0304, // TLS 1.3
			},
			wantA:    "t13d",
			validate: true,
		},
		{
			name: "TLS 1.2 without SNI",
			data: &ClientHelloData{
				Version: 0x0303,
				CipherSuites: []uint16{
					0xc02b, 0xc02f, 0xc02c, 0xc030,
				},
				Extensions: []uint16{
					0x0017, 0x0023, 0x000d,
				},
				SNI:           "",
				ALPNs:         []string{},
				SupportedVers: 0,
			},
			wantA:    "t12i",
			validate: true,
		},
		{
			name: "IP address as SNI",
			data: &ClientHelloData{
				Version: 0x0303,
				CipherSuites: []uint16{
					0xc02b, 0xc02f,
				},
				Extensions: []uint16{
					0x0000, 0x0017,
				},
				SNI:           "192.168.1.1",
				ALPNs:         []string{"http/1.1"},
				SupportedVers: 0,
			},
			wantA:    "t12i",
			validate: true,
		},
		{
			name: "QUIC",
			data: &ClientHelloData{
				Version: 0x0303,
				CipherSuites: []uint16{
					0x1301, 0x1302, 0x1303,
				},
				Extensions: []uint16{
					0x0000, 0x002b, 0x0033,
				},
				SNI:           "quic.example.com",
				ALPNs:         []string{"h3"},
				SupportedVers: 0x0304,
				IsQUIC:        true,
			},
			wantA:    "q13d",
			validate: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ComputeJA4(tt.data)
			
			// Check JA4_a prefix
			if len(result) < 4 || result[:4] != tt.wantA {
				t.Errorf("ComputeJA4() JA4_a = %s, want prefix %s", result, tt.wantA)
			}
			
			// Check format validation
			if tt.validate && !ValidateJA4(result) {
				t.Errorf("ComputeJA4() result %s failed validation", result)
			}
			
			t.Logf("JA4 = %s", result)
		})
	}
}

func TestComputeJA4S(t *testing.T) {
	tests := []struct {
		name     string
		data     *ServerHelloData
		wantA    string // Full JA4S_a part (7 chars)
		validate bool
	}{
		{
			name: "TLS 1.3 server",
			data: &ServerHelloData{
				Version:       0x0303,
				CipherSuite:   0x1301,
				Extensions:    []uint16{0x002b, 0x0033},
				SupportedVers: 0x0304,
			},
			wantA:    "t130200", // protocol(t) + version(13) + ext_count(02) + alpn(00)
			validate: true,
		},
		{
			name: "TLS 1.2 server",
			data: &ServerHelloData{
				Version:     0x0303,
				CipherSuite: 0xc02f,
				Extensions:  []uint16{0x0000, 0xff01},
			},
			wantA:    "t120200", // protocol(t) + version(12) + ext_count(02) + alpn(00)
			validate: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ComputeJA4S(tt.data)
			parts := strings.Split(result, "_")
			
			// Check JA4S_a part
			if len(parts) < 1 || parts[0] != tt.wantA {
				t.Errorf("ComputeJA4S() JA4S_a = %s, want %s", parts[0], tt.wantA)
			}
			
			if tt.validate && !ValidateJA4S(result) {
				t.Errorf("ComputeJA4S() result %s failed validation", result)
			}
			
			t.Logf("JA4S = %s", result)
		})
	}
}

func TestIsGrease(t *testing.T) {
	greaseVals := []uint16{0x0a0a, 0x1a1a, 0x2a2a, 0xfafa}
	nonGreaseVals := []uint16{0x0000, 0x1301, 0xc02f, 0xffff}
	
	for _, v := range greaseVals {
		if !isGrease(v) {
			t.Errorf("isGrease(0x%04x) = false, want true", v)
		}
	}
	
	for _, v := range nonGreaseVals {
		if isGrease(v) {
			t.Errorf("isGrease(0x%04x) = true, want false", v)
		}
	}
}

func TestGetTLSVersionString(t *testing.T) {
	tests := []struct {
		version       uint16
		supportedVers uint16
		want          string
	}{
		{0x0304, 0, "13"},
		{0x0303, 0x0304, "13"}, // TLS 1.3 via supported_versions
		{0x0303, 0, "12"},
		{0x0302, 0, "11"},
		{0x0301, 0, "10"},
		{0x0300, 0, "s3"},
	}
	
	for _, tt := range tests {
		got := getTLSVersionString(tt.version, tt.supportedVers)
		if got != tt.want {
			t.Errorf("getTLSVersionString(0x%04x, 0x%04x) = %s, want %s",
				tt.version, tt.supportedVers, got, tt.want)
		}
	}
}

func TestTruncatedSHA256(t *testing.T) {
	// Empty string should return zeros
	result := truncatedSHA256("")
	if result != "000000000000" {
		t.Errorf("truncatedSHA256(\"\") = %s, want 000000000000", result)
	}
	
	// Non-empty should return 12 char hex
	result = truncatedSHA256("test")
	if len(result) != 12 {
		t.Errorf("truncatedSHA256(\"test\") length = %d, want 12", len(result))
	}
}

func TestIsIPAddress(t *testing.T) {
	tests := []struct {
		input string
		want  bool
	}{
		{"192.168.1.1", true},
		{"::1", true},
		{"2001:db8::1", true},
		{"example.com", false},
		{"www.example.com", false},
		{"", false},
	}
	
	for _, tt := range tests {
		got := isIPAddress(tt.input)
		if got != tt.want {
			t.Errorf("isIPAddress(%q) = %v, want %v", tt.input, got, tt.want)
		}
	}
}

func TestValidateJA4(t *testing.T) {
	tests := []struct {
		input string
		want  bool
	}{
		{"t13d1516h2_8daaf6152771_e5627efa2ab1", true},
		{"q13d0305h3_abcdef123456_fedcba654321", true},
		{"invalid", false},
		{"t13d1516h2_short_e5627efa2ab1", false},
		{"t13d1516h2_8daaf6152771", false}, // Missing part
	}
	
	for _, tt := range tests {
		got := ValidateJA4(tt.input)
		if got != tt.want {
			t.Errorf("ValidateJA4(%q) = %v, want %v", tt.input, got, tt.want)
		}
	}
}

func TestParseHelpers(t *testing.T) {
	ciphers := []int32{0x1301, 0x1302, 0xc02f}
	parsed := ParseCipherSuites(ciphers)
	
	if len(parsed) != 3 {
		t.Errorf("ParseCipherSuites length = %d, want 3", len(parsed))
	}
	if parsed[0] != 0x1301 {
		t.Errorf("ParseCipherSuites[0] = 0x%04x, want 0x1301", parsed[0])
	}
	
	exts := []int32{0x0000, 0x0017, 0x000d}
	parsedExts := ParseExtensions(exts)
	
	if len(parsedExts) != 3 {
		t.Errorf("ParseExtensions length = %d, want 3", len(parsedExts))
	}
}

