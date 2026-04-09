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

// Package ja4 implements the JA4+ fingerprinting suite.
//
// JA4+ is the successor to JA3, developed by FoxIO-LLC:
//   - JA4: TLS Client Fingerprinting (BSD 3-Clause License)
//   - JA4S: TLS Server Fingerprinting (FoxIO License 1.1)
//   - JA4H: HTTP Client Fingerprinting (FoxIO License 1.1)
//   - JA4X: X.509 Certificate Fingerprinting (FoxIO License 1.1)
//   - JA4T: TCP Client Fingerprinting (FoxIO License 1.1)
//   - JA4SSH: SSH Session Fingerprinting (FoxIO License 1.1)
//
// JA4 addresses JA3's weakness to TLS extension randomization and adds QUIC support.
//
// Reference: https://github.com/FoxIO-LLC/ja4
// License: See LICENSE-JA4 file in this directory.
package ja4

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"slices"
	"strings"
)

// GREASE (Generate Random Extensions And Sustain Extensibility) values
// These are intentionally invalid values used by browsers to test server tolerance
// Reference: RFC 8701
var greaseValues = map[uint16]bool{
	0x0a0a: true, 0x1a1a: true, 0x2a2a: true, 0x3a3a: true,
	0x4a4a: true, 0x5a5a: true, 0x6a6a: true, 0x7a7a: true,
	0x8a8a: true, 0x9a9a: true, 0xaaaa: true, 0xbaba: true,
	0xcaca: true, 0xdada: true, 0xeaea: true, 0xfafa: true,
}

// TLS Extension types to exclude from JA4_c
const (
	ExtensionSNI  uint16 = 0  // Server Name Indication
	ExtensionALPN uint16 = 16 // Application-Layer Protocol Negotiation
)

// isGrease checks if a value is a GREASE value
func isGrease(v uint16) bool {
	return greaseValues[v]
}

// ClientHelloData contains the data needed to compute a JA4 fingerprint
type ClientHelloData struct {
	Version             uint16   // TLS version from handshake
	CipherSuites        []uint16 // Cipher suites offered
	Extensions          []uint16 // Extensions present
	SNI                 string   // Server Name Indication
	ALPNs               []string // Application-Layer Protocol Negotiation values
	SupportedVers       uint16   // Supported versions extension value (for TLS 1.3)
	IsQUIC              bool     // Whether this is QUIC (not TCP/TLS)
	SignatureAlgorithms []uint16 // Signature algorithms from extension 13 (signature_algorithms)
}

// ServerHelloData contains the data needed to compute a JA4S fingerprint
type ServerHelloData struct {
	Version       uint16   // TLS version
	CipherSuite   uint16   // Selected cipher suite
	Extensions    []uint16 // Extensions present
	SupportedVers uint16   // Supported versions extension value (for TLS 1.3)
	IsQUIC        bool     // Whether this is QUIC
	ALPN          string   // Selected ALPN protocol
}

// ComputeJA4 computes the JA4 fingerprint for a TLS ClientHello
// Format: {ja4_a}_{ja4_b}_{ja4_c}
// Example: t13d1516h2_8daaf6152771_e5627efa2ab1
func ComputeJA4(data *ClientHelloData) string {
	ja4a := computeJA4a(data)
	ja4b := computeJA4b(data.CipherSuites)
	ja4c := computeJA4c(data.Extensions, data.SignatureAlgorithms)

	return fmt.Sprintf("%s_%s_%s", ja4a, ja4b, ja4c)
}

// ComputeJA4S computes the JA4S fingerprint for a TLS ServerHello
// Format: {ja4s_a}_{ja4s_b}_{ja4s_c}
// Where ja4s_a = protocol+version+extcount+alpn, ja4s_b = cipher hex, ja4s_c = hash of extensions
func ComputeJA4S(data *ServerHelloData) string {
	ja4sa := computeJA4Sa(data)
	ja4sb := fmt.Sprintf("%04x", data.CipherSuite) // Cipher in hex
	ja4sc := computeJA4Sc(data.Extensions)

	return fmt.Sprintf("%s_%s_%s", ja4sa, ja4sb, ja4sc)
}

// computeJA4a computes the first part of JA4 (10 characters)
// Format: {protocol}{version}{sni}{cipher_count:2d}{ext_count:2d}{alpn_first}
func computeJA4a(data *ClientHelloData) string {
	// Protocol: t for TCP/TLS, q for QUIC
	protocol := "t"
	if data.IsQUIC {
		protocol = "q"
	}

	// TLS Version
	version := getTLSVersionString(data.Version, data.SupportedVers)

	// SNI: d for domain, i for IP or missing
	sni := "i"
	if data.SNI != "" && !isIPAddress(data.SNI) {
		sni = "d"
	}

	// Cipher count (without GREASE), capped at 99
	cipherCount := min(countNonGrease(data.CipherSuites), 99)

	// Extension count (without GREASE), capped at 99
	extCount := min(countNonGreaseExtensions(data.Extensions), 99)

	// ALPN first value's first character, or "00" if none
	alpn := "00"
	if len(data.ALPNs) > 0 && len(data.ALPNs[0]) > 0 {
		// Take first two characters of first ALPN
		firstALPN := data.ALPNs[0]
		if len(firstALPN) >= 2 {
			alpn = firstALPN[:2]
		} else {
			alpn = firstALPN + "0"
		}
	}

	return fmt.Sprintf("%s%s%s%02d%02d%s", protocol, version, sni, cipherCount, extCount, alpn)
}

// computeJA4b computes the second part of JA4 (12 character truncated SHA256)
// Hash of sorted cipher suites (GREASE filtered, comma-separated hex)
func computeJA4b(cipherSuites []uint16) string {
	// Filter out GREASE values
	var filtered []uint16
	for _, cs := range cipherSuites {
		if !isGrease(cs) {
			filtered = append(filtered, cs)
		}
	}

	// Sort numerically
	slices.Sort(filtered)

	// Convert to hex strings and join
	var hexStrs []string
	for _, cs := range filtered {
		hexStrs = append(hexStrs, fmt.Sprintf("%04x", cs))
	}

	// Hash and truncate
	return truncatedSHA256(strings.Join(hexStrs, ","))
}

// computeJA4c computes the third part of JA4 (12 character truncated SHA256)
// Hash of sorted extensions (GREASE, SNI, ALPN filtered, comma-separated hex)
// followed by underscore and signature algorithms (if present)
func computeJA4c(extensions []uint16, signatureAlgorithms []uint16) string {
	// Filter out GREASE, SNI, and ALPN
	var filtered []uint16
	for _, ext := range extensions {
		if !isGrease(ext) && ext != ExtensionSNI && ext != ExtensionALPN {
			filtered = append(filtered, ext)
		}
	}

	// Sort numerically
	slices.Sort(filtered)

	// Convert to hex strings and join
	var hexStrs []string
	for _, ext := range filtered {
		hexStrs = append(hexStrs, fmt.Sprintf("%04x", ext))
	}

	extStr := strings.Join(hexStrs, ",")

	// Add signature algorithms if present (after underscore)
	if len(signatureAlgorithms) > 0 {
		var sigStrs []string
		for _, sig := range signatureAlgorithms {
			sigStrs = append(sigStrs, fmt.Sprintf("%04x", sig))
		}
		extStr += "_" + strings.Join(sigStrs, ",")
	}

	// Hash and truncate
	return truncatedSHA256(extStr)
}

// computeJA4Sa computes the first part of JA4S
// Format: {protocol}{version}{ext_count:2d}{alpn_first}{alpn_last}
func computeJA4Sa(data *ServerHelloData) string {
	// Protocol: t for TCP/TLS, q for QUIC
	protocol := "t"
	if data.IsQUIC {
		protocol = "q"
	}

	// TLS Version
	version := getTLSVersionString(data.Version, data.SupportedVers)

	// Extension count (without GREASE), capped at 99
	extCount := min(countNonGreaseExtensions(data.Extensions), 99)

	// ALPN first and last characters, or "00" if none/non-alphanumeric
	alpnFirst := "0"
	alpnLast := "0"
	if data.ALPN != "" {
		// Check if first character is alphanumeric
		first := data.ALPN[0]
		if (first >= 'a' && first <= 'z') || (first >= 'A' && first <= 'Z') || (first >= '0' && first <= '9') {
			alpnFirst = string(first)
			last := data.ALPN[len(data.ALPN)-1]
			alpnLast = string(last)
		} else {
			alpnFirst = "9"
			alpnLast = "9"
		}
	}

	return fmt.Sprintf("%s%s%02d%s%s", protocol, version, extCount, alpnFirst, alpnLast)
}

// computeJA4Sc computes the third part of JA4S
// Truncated SHA256 hash of extensions (SNI and ALPN filtered, NOT sorted per spec)
func computeJA4Sc(extensions []uint16) string {
	// Filter SNI (0x0000) and ALPN (0x0010) - but NOT GREASE per go-ja4 implementation
	var filtered []uint16
	for _, ext := range extensions {
		if ext != ExtensionSNI && ext != ExtensionALPN {
			filtered = append(filtered, ext)
		}
	}

	// Convert to hex strings (NOT sorted for JA4S)
	var hexStrs []string
	for _, ext := range filtered {
		hexStrs = append(hexStrs, fmt.Sprintf("%04x", ext))
	}

	if len(hexStrs) == 0 {
		return "000000000000"
	}

	return truncatedSHA256(strings.Join(hexStrs, ","))
}

// getTLSVersionString returns the JA4 version string
func getTLSVersionString(version, supportedVers uint16) string {
	// If supported_versions extension indicates TLS 1.3, use that
	if supportedVers == 0x0304 {
		return "13"
	}

	switch version {
	case 0x0304:
		return "13" // TLS 1.3
	case 0x0303:
		return "12" // TLS 1.2
	case 0x0302:
		return "11" // TLS 1.1
	case 0x0301:
		return "10" // TLS 1.0
	case 0x0300:
		return "s3" // SSL 3.0
	case 0x0002:
		return "s2" // SSL 2.0
	default:
		// For QUIC or unknown versions
		return "00"
	}
}

// isIPAddress checks if a string is an IP address
func isIPAddress(s string) bool {
	return net.ParseIP(s) != nil
}

// countNonGrease counts values that are not GREASE
func countNonGrease(values []uint16) int {
	count := 0
	for _, v := range values {
		if !isGrease(v) {
			count++
		}
	}
	return count
}

// countNonGreaseExtensions counts extensions that are not GREASE
func countNonGreaseExtensions(extensions []uint16) int {
	count := 0
	for _, ext := range extensions {
		if !isGrease(ext) {
			count++
		}
	}
	return count
}

// truncatedSHA256 computes SHA256 and returns first 12 hex characters
func truncatedSHA256(input string) string {
	if input == "" {
		return "000000000000"
	}
	hash := sha256.Sum256([]byte(input))
	return hex.EncodeToString(hash[:])[:12]
}

// ParseCipherSuites converts int32 slice to uint16 slice
func ParseCipherSuites(ciphers []int32) []uint16 {
	result := make([]uint16, len(ciphers))
	for i, c := range ciphers {
		result[i] = uint16(c)
	}
	return result
}

// ParseExtensions converts int32 slice to uint16 slice
func ParseExtensions(extensions []int32) []uint16 {
	result := make([]uint16, len(extensions))
	for i, e := range extensions {
		result[i] = uint16(e)
	}
	return result
}

// GetSupportedVersion extracts the TLS 1.3 supported_versions value from extensions
// Returns 0 if not found
func GetSupportedVersion(extensions []uint16, supportedVersionsData []byte) uint16 {
	// The supported_versions extension (type 43) contains the actual negotiated version
	// For TLS 1.3, the handshake version is 0x0303 but supported_versions contains 0x0304
	// This function would need the actual extension data to parse properly
	// For now, we rely on the caller to pass the parsed supported version
	return 0
}

// FormatJA4 formats a JA4 fingerprint for display
func FormatJA4(fingerprint string) string {
	return fingerprint
}

// ValidateJA4 checks if a JA4 fingerprint has the correct format
func ValidateJA4(fingerprint string) bool {
	parts := strings.Split(fingerprint, "_")
	if len(parts) != 3 {
		return false
	}
	// JA4_a should be 10 chars, JA4_b and JA4_c should be 12 chars each
	return len(parts[0]) == 10 && len(parts[1]) == 12 && len(parts[2]) == 12
}

// ValidateJA4S checks if a JA4S fingerprint has the correct format
// Format: {ja4s_a}_{ja4s_b}_{ja4s_c}
func ValidateJA4S(fingerprint string) bool {
	parts := strings.Split(fingerprint, "_")
	if len(parts) != 3 {
		return false
	}
	// JA4S_a: 7 chars (protocol + version + ext_count + alpn)
	// JA4S_b: 4 chars (cipher hex)
	// JA4S_c: 12 chars (truncated hash)
	return len(parts[0]) == 7 && len(parts[1]) == 4 && len(parts[2]) == 12
}

// JA4Raw returns the raw (unhashed) JA4 fingerprint for debugging
// Format: {ja4_a}_{sorted_ciphers}_{sorted_extensions_signature_algorithms}
func JA4Raw(data *ClientHelloData) string {
	ja4a := computeJA4a(data)

	// Raw cipher suites (filtered and sorted numerically)
	var filteredCiphers []uint16
	for _, cs := range data.CipherSuites {
		if !isGrease(cs) {
			filteredCiphers = append(filteredCiphers, cs)
		}
	}
	slices.Sort(filteredCiphers)
	var ciphers []string
	for _, cs := range filteredCiphers {
		ciphers = append(ciphers, fmt.Sprintf("%04x", cs))
	}

	// Raw extensions (filtered and sorted numerically)
	var filteredExts []uint16
	for _, ext := range data.Extensions {
		if !isGrease(ext) && ext != ExtensionSNI && ext != ExtensionALPN {
			filteredExts = append(filteredExts, ext)
		}
	}
	slices.Sort(filteredExts)
	var exts []string
	for _, ext := range filteredExts {
		exts = append(exts, fmt.Sprintf("%04x", ext))
	}

	extStr := strings.Join(exts, ",")

	// Add signature algorithms if present
	if len(data.SignatureAlgorithms) > 0 {
		var sigStrs []string
		for _, sig := range data.SignatureAlgorithms {
			sigStrs = append(sigStrs, fmt.Sprintf("%04x", sig))
		}
		extStr += "_" + strings.Join(sigStrs, ",")
	}

	return fmt.Sprintf("%s_%s_%s", ja4a, strings.Join(ciphers, ","), extStr)
}
