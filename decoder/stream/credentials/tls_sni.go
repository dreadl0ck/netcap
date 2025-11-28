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

package credentials

import (
	"bytes"
	"fmt"
	"time"

	"github.com/dreadl0ck/netcap/types"
)

const serviceTLSSNI = "TLS SNI"

// TLS Record Type constants
const (
	tlsRecordTypeHandshake  = 0x16
	tlsHandshakeClientHello = 0x01
)

// TLS Extension types
const (
	tlsExtensionServerName = 0x0000
)

// tlsSNIHarvesterFunc extracts Server Name Indication from TLS Client Hello messages.
// SNI reveals the intended destination hostname even in encrypted TLS traffic.
// This is useful for tracking HTTPS destinations without decryption.
func tlsSNIHarvesterFunc(data []byte, ident string, ts time.Time) *types.Credentials {
	// Minimum size for a TLS record with SNI
	if len(data) < 50 {
		return nil
	}

	// Search for TLS Client Hello in the data
	for i := 0; i < len(data)-50; i++ {
		// Check for TLS record header
		// Record Type: Handshake (0x16)
		// Version: TLS 1.0-1.3 (0x0301 - 0x0304) or SSL 3.0 (0x0300)
		if data[i] != tlsRecordTypeHandshake {
			continue
		}

		// Check TLS version (major version should be 0x03)
		if i+1 >= len(data) || data[i+1] != 0x03 {
			continue
		}

		// Minor version 0x00-0x04 (SSL 3.0 through TLS 1.3)
		if i+2 >= len(data) || data[i+2] > 0x04 {
			continue
		}

		// Extract record length
		if i+5 >= len(data) {
			continue
		}
		recordLen := int(data[i+3])<<8 | int(data[i+4])
		if recordLen <= 0 || i+5+recordLen > len(data) {
			continue
		}

		// Check for Client Hello handshake message
		if i+5 >= len(data) || data[i+5] != tlsHandshakeClientHello {
			continue
		}

		// Parse Client Hello to find SNI extension
		sni := extractSNIFromClientHello(data[i+5:])
		if sni != "" {
			notes := "TLS Server Name Indication - encrypted destination"

			return &types.Credentials{
				Timestamp: ts.UnixNano(),
				Service:   serviceTLSSNI,
				Flow:      ident,
				User:      sni, // Store domain in User field for display
				Password:  "",
				Notes:     notes,
			}
		}
	}

	return nil
}

// extractSNIFromClientHello parses a TLS Client Hello message to extract the SNI extension
func extractSNIFromClientHello(data []byte) string {
	// Client Hello structure:
	// [0]: Handshake type (0x01 = Client Hello)
	// [1-3]: Length (24-bit)
	// [4-5]: Client Version
	// [6-37]: Random (32 bytes)
	// [38]: Session ID Length
	// ... Session ID
	// ... Cipher Suites
	// ... Compression Methods
	// ... Extensions

	if len(data) < 43 {
		return ""
	}

	// Skip handshake type
	pos := 1

	// Skip handshake length (3 bytes)
	pos += 3

	// Skip client version
	pos += 2

	// Skip random (32 bytes)
	pos += 32

	if pos >= len(data) {
		return ""
	}

	// Session ID length
	sessionIDLen := int(data[pos])
	pos++
	pos += sessionIDLen

	if pos+2 > len(data) {
		return ""
	}

	// Cipher suites length
	cipherSuitesLen := int(data[pos])<<8 | int(data[pos+1])
	pos += 2
	pos += cipherSuitesLen

	if pos+1 > len(data) {
		return ""
	}

	// Compression methods length
	compressionLen := int(data[pos])
	pos++
	pos += compressionLen

	if pos+2 > len(data) {
		return ""
	}

	// Extensions length
	extensionsLen := int(data[pos])<<8 | int(data[pos+1])
	pos += 2

	extensionsEnd := pos + extensionsLen
	if extensionsEnd > len(data) {
		extensionsEnd = len(data)
	}

	// Parse extensions
	for pos+4 <= extensionsEnd {
		extType := int(data[pos])<<8 | int(data[pos+1])
		extLen := int(data[pos+2])<<8 | int(data[pos+3])
		pos += 4

		if pos+extLen > extensionsEnd {
			break
		}

		// Server Name extension (type 0x0000)
		if extType == tlsExtensionServerName {
			return parseSNIExtension(data[pos : pos+extLen])
		}

		pos += extLen
	}

	return ""
}

// parseSNIExtension parses the SNI extension data to extract the hostname
func parseSNIExtension(data []byte) string {
	// SNI Extension structure:
	// [0-1]: Server Name List Length
	// [2]: Server Name Type (0x00 = hostname)
	// [3-4]: Server Name Length
	// [5...]: Server Name

	if len(data) < 5 {
		return ""
	}

	// Skip list length
	pos := 2

	// Check name type (0x00 = hostname)
	if data[pos] != 0x00 {
		return ""
	}
	pos++

	// Get name length
	if pos+2 > len(data) {
		return ""
	}
	nameLen := int(data[pos])<<8 | int(data[pos+1])
	pos += 2

	if pos+nameLen > len(data) {
		return ""
	}

	hostname := string(data[pos : pos+nameLen])

	// Validate hostname - should be ASCII and contain a dot
	if !isValidHostname(hostname) {
		return ""
	}

	return hostname
}

// isValidHostname checks if the extracted hostname looks valid
func isValidHostname(hostname string) bool {
	if len(hostname) < 4 || len(hostname) > 253 {
		return false
	}

	// Should contain at least one dot
	if !bytes.Contains([]byte(hostname), []byte(".")) {
		return false
	}

	// Check for valid characters
	for _, c := range hostname {
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
			(c >= '0' && c <= '9') || c == '-' || c == '.') {
			return false
		}
	}

	return true
}

// tlsSNIHarvester is the harvester definition for TLS SNI
var tlsSNIHarvester = Harvester{
	Name:          "TLS SNI",
	Description:   "TLS Server Name Indication - captures encrypted HTTPS destination hostnames from Client Hello",
	HarvesterFunc: tlsSNIHarvesterFunc,
}

// GetTLSSNIPort returns configured ports or defaults
func getTLSSNIPorts() []int {
	if harvesterConfig != nil {
		for _, hConfig := range harvesterConfig.Harvesters {
			if hConfig.Name == "TLS SNI" && len(hConfig.Ports) > 0 {
				return hConfig.Ports
			}
		}
	}
	return []int{443, 8443, 993, 995, 465, 636} // Common TLS ports
}

// Helper for formatting SNI output
func formatSNIOutput(hostname string, port int) string {
	if port == 443 {
		return fmt.Sprintf("https://%s", hostname)
	}
	return fmt.Sprintf("https://%s:%d", hostname, port)
}
