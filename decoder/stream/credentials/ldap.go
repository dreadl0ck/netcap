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

package credentials

import (
	"bytes"
	"time"

	"github.com/dreadl0ck/netcap/types"
)

const serviceLDAP = "LDAP"

// LDAP operation types
const (
	ldapBindRequest = 0x60
)

// Authentication choice types
const (
	ldapAuthSimple = 0x80 // Simple authentication (plaintext)
)

// ldapHarvester extracts credentials from LDAP Simple Bind operations
// LDAP uses ASN.1 BER encoding, but Simple Bind is simple enough to parse manually
// Structure: SEQUENCE { messageID, BindRequest { version, name, simple_auth } }
// BindRequest: [APPLICATION 0] (0x60)
//   version: INTEGER
//   name: OCTET STRING (DN)
//   authentication: CHOICE {
//     simple: [0] OCTET STRING (0x80) <- plaintext password
//   }
func ldapHarvester(data []byte, ident string, ts time.Time) *types.Credentials {
	if len(data) < 20 {
		return nil
	}

	// Search for LDAP Bind Request (APPLICATION 0 = 0x60)
	for i := 0; i < len(data)-20; i++ {
		if data[i] != ldapBindRequest {
			continue
		}

		offset := i + 1

		// Skip bind request length
		length, bytesRead := parseASN1Length(data[offset:])
		if length == 0 {
			continue
		}
		offset += bytesRead

		if offset+10 >= len(data) {
			continue
		}

		// Parse version (should be INTEGER 0x02)
		if data[offset] != 0x02 {
			continue
		}
		offset++

		// Skip version length and value
		versionLen := int(data[offset])
		offset += versionLen + 1

		if offset+4 >= len(data) {
			continue
		}

		// Parse DN (name) - OCTET STRING (0x04)
		if data[offset] != 0x04 {
			continue
		}
		offset++

		// Get DN length
		dnLength, bytesRead := parseASN1Length(data[offset:])
		if dnLength == 0 || offset+bytesRead+dnLength > len(data) {
			continue
		}
		offset += bytesRead

		// Extract DN (username/distinguished name)
		dn := string(data[offset : offset+dnLength])
		offset += dnLength

		if offset+2 >= len(data) {
			continue
		}

		// Check for Simple authentication (0x80)
		if data[offset] != ldapAuthSimple {
			// Not simple auth, might be SASL or other methods
			continue
		}
		offset++

		// Get password length
		passLength, bytesRead := parseASN1Length(data[offset:])
		if passLength == 0 || offset+bytesRead+passLength > len(data) {
			continue
		}
		offset += bytesRead

		// Extract password
		password := string(data[offset : offset+passLength])

		// Skip empty passwords (anonymous bind)
		if len(password) == 0 {
			continue
		}

		return &types.Credentials{
			Timestamp: ts.UnixNano(),
			Service:   serviceLDAP,
			Flow:      ident,
			User:      dn,
			Password:  password,
			Notes:     "LDAP Simple Bind",
		}
	}

	return nil
}

// parseASN1Length parses ASN.1 BER/DER length encoding
// Returns: (length, bytesRead)
func parseASN1Length(data []byte) (int, int) {
	if len(data) == 0 {
		return 0, 0
	}

	// Short form: length < 128
	if data[0] < 0x80 {
		return int(data[0]), 1
	}

	// Long form: first byte indicates number of length bytes
	lengthBytes := int(data[0] & 0x7f)
	if lengthBytes == 0 || lengthBytes > 4 || len(data) < lengthBytes+1 {
		return 0, 0
	}

	// Parse multi-byte length
	length := 0
	for i := 1; i <= lengthBytes; i++ {
		length = (length << 8) | int(data[i])
	}

	return length, lengthBytes + 1
}

// extractLDAPUsername extracts a simple username from an LDAP DN
// For example: "cn=admin,dc=example,dc=com" -> "admin"
func extractLDAPUsername(dn string) string {
	// Look for cn= (Common Name)
	cnIdx := bytes.Index([]byte(dn), []byte("cn="))
	if cnIdx == -1 {
		// Look for uid=
		cnIdx = bytes.Index([]byte(dn), []byte("uid="))
		if cnIdx == -1 {
			return dn // Return full DN if we can't parse it
		}
		cnIdx += 4 // len("uid=")
	} else {
		cnIdx += 3 // len("cn=")
	}

	// Find the end of the CN value (comma or end of string)
	commaIdx := bytes.IndexByte([]byte(dn[cnIdx:]), ',')
	if commaIdx == -1 {
		return dn[cnIdx:]
	}

	return dn[cnIdx : cnIdx+commaIdx]
}

