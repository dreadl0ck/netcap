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

package secret

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

// ldapHarvesterFunc extracts credentials from LDAP Simple Bind operations
// LDAP uses ASN.1 BER encoding, but Simple Bind is simple enough to parse manually
// Structure: SEQUENCE { messageID, BindRequest { version, name, simple_auth } }
// BindRequest: [APPLICATION 0] (0x60)
//
//	version: INTEGER
//	name: OCTET STRING (DN)
//	authentication: CHOICE {
//	  simple: [0] OCTET STRING (0x80) <- plaintext password
//	}
func ldapHarvesterFunc(data []byte, ident string, ts time.Time) *types.Secret {
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

		return &types.Secret{
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

// getLDAPUsernameAttributes returns configured DN attributes or defaults
func getLDAPUsernameAttributes() []string {
	if harvesterConfig != nil {
		for _, hConfig := range harvesterConfig.Harvesters {
			if hConfig.Name == "LDAP" && hConfig.Parameters != nil {
				if params, ok := hConfig.Parameters["username_attributes"]; ok {
					if paramSlice, ok := params.([]any); ok {
						result := make([]string, 0, len(paramSlice))
						for _, p := range paramSlice {
							if strParam, ok := p.(string); ok {
								result = append(result, strParam)
							}
						}
						if len(result) > 0 {
							return result
						}
					}
				}
			}
		}
	}
	return []string{"cn", "uid", "mail", "sAMAccountName"}
}

// shouldExtractSimpleLDAPUsername returns whether to extract simple username or return full DN
func shouldExtractSimpleLDAPUsername() bool {
	if harvesterConfig != nil {
		for _, hConfig := range harvesterConfig.Harvesters {
			if hConfig.Name == "LDAP" && hConfig.Parameters != nil {
				if params, ok := hConfig.Parameters["extract_simple_username"]; ok {
					if boolParam, ok := params.(bool); ok {
						return boolParam
					}
				}
			}
		}
	}
	return true // Default to extracting simple username
}

// extractLDAPUsername extracts a simple username from an LDAP DN
// For example: "cn=admin,dc=example,dc=com" -> "admin"
func extractLDAPUsername(dn string) string {
	// If configured to return full DN, do so
	if !shouldExtractSimpleLDAPUsername() {
		return dn
	}

	// Try each configured attribute in order
	for _, attr := range getLDAPUsernameAttributes() {
		searchStr := attr + "="
		attrIdx := bytes.Index([]byte(dn), []byte(searchStr))
		if attrIdx == -1 {
			continue
		}

		attrIdx += len(searchStr)

		// Find the end of the attribute value (comma or end of string)
		commaIdx := bytes.IndexByte([]byte(dn[attrIdx:]), ',')
		if commaIdx == -1 {
			return dn[attrIdx:]
		}

		return dn[attrIdx : attrIdx+commaIdx]
	}

	return dn // Return full DN if we can't parse it
}

// ldapHarvester is the harvester definition for LDAP
var ldapHarvester = Harvester{
	Name:          "LDAP",
	Description:   "Lightweight Directory Access Protocol - captures Simple Bind credentials (plaintext)",
	HarvesterFunc: ldapHarvesterFunc,
}
