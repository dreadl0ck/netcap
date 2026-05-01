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

const serviceSNMP = "SNMP"

// SNMP version constants
const (
	snmpVersion1  = 0
	snmpVersion2c = 1
)

// snmpHarvesterFunc extracts community strings from SNMP v1/v2c traffic
// SNMP v1 and v2c use community strings as authentication
// Structure: [0x30][length][0x02][0x01][version][0x04][comm_len][community_string]...
func snmpHarvesterFunc(data []byte, ident string, ts time.Time) *types.Secret {
	if len(data) < 10 {
		return nil
	}

	// Look for SNMP message start: 0x30 (SEQUENCE)
	for i := 0; i < len(data)-10; i++ {
		// Check for SEQUENCE tag
		if data[i] != 0x30 {
			continue
		}

		// Skip length byte(s)
		offset := i + 1
		if data[offset] >= 0x80 {
			// Long form length
			lengthBytes := int(data[offset] & 0x7f)
			offset += lengthBytes + 1
		} else {
			// Short form length
			offset++
		}

		if offset+6 >= len(data) {
			continue
		}

		// Check for INTEGER tag (version)
		if data[offset] != 0x02 {
			continue
		}
		offset++

		// Version length (should be 1)
		if data[offset] != 0x01 {
			continue
		}
		offset++

		// Version value (0 = v1, 1 = v2c)
		version := data[offset]
		if version != snmpVersion1 && version != snmpVersion2c {
			continue
		}
		offset++

		// Check for OCTET STRING tag (community string)
		if data[offset] != 0x04 {
			continue
		}
		offset++

		// Community string length
		commLen := int(data[offset])
		offset++

		// Validate length
		if commLen == 0 || commLen > 255 || offset+commLen > len(data) {
			continue
		}

		// Extract community string
		community := data[offset : offset+commLen]

		// Validate it's printable ASCII (community strings should be)
		if !isPrintableASCII(community) {
			continue
		}

		versionStr := "v1"
		if version == snmpVersion2c {
			versionStr = "v2c"
		}

		return &types.Secret{
			Timestamp: ts.UnixNano(),
			Service:   serviceSNMP,
			Flow:      ident,
			User:      "", // SNMP doesn't have usernames
			Password:  string(community),
			Notes:     "SNMP " + versionStr + " community string",
		}
	}

	return nil
}

// getSNMPMinCommunityLength returns configured minimum community string length
func getSNMPMinCommunityLength() int {
	if harvesterConfig != nil {
		for _, hConfig := range harvesterConfig.Harvesters {
			if hConfig.Name == "SNMP" && hConfig.Parameters != nil {
				if params, ok := hConfig.Parameters["min_community_length"]; ok {
					switch v := params.(type) {
					case int:
						return v
					case float64:
						return int(v)
					}
				}
			}
		}
	}
	return 1 // Default minimum length
}

// getSNMPMaxCommunityLength returns configured maximum community string length
func getSNMPMaxCommunityLength() int {
	if harvesterConfig != nil {
		for _, hConfig := range harvesterConfig.Harvesters {
			if hConfig.Name == "SNMP" && hConfig.Parameters != nil {
				if params, ok := hConfig.Parameters["max_community_length"]; ok {
					switch v := params.(type) {
					case int:
						return v
					case float64:
						return int(v)
					}
				}
			}
		}
	}
	return 255 // Default maximum length
}

// isPrintableASCII checks if the bytes are all printable ASCII characters
func isPrintableASCII(data []byte) bool {
	minLen := getSNMPMinCommunityLength()
	maxLen := getSNMPMaxCommunityLength()

	// Check length constraints
	if len(data) < minLen || len(data) > maxLen {
		return false
	}

	for _, b := range data {
		// Allow space (0x20) through tilde (0x7e)
		if b < 0x20 || b > 0x7e {
			return false
		}
	}
	return len(data) > 0
}

// snmpUDPHarvester is a variant that can be used for UDP packets
// It's essentially the same but may be called from a different context
func snmpUDPHarvester(data []byte, ident string, ts time.Time) *types.Secret {
	return snmpHarvesterFunc(data, ident, ts)
}

// extractSNMPv3Secret extracts credentials from SNMP v3
// Note: SNMPv3 uses USM (User-based Security Model) which is more complex
// This is a stub for future implementation
func extractSNMPv3Secret(data []byte, ident string, ts time.Time) *types.Secret {
	// SNMPv3 structure is more complex and uses:
	// - msgUserName (username)
	// - msgAuthenticationParameters (for authentication)
	// - msgPrivacyParameters (for encryption)
	// This would require more complex ASN.1 parsing
	// For now, we'll focus on v1/v2c which use simple community strings

	// Check if this is SNMPv3 (version = 3)
	if len(data) < 20 {
		return nil
	}

	// Look for version 3
	versionIdx := bytes.Index(data, []byte{0x02, 0x01, 0x03})
	if versionIdx == -1 {
		return nil
	}

	// TODO: Implement full SNMPv3 USM parsing
	// For now, return nil as this requires more complex ASN.1 handling

	return nil
}

// snmpHarvester is the harvester definition for SNMP
var snmpHarvester = Harvester{
	Name:          "SNMP",
	Description:   "Simple Network Management Protocol - captures community strings from SNMPv1 and SNMPv2c",
	HarvesterFunc: snmpHarvesterFunc,
}
