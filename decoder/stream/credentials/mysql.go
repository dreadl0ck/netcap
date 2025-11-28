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
	"encoding/binary"
	"encoding/hex"
	"time"

	"github.com/dreadl0ck/netcap/types"
)

const serviceMySQL = "MySQL"

// MySQL protocol constants
const (
	mysqlProtocol10     = 10
	mysqlServerGreeting = 0x0a // Protocol version in greeting
	mysqlClientAuth     = 0x00 // Client authentication packet has no command byte at start
)

// mysqlHarvester extracts MySQL challenge-response authentication hashes
// MySQL uses a challenge-response mechanism that can be extracted and cracked offline
// Format: SHA1(password) XOR SHA1(challenge + SHA1(SHA1(password)))
func mysqlHarvesterFunc(data []byte, ident string, ts time.Time) *types.Credentials {
	if len(data) < 50 {
		return nil
	}

	var (
		username  string
		challenge []byte
		response  []byte
		database  string
	)

	// Search for MySQL Server Greeting (Initial Handshake Packet)
	// Format: [length:3][seq:1][protocol:1][version\0][thread_id:4][challenge:8][filler:1]
	//         [capability:2][charset:1][status:2][capability:2][challenge_len:1][reserved:10][challenge:n]
	for i := 0; i < len(data)-50; i++ {
		// Check packet length (3 bytes little-endian)
		if i+4 > len(data) {
			break
		}

		pktLen := int(data[i]) | int(data[i+1])<<8 | int(data[i+2])<<16
		seqNum := data[i+3]

		// Initial handshake is typically sequence 0
		if seqNum != 0 || pktLen < 40 || pktLen > 10000 || i+4+pktLen > len(data) {
			continue
		}

		// Check protocol version (should be 10)
		if data[i+4] != mysqlProtocol10 {
			continue
		}

		// Find server version string (null-terminated)
		versionStart := i + 5
		nullIdx := bytes.IndexByte(data[versionStart:i+4+pktLen], 0)
		if nullIdx == -1 || nullIdx > 100 {
			continue
		}

		// Extract first part of challenge (8 bytes after thread_id)
		challengeStart := versionStart + nullIdx + 1 + 4 // +1 for null, +4 for thread_id
		if challengeStart+8 > i+4+pktLen {
			continue
		}

		challenge1 := data[challengeStart : challengeStart+8]

		// Skip to second part of challenge
		// After challenge1: [filler:1][capability:2][charset:1][status:2][capability:2][challenge_len:1][reserved:10]
		challenge2Start := challengeStart + 8 + 1 + 2 + 1 + 2 + 2 + 1 + 10
		if challenge2Start+12 > i+4+pktLen {
			continue
		}

		challenge2 := data[challenge2Start : challenge2Start+12]

		// Combine both parts of the challenge
		challenge = append(challenge1, challenge2...)
	}

	// Search for MySQL Client Authentication Packet
	// Format: [length:3][seq:1][capability:4][max_packet:4][charset:1][reserved:23]
	//         [username\0][response_length:1][response:n][database\0]
	for i := 0; i < len(data)-40; i++ {
		if i+4 > len(data) {
			break
		}

		pktLen := int(data[i]) | int(data[i+1])<<8 | int(data[i+2])<<16
		seqNum := data[i+3]

		// Client auth response is typically sequence 1
		if seqNum != 1 || pktLen < 32 || pktLen > 10000 || i+4+pktLen > len(data) {
			continue
		}

		// Skip capability flags (4 bytes), max packet (4 bytes), charset (1 byte), reserved (23 bytes) = 32 bytes
		usernameStart := i + 4 + 32
		if usernameStart >= i+4+pktLen {
			continue
		}

		// Extract username (null-terminated)
		usernameEnd := bytes.IndexByte(data[usernameStart:i+4+pktLen], 0)
		if usernameEnd == -1 {
			continue
		}
		username = string(data[usernameStart : usernameStart+usernameEnd])

		// Extract response length and response
		responseStart := usernameStart + usernameEnd + 1
		if responseStart >= i+4+pktLen {
			continue
		}

		responseLen := int(data[responseStart])
		responseStart++

		if responseLen > 0 && responseStart+responseLen <= i+4+pktLen {
			response = make([]byte, responseLen)
			copy(response, data[responseStart:responseStart+responseLen])
		}

		// Extract database name if present
		dbStart := responseStart + responseLen
		if dbStart < i+4+pktLen {
			dbEnd := bytes.IndexByte(data[dbStart:i+4+pktLen], 0)
			if dbEnd != -1 && dbEnd > 0 {
				database = string(data[dbStart : dbStart+dbEnd])
			}
		}

		break
	}

	// If we have username, challenge, and response, create credential entry
	if username != "" && len(challenge) > 0 && len(response) > 0 {
		// Format for Hashcat mode 300: $mysqlna$challenge*response
		// Or mode 11200 for MySQL-sha1: username:salt:hash
		challengeHex := hex.EncodeToString(challenge)
		responseHex := hex.EncodeToString(response)

		hashcatFormat := "$mysqlna$" + challengeHex + "*" + responseHex

		notes := "MySQL challenge-response (Hashcat mode 11200)"
		if database != "" {
			notes += ", Database: " + database
		}

		return &types.Credentials{
			Timestamp: ts.UnixNano(),
			Service:   serviceMySQL,
			Flow:      ident,
			User:      username,
			Password:  hashcatFormat,
			Notes:     notes,
		}
	}

	return nil
}

// mysqlOldPasswordHarvester extracts MySQL old password hashes (pre-4.1)
// Old password hashing is weaker and uses a different algorithm
func mysqlOldPasswordHarvesterFunc(data []byte, ident string, ts time.Time) *types.Credentials {
	// Old password authentication is similar but uses 8-byte challenge
	// and 8-byte response with a different hashing algorithm
	// This is less common but still worth detecting

	if len(data) < 30 {
		return nil
	}

	// Look for old protocol handshake (protocol version < 10)
	for i := 0; i < len(data)-30; i++ {
		if i+4 > len(data) {
			break
		}

		pktLen := int(data[i]) | int(data[i+1])<<8 | int(data[i+2])<<16
		seqNum := data[i+3]

		if seqNum != 0 || pktLen < 20 || pktLen > 10000 || i+4+pktLen > len(data) {
			continue
		}

		// Check for old protocol (version 9 or lower)
		protocolVer := data[i+4]
		if protocolVer >= mysqlProtocol10 {
			continue
		}

		// Old protocol uses 8-byte challenge
		// Extract and process similar to above but with old format
		// For brevity, not implementing full old password extraction here
		// as it's rarely used in modern systems
	}

	return nil
}

// parseMySQLLengthEncodedInteger parses MySQL's length-encoded integer format
func parseMySQLLengthEncodedInteger(data []byte) (value int, bytesRead int) {
	if len(data) == 0 {
		return 0, 0
	}

	first := data[0]

	if first < 0xfb {
		return int(first), 1
	} else if first == 0xfc && len(data) >= 3 {
		return int(binary.LittleEndian.Uint16(data[1:3])), 3
	} else if first == 0xfd && len(data) >= 4 {
		return int(data[1]) | int(data[2])<<8 | int(data[3])<<16, 4
	} else if first == 0xfe && len(data) >= 9 {
		return int(binary.LittleEndian.Uint64(data[1:9])), 9
	}

	return 0, 0
}

// mysqlHarvester is the harvester definition for MySQL
var mysqlHarvester = Harvester{
	Name:          "MySQL",
	Description:   "MySQL/MariaDB - captures challenge-response authentication hashes (Hashcat mode 11200)",
	HarvesterFunc: mysqlHarvesterFunc,
}
