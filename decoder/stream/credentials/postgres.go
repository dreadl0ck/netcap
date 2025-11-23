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
	"encoding/binary"
	"time"

	"github.com/dreadl0ck/netcap/types"
)

const servicePostgres = "PostgreSQL"

// PostgreSQL message types
const (
	postgresStartupMessage = 0 // No type byte, starts with length
	postgresPasswordMessage = 'p'
)

// postgresHarvester extracts credentials from PostgreSQL authentication
// PostgreSQL protocol messages have format: [length:4][type:1][data...]
// Startup message has format: [length:4][version:4][param=value\0]...
// Password message has format: [type:1='p'][length:4][password\0]
func postgresHarvester(data []byte, ident string, ts time.Time) *types.Credentials {
	if len(data) < 8 {
		return nil
	}

	var username string
	var password string
	var database string

	// Search for Startup Message (contains username and database)
	// Startup message starts with length (4 bytes) + version (4 bytes, typically 0x00030000)
	for i := 0; i < len(data)-8; i++ {
		// Check if this could be a startup message
		// Length should be reasonable (between 8 and 10000 bytes)
		if i+4 > len(data) {
			break
		}

		msgLen := int(binary.BigEndian.Uint32(data[i : i+4]))
		if msgLen < 8 || msgLen > 10000 || i+msgLen > len(data) {
			continue
		}

		// Check for PostgreSQL version (3.0 = 0x00030000)
		if i+8 > len(data) {
			break
		}
		version := binary.BigEndian.Uint32(data[i+4 : i+8])
		if version != 0x00030000 && version != 0x00030001 && version != 0x00030002 {
			continue
		}

		// Parse parameters (key\0value\0 pairs)
		paramStart := i + 8
		paramEnd := i + msgLen

		user, db := parsePostgresParams(data[paramStart:paramEnd])
		if user != "" {
			username = user
			database = db
		}
	}

	// Search for Password Message (type 'p')
	for i := 0; i < len(data)-5; i++ {
		if data[i] != postgresPasswordMessage {
			continue
		}

		// Get message length
		if i+5 > len(data) {
			break
		}
		msgLen := int(binary.BigEndian.Uint32(data[i+1 : i+5]))
		if msgLen < 5 || msgLen > 10000 || i+1+msgLen > len(data) {
			continue
		}

		// Extract password (null-terminated string)
		passStart := i + 5
		passEnd := i + 1 + msgLen
		if passEnd > len(data) {
			continue
		}

		passData := data[passStart:passEnd]
		// Remove null terminator if present
		if nullIdx := bytes.IndexByte(passData, 0); nullIdx != -1 {
			passData = passData[:nullIdx]
		}

		password = string(passData)
		break
	}

	// Return credentials if we found both username and password
	if username != "" && password != "" {
		notes := "PostgreSQL plaintext authentication"
		if database != "" {
			notes += ", Database: " + database
		}

		return &types.Credentials{
			Timestamp: ts.UnixNano(),
			Service:   servicePostgres,
			Flow:      ident,
			User:      username,
			Password:  password,
			Notes:     notes,
		}
	}

	return nil
}

// parsePostgresParams extracts parameters from PostgreSQL startup message
// Format: key\0value\0key\0value\0...\0
func parsePostgresParams(data []byte) (username, database string) {
	params := bytes.Split(data, []byte{0})

	for i := 0; i < len(params)-1; i += 2 {
		key := string(params[i])
		value := string(params[i+1])

		switch key {
		case "user":
			username = value
		case "database":
			database = value
		}
	}

	return username, database
}

// postgresHashHarvester extracts MD5 challenge-response hashes from PostgreSQL
// MD5 authentication: server sends salt, client responds with md5(md5(password+username)+salt)
// This is useful for offline cracking with tools like Hashcat
func postgresHashHarvester(data []byte, ident string, ts time.Time) *types.Credentials {
	if len(data) < 20 {
		return nil
	}

	var username string
	var salt []byte
	var response []byte

	// Search for Authentication MD5Password message (type 'R', subtype 5)
	// Format: [type:1='R'][length:4][authtype:4=5][salt:4]
	for i := 0; i < len(data)-13; i++ {
		if data[i] != 'R' {
			continue
		}

		if i+13 > len(data) {
			break
		}

		msgLen := int(binary.BigEndian.Uint32(data[i+1 : i+5]))
		authType := binary.BigEndian.Uint32(data[i+5 : i+9])

		// authType 5 = MD5 password
		if authType == 5 && msgLen >= 12 {
			// Extract 4-byte salt
			salt = make([]byte, 4)
			copy(salt, data[i+9:i+13])
		}
	}

	// Search for username in startup message
	for i := 0; i < len(data)-8; i++ {
		if i+4 > len(data) {
			break
		}
		msgLen := int(binary.BigEndian.Uint32(data[i : i+4]))
		if msgLen < 8 || msgLen > 10000 || i+msgLen > len(data) {
			continue
		}

		if i+8 > len(data) {
			break
		}
		version := binary.BigEndian.Uint32(data[i+4 : i+8])
		if version == 0x00030000 {
			user, _ := parsePostgresParams(data[i+8 : i+msgLen])
			if user != "" {
				username = user
				break
			}
		}
	}

	// Search for password response (MD5 hash)
	// Format: [type:1='p'][length:4]['md5'][32-char-hex-hash]\0
	for i := 0; i < len(data)-40; i++ {
		if data[i] != postgresPasswordMessage {
			continue
		}

		if i+5 > len(data) {
			break
		}

		msgLen := int(binary.BigEndian.Uint32(data[i+1 : i+5]))
		if msgLen < 40 || i+1+msgLen > len(data) {
			continue
		}

		// Check for "md5" prefix
		if i+8 > len(data) {
			break
		}
		if string(data[i+5:i+8]) == "md5" {
			// Extract MD5 hash (32 hex characters)
			hashEnd := i + 40
			if hashEnd > len(data) {
				break
			}
			response = make([]byte, 32)
			copy(response, data[i+8:i+40])
			break
		}
	}

	// If we have username, salt, and response, create a hash credential
	if username != "" && len(salt) > 0 && len(response) > 0 {
		// Format for Hashcat: username:$postgres$username*salt*hash
		hashcatFormat := username + ":$postgres$" + username + "*" + string(salt) + "*" + string(response)

		return &types.Credentials{
			Timestamp: ts.UnixNano(),
			Service:   servicePostgres,
			Flow:      ident,
			User:      username,
			Password:  hashcatFormat,
			Notes:     "PostgreSQL MD5 challenge-response (Hashcat mode 11100)",
		}
	}

	return nil
}

