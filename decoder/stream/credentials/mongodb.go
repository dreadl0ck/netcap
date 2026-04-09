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
	"encoding/base64"
	"encoding/binary"
	"strings"
	"time"

	"github.com/dreadl0ck/netcap/types"
)

const serviceMongoDB = "MongoDB"

// MongoDB wire protocol opcodes
const (
	mongoOpReply       = 1
	mongoOpUpdate      = 2001
	mongoOpInsert      = 2002
	mongoOpQuery       = 2004
	mongoOpGetMore     = 2005
	mongoOpDelete      = 2006
	mongoOpKillCursors = 2007
	mongoOpMsg         = 2013
)

// mongodbHarvester extracts credentials from MongoDB SCRAM-SHA-1 and SCRAM-SHA-256 authentication
// MongoDB uses SASL SCRAM (Salted Challenge Response Authentication Mechanism)
// SCRAM-SHA-1 and SCRAM-SHA-256 are similar to SMTP/IMAP CRAM-MD5 but more complex
func mongodbHarvesterFunc(data []byte, ident string, ts time.Time) *types.Credentials {
	if len(data) < 50 {
		return nil
	}

	var (
		username    string
		serverNonce string
		salt        string
		iterations  string
		clientProof string
		mechanism   string
	)

	// MongoDB SCRAM authentication happens in multiple round trips:
	// 1. Client sends: saslStart with mechanism and client-first-message
	// 2. Server sends: challenge with server-first-message (contains salt, nonce, iterations)
	// 3. Client sends: saslContinue with client-final-message (contains proof)
	// 4. Server sends: completion with server-final-message

	// Look for SCRAM authentication messages in MongoDB wire protocol
	// Messages are typically in BSON format within MongoDB queries

	// Search for "saslStart" command
	saslStartIdx := bytes.Index(data, []byte("saslStart"))
	if saslStartIdx != -1 {
		// Extract mechanism (SCRAM-SHA-1 or SCRAM-SHA-256)
		if bytes.Contains(data[saslStartIdx:], []byte("SCRAM-SHA-256")) {
			mechanism = "SCRAM-SHA-256"
		} else if bytes.Contains(data[saslStartIdx:], []byte("SCRAM-SHA-1")) {
			mechanism = "SCRAM-SHA-1"
		}

		// Extract client-first-message
		// Format: n,,n=username,r=clientNonce
		clientFirstIdx := bytes.Index(data[saslStartIdx:], []byte("n,,n="))
		if clientFirstIdx != -1 {
			clientFirstIdx += saslStartIdx
			// Extract username
			usernameStart := clientFirstIdx + 5 // len("n,,n=")

			// Bounds check for username extraction
			usernameEnd := min(usernameStart+200, len(data))
			commaIdx := bytes.IndexByte(data[usernameStart:usernameEnd], ',')
			if commaIdx != -1 {
				username = string(data[usernameStart : usernameStart+commaIdx])
			}

			// Extract client nonce (not stored, just validated)
			// Bounds check for nonce extraction
			nonceSearchEnd := min(usernameStart+300, len(data))
			nonceIdx := bytes.Index(data[usernameStart:nonceSearchEnd], []byte(",r="))
			if nonceIdx != -1 {
				// Client nonce is present, validation successful
				_ = nonceIdx
			}
		}
	}

	// Search for server challenge response
	// Contains: r=serverNonce,s=salt,i=iterations
	serverChallengeIdx := bytes.Index(data, []byte("r="))
	if serverChallengeIdx != -1 {
		// Bounds check for server challenge search
		challengeSearchEnd := min(serverChallengeIdx+200, len(data))

		if bytes.Contains(data[serverChallengeIdx:challengeSearchEnd], []byte(",s=")) {
			// Extract server nonce (includes client nonce + server nonce)
			nonceStart := serverChallengeIdx + 2

			// Bounds check for nonce extraction
			nonceSearchEnd := min(nonceStart+100, len(data))
			nonceEnd := bytes.IndexByte(data[nonceStart:nonceSearchEnd], ',')
			if nonceEnd != -1 {
				serverNonce = string(data[nonceStart : nonceStart+nonceEnd])
			}

			// Extract salt
			// Bounds check for salt search
			saltSearchEnd := min(serverChallengeIdx+300, len(data))
			saltIdx := bytes.Index(data[serverChallengeIdx:saltSearchEnd], []byte(",s="))
			if saltIdx != -1 {
				saltStart := serverChallengeIdx + saltIdx + 3

				// Bounds check for salt extraction
				saltEnd := min(saltStart+100, len(data))
				saltEndIdx := bytes.IndexByte(data[saltStart:saltEnd], ',')
				if saltEndIdx != -1 {
					salt = string(data[saltStart : saltStart+saltEndIdx])
				}
			}

			// Extract iterations
			// Bounds check for iterations search
			iterSearchEnd := min(serverChallengeIdx+400, len(data))
			iterIdx := bytes.Index(data[serverChallengeIdx:iterSearchEnd], []byte(",i="))
			if iterIdx != -1 {
				iterStart := serverChallengeIdx + iterIdx + 3

				// Bounds check for iteration extraction
				iterEnd := min(iterStart+20, len(data))
				iterEndIdx := bytes.IndexAny(data[iterStart:iterEnd], ",\x00\r\n")
				if iterEndIdx != -1 {
					iterations = string(data[iterStart : iterStart+iterEndIdx])
				}
			}
		}
	}

	// Search for client proof
	// Contains: c=biws,r=nonce,p=proof
	proofIdx := bytes.Index(data, []byte(",p="))
	if proofIdx != -1 {
		proofStart := proofIdx + 3

		// Bounds check for proof extraction
		proofSearchEnd := min(proofStart+100, len(data))
		proofEnd := bytes.IndexAny(data[proofStart:proofSearchEnd], ",\x00\r\n")
		if proofEnd != -1 {
			clientProof = string(data[proofStart : proofStart+proofEnd])
		}
	}

	// If we have enough information, create a credential entry
	if username != "" && salt != "" && iterations != "" && clientProof != "" {
		// Format similar to PostgreSQL SCRAM
		// For offline cracking, we need: mechanism, username, salt, iterations, and proof
		hashcatFormat := "$mongodb$*" + mechanism + "*" + username + "*" + salt + "*" + iterations + "*" + clientProof

		notes := "MongoDB " + mechanism + " authentication"
		if serverNonce != "" {
			notes += ", Nonce: " + serverNonce
		}

		return &types.Credentials{
			Timestamp: ts.UnixNano(),
			Service:   serviceMongoDB,
			Flow:      ident,
			User:      username,
			Password:  hashcatFormat,
			Notes:     notes,
		}
	}

	return nil
}

// mongodbChallengeResponseHarvester is an alternative approach focusing on the wire protocol
func mongodbChallengeResponseHarvesterFunc(data []byte, ident string, ts time.Time) *types.Credentials {
	// Parse MongoDB wire protocol messages
	// Standard message header: [messageLength:4][requestID:4][responseTo:4][opCode:4][message...]

	for i := 0; i < len(data)-16; i++ {
		if i+16 > len(data) {
			break
		}

		// Read message length
		msgLen := int(binary.LittleEndian.Uint32(data[i : i+4]))
		if msgLen < 16 || msgLen > 100000 || i+msgLen > len(data) {
			continue
		}

		// Read opcode
		opCode := int(binary.LittleEndian.Uint32(data[i+12 : i+16]))

		// Look for query operations (OP_QUERY or OP_MSG)
		if opCode == mongoOpQuery || opCode == mongoOpMsg {
			messageData := data[i+16 : i+msgLen]

			// Check if this contains authentication data
			if bytes.Contains(messageData, []byte("saslStart")) ||
				bytes.Contains(messageData, []byte("saslContinue")) ||
				bytes.Contains(messageData, []byte("authenticate")) {

				// Process with main harvester
				return mongodbHarvesterFunc(messageData, ident, ts)
			}
		}

		// Move to next potential message
		i += msgLen - 1
	}

	return nil
}

// parseMongoDBSCRAM parses SCRAM messages for MongoDB
func parseMongoDBSCRAM(message string) map[string]string {
	result := make(map[string]string)

	// SCRAM message format: key=value,key=value,...
	parts := strings.SplitSeq(message, ",")
	for part := range parts {
		kv := strings.SplitN(part, "=", 2)
		if len(kv) == 2 {
			result[kv[0]] = kv[1]
		}
	}

	return result
}

// decodeSCRAMBase64 decodes base64-encoded SCRAM fields
func decodeSCRAMBase64(encoded string) string {
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return encoded
	}
	return string(decoded)
}

// mongodbPlaintextHarvester detects old MongoDB versions that might use plaintext
// Very old MongoDB versions (pre-2.6) had weaker authentication
func mongodbPlaintextHarvesterFunc(data []byte, ident string, ts time.Time) *types.Credentials {
	// Look for old-style "getnonce" and "authenticate" commands
	// Format: {authenticate: 1, user: "username", nonce: "nonce", key: "key"}

	if !bytes.Contains(data, []byte("authenticate")) {
		return nil
	}

	// Look for user field
	found := bytes.Contains(data, []byte("user"))
	if !found {
		return nil
	}

	// This is complex to parse without a full BSON parser
	// For now, just detect that old-style auth is being used

	return &types.Credentials{
		Timestamp: ts.UnixNano(),
		Service:   serviceMongoDB,
		Flow:      ident,
		User:      "",
		Password:  "",
		Notes:     "MongoDB old-style authentication detected (pre-2.6)",
	}
}

// mongodbHarvester is the harvester definition for MongoDB
var mongodbHarvester = Harvester{
	Name:          "MongoDB",
	Description:   "MongoDB database - captures SCRAM-SHA-1 and SCRAM-SHA-256 authentication data",
	HarvesterFunc: mongodbHarvesterFunc,
}

// mongodbChallengeResponseHarvester is the harvester definition for MongoDB Challenge-Response
var mongodbChallengeResponseHarvester = Harvester{
	Name:          "MongoDB Challenge-Response",
	Description:   "MongoDB wire protocol - captures challenge-response authentication from MongoDB wire protocol",
	HarvesterFunc: mongodbChallengeResponseHarvesterFunc,
}
