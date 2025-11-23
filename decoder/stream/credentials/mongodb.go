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
func mongodbHarvester(data []byte, ident string, ts time.Time) *types.Credentials {
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
			commaIdx := bytes.IndexByte(data[usernameStart:usernameStart+200], ',')
			if commaIdx != -1 {
				username = string(data[usernameStart : usernameStart+commaIdx])
			}

			// Extract client nonce (not stored, just validated)
			nonceIdx := bytes.Index(data[usernameStart:usernameStart+300], []byte(",r="))
			if nonceIdx != -1 {
				// Client nonce is present, validation successful
				_ = nonceIdx
			}
		}
	}

	// Search for server challenge response
	// Contains: r=serverNonce,s=salt,i=iterations
	serverChallengeIdx := bytes.Index(data, []byte("r="))
	if serverChallengeIdx != -1 && bytes.Contains(data[serverChallengeIdx:serverChallengeIdx+200], []byte(",s=")) {
		// Extract server nonce (includes client nonce + server nonce)
		nonceStart := serverChallengeIdx + 2
		nonceEnd := bytes.IndexByte(data[nonceStart:nonceStart+100], ',')
		if nonceEnd != -1 {
			serverNonce = string(data[nonceStart : nonceStart+nonceEnd])
		}

		// Extract salt
		saltIdx := bytes.Index(data[serverChallengeIdx:serverChallengeIdx+300], []byte(",s="))
		if saltIdx != -1 {
			saltStart := serverChallengeIdx + saltIdx + 3
			saltEnd := bytes.IndexByte(data[saltStart:saltStart+100], ',')
			if saltEnd != -1 {
				salt = string(data[saltStart : saltStart+saltEnd])
			}
		}

		// Extract iterations
		iterIdx := bytes.Index(data[serverChallengeIdx:serverChallengeIdx+400], []byte(",i="))
		if iterIdx != -1 {
			iterStart := serverChallengeIdx + iterIdx + 3
			iterEnd := bytes.IndexAny(data[iterStart:iterStart+20], ",\x00\r\n")
			if iterEnd != -1 {
				iterations = string(data[iterStart : iterStart+iterEnd])
			}
		}
	}

	// Search for client proof
	// Contains: c=biws,r=nonce,p=proof
	proofIdx := bytes.Index(data, []byte(",p="))
	if proofIdx != -1 {
		proofStart := proofIdx + 3
		proofEnd := bytes.IndexAny(data[proofStart:proofStart+100], ",\x00\r\n")
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
func mongodbChallengeResponseHarvester(data []byte, ident string, ts time.Time) *types.Credentials {
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
				return mongodbHarvester(messageData, ident, ts)
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
	parts := strings.Split(message, ",")
	for _, part := range parts {
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
func mongodbPlaintextHarvester(data []byte, ident string, ts time.Time) *types.Credentials {
	// Look for old-style "getnonce" and "authenticate" commands
	// Format: {authenticate: 1, user: "username", nonce: "nonce", key: "key"}

	if !bytes.Contains(data, []byte("authenticate")) {
		return nil
	}

	// Look for user field
	userIdx := bytes.Index(data, []byte("user"))
	if userIdx == -1 {
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

