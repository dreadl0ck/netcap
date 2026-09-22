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
	"encoding/binary"
	"encoding/hex"
	"time"

	"github.com/dreadl0ck/netcap/types"
)

// NTLMSSP Message Types
const (
	ntlmsspNegotiate = 0x01
	ntlmsspChallenge = 0x02
	ntlmsspAuth      = 0x03
)

// NTLMSSP Signature: "NTLMSSP\x00"
var ntlmsspSignature = []byte{0x4e, 0x54, 0x4c, 0x4d, 0x53, 0x53, 0x50, 0x00}

type ntlmState int

const (
	ntlmStateWaitChallenge ntlmState = iota
	ntlmStateWaitResponse
)

// ntlmsspHarvesterFunc extracts NTLM credentials from a TCP session
// It implements a state machine to match challenge-response pairs
// Works with SMB, HTTP, IMAP, SMTP, etc.
func ntlmsspHarvesterFunc(data []byte, ident string, ts time.Time) *types.Secret {
	var (
		challenge   []byte
		username    string
		domain      string
		workstation string
		lmHash      string
		ntHash      string
		state       = ntlmStateWaitChallenge
	)

	// Search for NTLMSSP messages in the session data
	pos := 0
	for pos < len(data) {
		// Look for NTLMSSP signature
		idx := bytes.Index(data[pos:], ntlmsspSignature)
		if idx == -1 {
			break
		}

		pos += idx
		if pos+12 > len(data) {
			break
		}

		// Check message type (little endian uint32 at offset 8)
		msgType := binary.LittleEndian.Uint32(data[pos+8 : pos+12])

		switch msgType {
		case ntlmsspChallenge:
			if state == ntlmStateWaitChallenge {
				// Extract 8-byte challenge at offset 24
				if pos+32 <= len(data) {
					challenge = make([]byte, 8)
					copy(challenge, data[pos+24:pos+32])
					state = ntlmStateWaitResponse
				}
			}

		case ntlmsspAuth:
			if state == ntlmStateWaitResponse && len(challenge) > 0 {
				// Extract all fields using offset/length pairs
				lmHash, ntHash, domain, username, workstation = extractNTLMAuthFields(data[pos:])

				// Determine if NTLMv1 or NTLMv2
				var hashType string
				var finalHash string

				// NTLMv1 has exactly 24 bytes (48 hex chars)
				// NTLMv2 has more than 24 bytes
				ntHashBytes := len(ntHash) / 2
				if ntHashBytes == 24 {
					hashType = "NTLMv1"
					finalHash = lmHash
				} else if ntHashBytes > 24 {
					hashType = "NTLMv2"
					finalHash = ntHash
				}

				if finalHash != "" {
					hashcatFormat := formatNTLMForHashcat(username, domain, challenge, lmHash, ntHash, hashType)

					return &types.Secret{
						Timestamp: ts.UnixNano(),
						Service:   "NTLMSSP",
						Flow:      ident,
						User:      username,
						Password:  hashcatFormat, // Store in password field for now
						Notes:     "HashType: " + hashType + ", Domain: " + domain + ", Workstation: " + workstation + ", Challenge: " + hex.EncodeToString(challenge),
					}
				}
			}
		}

		pos++
	}

	return nil
}

// extractNTLMAuthFields extracts fields from NTLMSSP AUTH message (Type 3)
// Fields are encoded as [length:2][maxlen:2][offset:4]
func extractNTLMAuthFields(data []byte) (lmHash, ntHash, domain, username, workstation string) {
	if len(data) < 64 {
		return
	}

	// LM Response: offset 12 (in Type 3 message structure)
	// The structure is: length(2) + max_length(2) + offset(4)
	if len(data) >= 20 {
		lmLen := int(binary.LittleEndian.Uint16(data[12:14]))
		lmOff := int(binary.LittleEndian.Uint32(data[16:20]))
		if lmOff > 0 && lmOff+lmLen <= len(data) {
			lmHash = hex.EncodeToString(data[lmOff : lmOff+lmLen])
		}
	}

	// NTLM Response: offset 20
	if len(data) >= 28 {
		ntLen := int(binary.LittleEndian.Uint16(data[20:22]))
		ntOff := int(binary.LittleEndian.Uint32(data[24:28]))
		if ntOff > 0 && ntOff+ntLen <= len(data) {
			ntHash = hex.EncodeToString(data[ntOff : ntOff+ntLen])
		}
	}

	// Domain: offset 28
	if len(data) >= 36 {
		domLen := int(binary.LittleEndian.Uint16(data[28:30]))
		domOff := int(binary.LittleEndian.Uint32(data[32:36]))
		if domOff > 0 && domOff+domLen <= len(data) {
			domain = decodeUnicode(data[domOff : domOff+domLen])
		}
	}

	// Username: offset 36
	if len(data) >= 44 {
		userLen := int(binary.LittleEndian.Uint16(data[36:38]))
		userOff := int(binary.LittleEndian.Uint32(data[40:44]))
		if userOff > 0 && userOff+userLen <= len(data) {
			username = decodeUnicode(data[userOff : userOff+userLen])
		}
	}

	// Workstation: offset 44
	if len(data) >= 52 {
		wsLen := int(binary.LittleEndian.Uint16(data[44:46]))
		wsOff := int(binary.LittleEndian.Uint32(data[48:52]))
		if wsOff > 0 && wsOff+wsLen <= len(data) {
			workstation = decodeUnicode(data[wsOff : wsOff+wsLen])
		}
	}

	return
}

// decodeUnicode converts UTF-16LE to string
func decodeUnicode(data []byte) string {
	if len(data) == 0 {
		return ""
	}

	var result []rune
	for i := 0; i < len(data)-1; i += 2 {
		r := rune(binary.LittleEndian.Uint16(data[i : i+2]))
		if r != 0 {
			result = append(result, r)
		}
	}
	return string(result)
}

// formatNTLMForHashcat formats NTLM credentials for Hashcat
// NTLMv1 (mode 5500): username::domain:LM:NT:challenge
// NTLMv2 (mode 5600): username::domain:challenge:NT:blob
func formatNTLMForHashcat(username, domain string, challenge []byte, lmHash, ntHash, hashType string) string {
	chalStr := hex.EncodeToString(challenge)

	if hashType == "NTLMv1" {
		// Mode 5500: username::domain:LM:NT:challenge
		return username + "::" + domain + ":" + lmHash + ":" + ntHash + ":" + chalStr
	} else if hashType == "NTLMv2" {
		// Mode 5600: username::domain:challenge:NT[:blob]
		// For NTLMv2, the ntHash contains both the NTProofStr and the blob
		// We need to split it: first 16 bytes (32 hex chars) is NTProofStr, rest is blob
		if len(ntHash) > 32 {
			ntProof := ntHash[:32]
			blob := ntHash[32:]
			return username + "::" + domain + ":" + chalStr + ":" + ntProof + ":" + blob
		}
	}

	return ""
}

// ntlmsspHarvester is the harvester definition for NTLMSSP
var ntlmsspHarvester = Harvester{
	Name:          "NTLMSSP",
	Description:   "NT LAN Manager Security Support Provider - captures NTLM challenge-response hashes for offline cracking",
	HarvesterFunc: ntlmsspHarvesterFunc,
}
