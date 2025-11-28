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
	"encoding/hex"
	"time"

	"github.com/dreadl0ck/netcap/types"
)

const serviceVNC = "VNC"

// VNC authentication types
const (
	vncAuthNone      = 1
	vncAuthVNC       = 2
	vncAuthRA2       = 5
	vncAuthRA2ne     = 6
	vncAuthTight     = 16
	vncAuthUltra     = 17
	vncAuthTLS       = 18
	vncAuthVeNCrypt  = 19
	vncAuthSASL      = 20
	vncAuthARD       = 30
	vncAuthMSLogonII = 113
)

// vncHarvesterFunc extracts VNC authentication hashes
// VNC uses DES-encrypted challenge-response authentication
// The challenge is 16 bytes, the response is 16 bytes
// The password is DES-encrypted with the challenge as the key
func vncHarvesterFunc(data []byte, ident string, ts time.Time) *types.Credentials {
	if len(data) < 50 {
		return nil
	}

	// REQUIRED: VNC must start with protocol version string "RFB XXX.YYY\n"
	// This prevents false positives on non-VNC traffic (e.g., DNS)
	vncVersionIdx := bytes.Index(data, []byte("RFB "))
	if vncVersionIdx == -1 {
		return nil // Not VNC traffic
	}

	// Verify the version string is properly formatted
	if vncVersionIdx+12 > len(data) {
		return nil
	}

	var (
		challenge []byte
		response  []byte
		version   string
	)

	version = string(data[vncVersionIdx : vncVersionIdx+11])

	// Search for VNC authentication challenge (16 bytes)
	// The challenge comes after the security handshake
	// Look for the characteristic pattern of VNC auth negotiation
	for i := 0; i < len(data)-32; i++ {
		// After version exchange, server sends security types
		// For VNC auth (type 2), server then sends 16-byte challenge

		// Look for authentication type 2 (VNC Authentication)
		// This is typically 1 byte in newer versions or 4 bytes in older versions
		if i+20 > len(data) {
			break
		}

		// Check for VNC auth type (value 2)
		if data[i] == vncAuthVNC {
			// Challenge should follow soon after
			// VNC challenge is exactly 16 bytes
			challengeStart := i + 1

			// Skip any intermediate bytes (protocol variations)
			for j := 0; j < 10 && challengeStart+16 <= len(data); j++ {
				// Try this position as potential challenge start
				possibleChallenge := data[challengeStart : challengeStart+16]

				// Check if this looks like random data (challenge)
				if looksLikeRandomData(possibleChallenge) {
					challenge = make([]byte, 16)
					copy(challenge, possibleChallenge)
					break
				}
				challengeStart++
			}
		}

		// Look for client response (16 bytes after challenge)
		if len(challenge) > 0 && i+16 <= len(data) {
			possibleResponse := data[i : i+16]
			if looksLikeRandomData(possibleResponse) && !bytes.Equal(possibleResponse, challenge) {
				response = make([]byte, 16)
				copy(response, possibleResponse)
				break
			}
		}
	}

	// If we found both challenge and response, create credential entry
	if len(challenge) > 0 && len(response) > 0 {
		// Format for Hashcat mode 20200: $vnc$*challenge*response
		challengeHex := hex.EncodeToString(challenge)
		responseHex := hex.EncodeToString(response)

		hashcatFormat := "$vnc$*" + challengeHex + "*" + responseHex

		notes := "VNC DES challenge-response (Hashcat mode 20200)"
		if version != "" {
			notes += ", Version: " + version
		}

		return &types.Credentials{
			Timestamp: ts.UnixNano(),
			Service:   serviceVNC,
			Flow:      ident,
			User:      "", // VNC doesn't have usernames in basic auth
			Password:  hashcatFormat,
			Notes:     notes,
		}
	}

	return nil
}

// looksLikeRandomData checks if data appears to be random (high entropy)
// Used to identify VNC challenges and responses which should be random
func looksLikeRandomData(data []byte) bool {
	if len(data) == 0 {
		return false
	}

	// Check that it's not all zeros or all the same byte
	firstByte := data[0]
	allSame := true
	zeroCount := 0

	for _, b := range data {
		if b == 0 {
			zeroCount++
		}
		if b != firstByte {
			allSame = false
		}
	}

	// If all bytes are the same, it's not random
	if allSame {
		return false
	}

	// If more than 80% zeros, probably not random challenge/response
	if float64(zeroCount)/float64(len(data)) > 0.8 {
		return false
	}

	// Check for some entropy - at least 30% of bytes should be unique
	uniqueBytes := make(map[byte]bool)
	for _, b := range data {
		uniqueBytes[b] = true
	}

	return float64(len(uniqueBytes))/float64(len(data)) > 0.3
}

// vncARDHarvester extracts Apple Remote Desktop (ARD) credentials
// ARD uses a different authentication mechanism than standard VNC
func vncARDHarvester(data []byte, ident string, ts time.Time) *types.Credentials {
	// Apple Remote Desktop (VNC auth type 30) uses MD5-based authentication
	// Format is different from standard VNC

	if len(data) < 100 {
		return nil
	}

	// Look for ARD auth type (30 = 0x1e)
	ardIdx := bytes.IndexByte(data, vncAuthARD)
	if ardIdx == -1 {
		return nil
	}

	// ARD authentication involves:
	// 1. 16-byte generator value
	// 2. 16-byte key length
	// 3. Prime value
	// 4. Peer's public key
	// This is more complex and requires Diffie-Hellman parsing

	// For now, just detect that ARD authentication is being used
	// Full implementation would require DH parameter extraction

	return &types.Credentials{
		Timestamp: ts.UnixNano(),
		Service:   serviceVNC,
		Flow:      ident,
		User:      "",
		Password:  "",
		Notes:     "Apple Remote Desktop (ARD) authentication detected - complex DH-based auth",
	}
}

// vncMSLogonHarvester extracts Microsoft VNC Logon credentials
// UltraVNC MS Logon uses Windows credentials
func vncMSLogonHarvester(data []byte, ident string, ts time.Time) *types.Credentials {
	// MS Logon II (auth type 113) uses Windows domain credentials
	// This might contain NTLM authentication
	// Leverage the existing NTLMSSP harvester if NTLM is detected

	if bytes.Contains(data, []byte{vncAuthMSLogonII}) {
		// Try to extract NTLM from the session
		ntlmCreds := ntlmsspHarvesterFunc(data, ident, ts)
		if ntlmCreds != nil {
			ntlmCreds.Service = "VNC MS Logon II"
			ntlmCreds.Notes = "VNC with Microsoft Logon (NTLM)"
			return ntlmCreds
		}
	}

	return nil
}

// vncHarvester is the harvester definition for VNC
var vncHarvester = Harvester{
	Name:          "VNC",
	Description:   "Virtual Network Computing - captures DES challenge-response authentication (Hashcat mode 20200)",
	HarvesterFunc: vncHarvesterFunc,
}
