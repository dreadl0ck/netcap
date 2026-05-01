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
	"encoding/hex"
	"fmt"

	"github.com/jcmturner/gokrb5/v8/types"
)

// Kerberos encryption type constants
const (
	EtypeAES128CTS = 17 // AES128-CTS-HMAC-SHA1-96
	EtypeAES256CTS = 18 // AES256-CTS-HMAC-SHA1-96
	EtypeRC4HMAC   = 23 // RC4-HMAC
)

// isSupportedEtype checks if the encryption type is one we can extract for cracking
// We support etypes 17 (AES128), 18 (AES256), and 23 (RC4-HMAC)
func isSupportedEtype(etype int32) bool {
	return etype == EtypeAES128CTS || etype == EtypeAES256CTS || etype == EtypeRC4HMAC
}

// getHashcatMode returns the appropriate Hashcat mode for the given message type and etype
func getHashcatMode(msgType string, etype int32) int {
	switch msgType {
	case "AS-REP":
		switch etype {
		case EtypeRC4HMAC:
			return 18200 // Kerberos 5, etype 23, AS-REP
		case EtypeAES128CTS:
			return 19600 // Kerberos 5, etype 17, Pre-Auth
		case EtypeAES256CTS:
			return 19700 // Kerberos 5, etype 18, Pre-Auth
		}
	case "TGS-REP":
		switch etype {
		case EtypeRC4HMAC:
			return 13100 // Kerberos 5, etype 23, TGS-REP
		case EtypeAES128CTS:
			return 19600 // Kerberos 5, etype 17
		case EtypeAES256CTS:
			return 19700 // Kerberos 5, etype 18
		}
	}
	return 0
}

// extractPrincipalName extracts the username from a Kerberos PrincipalName
// Returns empty string if no name strings are present
func extractPrincipalName(pname types.PrincipalName) string {
	if len(pname.NameString) > 0 {
		return pname.NameString[0]
	}
	return ""
}

// handleKerberosRecordMark strips the TCP record mark if present
// TCP Kerberos messages have a 4-byte big-endian length prefix
// UDP Kerberos messages have no such prefix
// This function detects and strips the TCP record mark automatically
func handleKerberosRecordMark(data []byte) []byte {
	// Check if this looks like TCP format (4-byte length prefix)
	// TCP record mark starts with 0x00 0x00 for typical message sizes
	if len(data) > 4 && data[0] == 0x00 && data[1] == 0x00 {
		// Skip the 4-byte record mark
		return data[4:]
	}
	// Otherwise assume UDP (no record mark)
	return data
}

// formatASRepForHashcat formats AS-REP data for Hashcat cracking
// Format: $krb5asrep$<etype>$user@realm:hash
func formatASRepForHashcat(username, realm string, cipher []byte, etype int32) string {
	hash := hex.EncodeToString(cipher)

	switch etype {
	case EtypeRC4HMAC:
		// Hashcat mode 18200: $krb5asrep$23$user@realm:hash
		return fmt.Sprintf("$krb5asrep$23$%s@%s:%s", username, realm, hash)

	case EtypeAES128CTS:
		// Hashcat mode 19600: $krb5asrep$17$user@realm:hash
		return fmt.Sprintf("$krb5asrep$17$%s@%s:%s", username, realm, hash)

	case EtypeAES256CTS:
		// Hashcat mode 19700: $krb5asrep$18$user@realm:hash
		return fmt.Sprintf("$krb5asrep$18$%s@%s:%s", username, realm, hash)
	}

	return ""
}

// formatTGSRepForHashcat formats TGS-REP data for Hashcat cracking (Kerberoasting)
// Format: $krb5tgs$<etype>$*user$realm$service*$hash
func formatTGSRepForHashcat(username, realm, service string, cipher []byte, etype int32) string {
	hash := hex.EncodeToString(cipher)

	switch etype {
	case EtypeRC4HMAC:
		// Hashcat mode 13100: $krb5tgs$23$*user$realm$service*$hash
		return fmt.Sprintf("$krb5tgs$23$*%s$%s$%s*$%s", username, realm, service, hash)

	case EtypeAES128CTS:
		// Hashcat mode 19600: $krb5tgs$17$*user$realm$service*$hash
		return fmt.Sprintf("$krb5tgs$17$*%s$%s$%s*$%s", username, realm, service, hash)

	case EtypeAES256CTS:
		// Hashcat mode 19700: $krb5tgs$18$*user$realm$service*$hash
		return fmt.Sprintf("$krb5tgs$18$*%s$%s$%s*$%s", username, realm, service, hash)
	}

	return ""
}
