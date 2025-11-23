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
	"encoding/hex"
	"time"

	"github.com/dreadl0ck/netcap/types"
)

// Kerberos constants
const (
	kerberosPort = 88
	asMsgType    = 0x0a // AS-REQ message type
	rc4EncType   = 0x17 // etype 23 (RC4-HMAC-MD5)
)

// PA-DATA signatures (pre-authentication data)
var (
	paDataSig1 = []byte{0xa2, 0x36, 0x04, 0x34} // Hash length = 54 (0x36)
	paDataSig2 = []byte{0xa2, 0x35, 0x04, 0x33} // Hash length = 53 (0x35)
)

// kerberosASReqHarvesterFunc extracts AS-REQ pre-authentication hashes from UDP data
// This extracts hashes that can be cracked offline with Hashcat mode 7500
// Note: This is designed to work with UDP packets on port 88
func kerberosASReqHarvesterFunc(data []byte, ident string, ts time.Time) *types.Credentials {
	if len(data) < 150 {
		return nil
	}

	// Check for AS-REQ message type (0x0a at offset 17) and RC4 encryption (0x17 at offset 39)
	if len(data) > 39 && data[17] == asMsgType && data[39] == rc4EncType {
		// Look for PA-DATA signature starting at offset 40
		if len(data) < 44 {
			return nil
		}

		sigPart := data[40:44]

		var paddingLen, hashOffset, userNameOffset, hashItemLen int

		// Check if we have a known PA-DATA signature
		if bytes.Equal(sigPart, paDataSig1) || bytes.Equal(sigPart, paDataSig2) {
			hashItemLen = int(data[41])

			if hashItemLen == 53 {
				paddingLen = 1
				hashOffset = 44
				userNameOffset = 144
			} else if hashItemLen == 54 {
				paddingLen = 0
				hashOffset = 44
				userNameOffset = 144
			} else {
				// Alternative structure
				if len(data) < 49 {
					return nil
				}
				hashItemLen = int(data[48])
				hashOffset = 49
				userNameOffset = hashItemLen + 97
			}

			hashLen := 52 - paddingLen
			if hashOffset+hashLen > len(data) {
				return nil
			}

			hash := data[hashOffset : hashOffset+hashLen]

			// Switch byte order: last 36 bytes first, then first 16 bytes
			// This is specific to Kerberos AS-REQ hash format
			switchedHash := make([]byte, hashLen)
			if len(hash) >= 52 {
				copy(switchedHash[0:36], hash[16:52])
				copy(switchedHash[36:52], hash[0:16])
			} else {
				copy(switchedHash, hash)
			}

			// Extract username and domain
			username := extractKerberosItem(data, userNameOffset-paddingLen)
			if username == "" {
				return nil
			}

			domain := extractKerberosItem(data, userNameOffset+len(username)-paddingLen+4)

			// Format for Hashcat mode 7500: $krb5pa$23$user$realm$salt$hash
			hashcatFormat := "$krb5pa$23$" + username + "$" + domain + "$$" + hex.EncodeToString(switchedHash)

			return &types.Credentials{
				Timestamp: ts.UnixNano(),
				Service:   "Kerberos",
				Flow:      ident,
				User:      username,
				Password:  hashcatFormat, // Store Hashcat format in password field
				Notes:     "HashType: Kerberos V5 AS-REQ Pre-Auth etype 23, Domain: " + domain,
			}
		}
	}

	return nil
}

// extractKerberosItem extracts a length-prefixed item from Kerberos message
// The format is: [length:1][data:length]
func extractKerberosItem(data []byte, offset int) string {
	if offset >= len(data) {
		return ""
	}

	itemLen := int(data[offset])
	if itemLen == 0 || offset+1+itemLen > len(data) {
		return ""
	}

	return string(data[offset+1 : offset+1+itemLen])
}

// kerberosASReqHarvester is the harvester definition for Kerberos AS-REQ
var kerberosASReqHarvester = Harvester{
	Name:          "Kerberos AS-REQ",
	Description:   "Kerberos Authentication Service Request - captures pre-authentication data for offline password cracking",
	HarvesterFunc: kerberosASReqHarvesterFunc,
}

