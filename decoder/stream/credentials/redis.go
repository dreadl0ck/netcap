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
	"regexp"
	"time"

	"github.com/dreadl0ck/netcap/types"
)

const serviceRedis = "Redis"

var (
	// Redis AUTH command - simple text protocol
	// Pattern: AUTH password\r\n or auth password\r\n (case insensitive)
	reRedisAuth = regexp.MustCompile(`(?i)AUTH\s+([^\r\n]+)\r?\n`)

	// Redis RESP protocol AUTH (Redis Serialization Protocol)
	// Pattern: *2\r\n$4\r\nAUTH\r\n$<len>\r\n<password>\r\n
	reRedisRESP = regexp.MustCompile(`\*2\r\n\$4\r\n(?i:AUTH)\r\n\$(\d+)\r\n`)
)

// redisHarvester extracts credentials from Redis AUTH commands
// Redis uses a simple text protocol and RESP (Redis Serialization Protocol)
// Both plaintext AUTH and RESP format are supported
func redisHarvester(data []byte, ident string, ts time.Time) *types.Credentials {
	// Try simple AUTH command first
	matches := reRedisAuth.FindSubmatch(data)
	if len(matches) > 1 {
		password := string(matches[1])
		// Remove any trailing whitespace or newlines
		password = string(bytes.TrimSpace([]byte(password)))
		
		return &types.Credentials{
			Timestamp: ts.UnixNano(),
			Service:   serviceRedis,
			Flow:      ident,
			User:      "", // Redis doesn't have usernames in basic AUTH (only password)
			Password:  string(password),
			Notes:     "Redis AUTH command",
		}
	}

	// Try RESP protocol format
	matchesRESP := reRedisRESP.FindSubmatch(data)
	if len(matchesRESP) > 1 {
		// Extract the length of the password
		lengthStr := string(matchesRESP[1])
		// Find the position after the length line
		lengthPos := bytes.Index(data, matchesRESP[0])
		if lengthPos != -1 {
			// Calculate where the password starts
			passwordStart := lengthPos + len(matchesRESP[0])
			// Parse the length
			var passwordLen int
			if regexp.MustCompile(`\d+`).MatchString(lengthStr) {
				// Simple conversion
				for _, ch := range lengthStr {
					if ch >= '0' && ch <= '9' {
						passwordLen = passwordLen*10 + int(ch-'0')
					}
				}
				
				// Extract password if we have enough data
				if passwordStart+passwordLen <= len(data) {
					password := string(data[passwordStart : passwordStart+passwordLen])
					
					return &types.Credentials{
						Timestamp: ts.UnixNano(),
						Service:   serviceRedis,
						Flow:      ident,
						User:      "", // Redis doesn't have usernames in basic AUTH
						Password:  password,
						Notes:     "Redis RESP protocol AUTH",
					}
				}
			}
		}
	}

	// Also check for Redis 6+ ACL AUTH with username
	// Pattern: AUTH username password or AUTH default password
	reRedisACL := regexp.MustCompile(`(?i)AUTH\s+([^\s\r\n]+)\s+([^\r\n]+)\r?\n`)
	matchesACL := reRedisACL.FindSubmatch(data)
	if len(matchesACL) > 2 {
		username := string(matchesACL[1])
		password := bytes.TrimSpace(matchesACL[2])
		
		return &types.Credentials{
			Timestamp: ts.UnixNano(),
			Service:   serviceRedis,
			Flow:      ident,
			User:      username,
			Password:  string(password),
			Notes:     "Redis 6+ ACL AUTH",
		}
	}

	return nil
}

