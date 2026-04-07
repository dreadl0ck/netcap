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
	"regexp"
	"strings"
	"time"

	"github.com/dreadl0ck/netcap/types"
)

const serviceRedis = "Redis"

var (
	// Redis AUTH command - simple text protocol (must appear at start of a line)
	// Pattern: AUTH password\r\n (case insensitive, anchored to line start)
	reRedisAuth = regexp.MustCompile(`(?im)^AUTH\s+([^\r\n]+)\r?\n`)

	// Redis RESP protocol AUTH (Redis Serialization Protocol)
	// Pattern: *2\r\n$4\r\nAUTH\r\n$<len>\r\n<password>\r\n
	reRedisRESP = regexp.MustCompile(`\*2\r\n\$4\r\n(?i:AUTH)\r\n\$(\d+)\r\n`)

	// Redis 6+ ACL AUTH with username (must appear at start of a line)
	// Pattern: AUTH username password\r\n (space separator only, not \r\n)
	reRedisACL = regexp.MustCompile(`(?im)^AUTH[ \t]+([^\s\r\n]+)[ \t]+([^\r\n]+)\r?\n`)

	// Known false positive password values from protocol keywords
	redisFalsePositivePasswords = []string{"TLS", "SSL", "STARTTLS"}
)

// redisHarvesterFunc extracts credentials from Redis AUTH commands
// Redis uses a simple text protocol and RESP (Redis Serialization Protocol)
// Both plaintext AUTH and RESP format are supported
func redisHarvesterFunc(data []byte, ident string, ts time.Time) *types.Credentials {
	// Redis text protocol requires \r\n line terminators
	if !bytes.Contains(data, []byte("\r\n")) {
		return nil
	}

	// Try RESP protocol format first (most specific)
	matchesRESP := reRedisRESP.FindSubmatch(data)
	if len(matchesRESP) > 1 {
		lengthStr := string(matchesRESP[1])
		lengthPos := bytes.Index(data, matchesRESP[0])
		if lengthPos != -1 {
			passwordStart := lengthPos + len(matchesRESP[0])
			var passwordLen int
			for _, ch := range lengthStr {
				if ch >= '0' && ch <= '9' {
					passwordLen = passwordLen*10 + int(ch-'0')
				}
			}
			if passwordLen > 0 && passwordStart+passwordLen <= len(data) {
				password := string(data[passwordStart : passwordStart+passwordLen])

				return &types.Credentials{
					Timestamp: ts.UnixNano(),
					Service:   serviceRedis,
					Flow:      ident,
					User:      "",
					Password:  password,
					Notes:     "Redis RESP protocol AUTH",
				}
			}
		}
	}

	// Try ACL AUTH (two capture groups - more specific than simple AUTH)
	matchesACL := reRedisACL.FindSubmatch(data)
	if len(matchesACL) > 2 {
		username := string(matchesACL[1])
		password := string(bytes.TrimSpace(matchesACL[2]))

		if !isRedisFalsePositive(password) {
			return &types.Credentials{
				Timestamp: ts.UnixNano(),
				Service:   serviceRedis,
				Flow:      ident,
				User:      username,
				Password:  password,
				Notes:     "Redis 6+ ACL AUTH",
			}
		}
	}

	// Try simple AUTH command (least specific)
	matches := reRedisAuth.FindSubmatch(data)
	if len(matches) > 1 {
		password := string(bytes.TrimSpace(matches[1]))

		if !isRedisFalsePositive(password) {
			return &types.Credentials{
				Timestamp: ts.UnixNano(),
				Service:   serviceRedis,
				Flow:      ident,
				User:      "",
				Password:  password,
				Notes:     "Redis AUTH command",
			}
		}
	}

	return nil
}

// isRedisFalsePositive checks if a password value is a known false positive
func isRedisFalsePositive(password string) bool {
	for _, fp := range redisFalsePositivePasswords {
		if strings.EqualFold(password, fp) {
			return true
		}
	}
	return false
}

// redisHarvester is the harvester definition for Redis
var redisHarvester = Harvester{
	Name:          "Redis",
	Description:   "Redis in-memory database - captures AUTH command passwords and ACL authentication",
	HarvesterFunc: redisHarvesterFunc,
}
