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
	"encoding/base64"
	"regexp"
	"strings"
	"time"

	"github.com/dreadl0ck/netcap/types"
)

const (
	servicePOP3          = "POP3"
	servicePOP3AuthPlain = "POP3 Auth Plain"
	servicePOP3AuthLogin = "POP3 Auth Login"
)

var (
	// POP3 USER/PASS authentication
	// Pattern: USER username\r\n...PASS password\r\n
	rePOP3 = regexp.MustCompile(`USER\s+(.*?)\r\n.*?PASS\s+(.*?)\r\n`)

	// POP3 AUTH PLAIN (base64 encoded username\0username\0password)
	rePOP3AuthPlain = regexp.MustCompile(`AUTH PLAIN\r\n.*?\r\n(.*?)\r\n`)

	// POP3 AUTH LOGIN (base64 encoded username and password in separate steps)
	// Pattern: AUTH LOGIN\r\n+OK\r\nbase64(username)\r\n+OK\r\nbase64(password)\r\n
	rePOP3AuthLogin = regexp.MustCompile(`AUTH LOGIN\r\n\+OK.*?\r\n(.*?)\r\n\+OK.*?\r\n(.*?)\r\n`)
)

// pop3Harvester extracts credentials from POP3 (Post Office Protocol v3) traffic
// Supports:
// - USER/PASS plaintext authentication
// - AUTH PLAIN (base64)
// - AUTH LOGIN (base64)
func pop3Harvester(data []byte, ident string, ts time.Time) *types.Credentials {
	// Try USER/PASS first (most common)
	matches := rePOP3.FindSubmatch(data)
	if len(matches) > 2 {
		return &types.Credentials{
			Timestamp: ts.UnixNano(),
			Service:   servicePOP3,
			Flow:      ident,
			User:      string(matches[1]),
			Password:  string(matches[2]),
		}
	}

	// Try AUTH PLAIN
	matchesPlain := rePOP3AuthPlain.FindSubmatch(data)
	if len(matchesPlain) > 1 {
		decoded, err := base64.StdEncoding.DecodeString(string(matchesPlain[1]))
		if err == nil {
			// AUTH PLAIN format: [authzid]\0username\0password
			parts := strings.Split(string(decoded), "\x00")
			if len(parts) >= 3 {
				// Format: \0username\0password
				return &types.Credentials{
					Timestamp: ts.UnixNano(),
					Service:   servicePOP3AuthPlain,
					Flow:      ident,
					User:      parts[1],
					Password:  parts[2],
				}
			} else if len(parts) == 2 {
				// Format: username\0password
				return &types.Credentials{
					Timestamp: ts.UnixNano(),
					Service:   servicePOP3AuthPlain,
					Flow:      ident,
					User:      parts[0],
					Password:  parts[1],
				}
			}
		}
	}

	// Try AUTH LOGIN
	matchesLogin := rePOP3AuthLogin.FindSubmatch(data)
	if len(matchesLogin) > 2 {
		username, err1 := base64.StdEncoding.DecodeString(string(matchesLogin[1]))
		password, err2 := base64.StdEncoding.DecodeString(string(matchesLogin[2]))
		if err1 == nil && err2 == nil {
			return &types.Credentials{
				Timestamp: ts.UnixNano(),
				Service:   servicePOP3AuthLogin,
				Flow:      ident,
				User:      string(username),
				Password:  string(password),
			}
		}
	}

	return nil
}

