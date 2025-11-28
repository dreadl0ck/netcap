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

// pop3HarvesterFunc extracts credentials from POP3 (Post Office Protocol v3) traffic
// Supports:
// - USER/PASS plaintext authentication
// - AUTH PLAIN (base64)
// - AUTH LOGIN (base64)
func pop3HarvesterFunc(data []byte, ident string, ts time.Time) *types.Credentials {
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

// pop3Harvester is the harvester definition for POP3
var pop3Harvester = Harvester{
	Name:          "POP3",
	Description:   "Post Office Protocol v3 - captures USER/PASS, AUTH PLAIN, and AUTH LOGIN credentials",
	HarvesterFunc: pop3HarvesterFunc,
}
