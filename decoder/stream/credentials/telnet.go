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
	"regexp"
	"time"

	"github.com/dreadl0ck/netcap/types"
)

const serviceTelnet = "Telnet"

var reTelnet = regexp.MustCompile(`(?:.*?)login:(?:.*?)(\w*?)\r\n(?:.*?)\r\nPassword:\s(.*?)\r\n(?:.*?)`)

// getTelnetLoginPatterns returns configured login prompt patterns or defaults
func getTelnetLoginPatterns() []string {
	if harvesterConfig != nil {
		for _, hConfig := range harvesterConfig.Harvesters {
			if hConfig.Name == "Telnet" && hConfig.Parameters != nil {
				if params, ok := hConfig.Parameters["login_patterns"]; ok {
					if paramSlice, ok := params.([]interface{}); ok {
						result := make([]string, 0, len(paramSlice))
						for _, p := range paramSlice {
							if strParam, ok := p.(string); ok {
								result = append(result, strParam)
							}
						}
						if len(result) > 0 {
							return result
						}
					}
				}
			}
		}
	}
	return []string{"login:", "username:", "Username:", "login as:", "Login:"}
}

// getTelnetPasswordPatterns returns configured password prompt patterns or defaults
func getTelnetPasswordPatterns() []string {
	if harvesterConfig != nil {
		for _, hConfig := range harvesterConfig.Harvesters {
			if hConfig.Name == "Telnet" && hConfig.Parameters != nil {
				if params, ok := hConfig.Parameters["password_patterns"]; ok {
					if paramSlice, ok := params.([]interface{}); ok {
						result := make([]string, 0, len(paramSlice))
						for _, p := range paramSlice {
							if strParam, ok := p.(string); ok {
								result = append(result, strParam)
							}
						}
						if len(result) > 0 {
							return result
						}
					}
				}
			}
		}
	}
	return []string{"Password:", "password:", "Pass:", "passwd:"}
}

// telnetHarvesterFunc is the harvester function for telnet traffic.
func telnetHarvesterFunc(data []byte, ident string, ts time.Time) *types.Credentials {
	// Try default pattern first for backwards compatibility
	matches := reTelnet.FindSubmatch(data)
	if len(matches) > 1 {
		var username string
		for i, letter := range string(matches[1]) {
			if i%2 == 0 {
				username = username + string(letter)
			}
		}
		return &types.Credentials{
			Timestamp: ts.UnixNano(),
			Service:   serviceTelnet,
			Flow:      ident,
			User:      username,
			Password:  string(matches[2]),
		}
	}

	// Try configurable patterns
	loginPatterns := getTelnetLoginPatterns()
	passwordPatterns := getTelnetPasswordPatterns()

	for _, loginPat := range loginPatterns {
		for _, passPat := range passwordPatterns {
			// Build dynamic regex pattern
			pattern := `(?:.*?)` + regexp.QuoteMeta(loginPat) + `(?:.*?)(\w*?)\r\n(?:.*?)\r\n` + regexp.QuoteMeta(passPat) + `\s(.*?)\r\n(?:.*?)`
			re := regexp.MustCompile(pattern)
			matches := re.FindSubmatch(data)
			if len(matches) > 1 {
				var username string
				for i, letter := range string(matches[1]) {
					if i%2 == 0 {
						username = username + string(letter)
					}
				}
				if len(username) > 0 || len(matches[2]) > 0 {
					return &types.Credentials{
						Timestamp: ts.UnixNano(),
						Service:   serviceTelnet,
						Flow:      ident,
						User:      username,
						Password:  string(matches[2]),
					}
				}
			}
		}
	}

	return nil
}

// telnetHarvester is the harvester definition for Telnet
var telnetHarvester = Harvester{
	Name:          "Telnet",
	Description:   "Telnet protocol - captures plaintext username and password",
	HarvesterFunc: telnetHarvesterFunc,
}
