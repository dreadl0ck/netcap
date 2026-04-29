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
	"sync"
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
					if paramSlice, ok := params.([]any); ok {
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
					if paramSlice, ok := params.([]any); ok {
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

// telnetPatternsOnce guards lazy compilation of telnet credential regexes.
// Harvester configuration is set once via InitializeHarvesters at decoder
// init time and is not hot-reloaded (a capture restart is required to apply
// changes), so caching the cartesian product of login/password patterns is
// safe for the lifetime of the process.
var (
	telnetPatternsOnce sync.Once
	telnetPatterns     []*regexp.Regexp
)

// getTelnetPatterns returns the precompiled telnet credential regexes,
// building them on first call from the configured login/password prompt
// patterns. This avoids recompiling the cartesian product on every stream.
func getTelnetPatterns() []*regexp.Regexp {
	telnetPatternsOnce.Do(func() {
		logins := getTelnetLoginPatterns()
		passes := getTelnetPasswordPatterns()
		telnetPatterns = make([]*regexp.Regexp, 0, len(logins)*len(passes))
		for _, loginPat := range logins {
			for _, passPat := range passes {
				pattern := `(?:.*?)` + regexp.QuoteMeta(loginPat) +
					`(?:.*?)(\w*?)\r\n(?:.*?)\r\n` +
					regexp.QuoteMeta(passPat) + `\s(.*?)\r\n(?:.*?)`
				telnetPatterns = append(telnetPatterns, regexp.MustCompile(pattern))
			}
		}
	})
	return telnetPatterns
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

	// Try configurable patterns (precompiled and cached on first call)
	for _, re := range getTelnetPatterns() {
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

	return nil
}

// telnetHarvester is the harvester definition for Telnet
var telnetHarvester = Harvester{
	Name:          "Telnet",
	Description:   "Telnet protocol - captures plaintext username and password",
	HarvesterFunc: telnetHarvesterFunc,
}
