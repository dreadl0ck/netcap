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
