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

package resolvers

import (
	"bytes"
	"io/ioutil"
	"log"
	"path/filepath"
	"strings"

	"go.uber.org/zap"
)

var ipWhitelist = make(map[string]struct{})

// initIPWhitelist initializes the ip address whitelist
// TODO: integrate into DeviceProfiles audit record.
func initIPWhitelist() {
	var hosts int

	data, err := ioutil.ReadFile(filepath.Join(DataBaseFolderPath, "ip-whitelist.csv"))
	if err != nil {
		log.Fatal(err)
	}

	for _, line := range bytes.Split(data, []byte{'\n'}) {
		if len(line) == 0 {
			continue
		}

		// ignore comments
		if string(line[0]) == "#" || string(line[0]) == "*" {
			continue
		}

		parts := strings.Split(string(line), ",")
		if len(parts) == 2 {
			ipWhitelist[parts[1]] = struct{}{}
		}

		hosts++
	}

	if !quiet {
		resolverLog.Info("loaded whitelisted IP hosts", zap.Int("numHosts", hosts))
	}
}

// isWhitelistedIP checks whether a given ip address is whitelisted.
func isWhitelistedIP(ip string) bool {
	if _, ok := ipWhitelist[ip]; ok {
		// log.Println(domain, "is whitelisted")
		return true
	}
	// log.Println(ip, "is NOT whitelisted")
	return false
}
