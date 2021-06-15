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

var dnsWhitelist = make(map[string]struct{})

// InitDNSWhitelist initializes the domain whitelist.
func InitDNSWhitelist() {
	var hosts int

	data, err := ioutil.ReadFile(filepath.Join(DataBaseFolderPath, "domain-whitelist.csv"))
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
			dnsWhitelist[parts[1]] = struct{}{}
		}

		hosts++
	}

	if !quiet {
		resolverLog.Info("loaded whitelisted DNS hosts", zap.Int("numHosts", hosts))
	}
}

func getHost(domain string) string {
	parts := strings.Split(domain, ".")
	if len(parts) < 3 {
		return domain
	}
	return parts[len(parts)-2] + "." + parts[len(parts)-1]
}

// IsWhitelistedDomain checks whether a given domain is whitelisted
// must be called after calling InitDNSWhitelist().
func IsWhitelistedDomain(domain string) bool {
	if _, ok := dnsWhitelist[getHost(domain)]; ok {
		// log.Println(domain, "is whitelisted")
		return true
	}
	// log.Println(domain, "is NOT whitelisted")
	return false
}
