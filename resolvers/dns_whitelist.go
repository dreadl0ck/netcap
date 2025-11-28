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

	resolverLog.Info("loaded whitelisted DNS hosts", zap.Int("numHosts", hosts))
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
