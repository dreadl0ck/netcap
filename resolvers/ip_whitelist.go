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

	resolverLog.Info("loaded whitelisted IP hosts", zap.Int("numHosts", hosts))
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
