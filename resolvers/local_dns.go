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
	"net"
	"path/filepath"
	"strings"

	"go.uber.org/zap"
)

var localDNSNamesDB = make(map[string]string)

// InitLocalDNS initializes reverse dns resolution via local hosts mapping.
func InitLocalDNS() {
	var hosts int

	data, err := ioutil.ReadFile(filepath.Join(DataBaseFolderPath, "hosts"))
	if err != nil {
		log.Println(err)

		return
	}

	for _, line := range bytes.Split(data, []byte{'\n'}) {
		if len(line) == 0 {
			continue
		}

		// ignore comments
		if string(line[0]) == "#" {
			continue
		}

		parts := strings.Split(string(line), "\t")
		if len(parts) == 2 {
			localDNSNamesDB[parts[0]] = parts[1]
		}

		hosts++
	}

	resolverLog.Info("loaded local DNS hosts",
		zap.Int("numHosts", hosts),
	)
}

// LookupDNSNameLocal retrieves the DNS names associated with an IP addr.
func LookupDNSNameLocal(ip string) string {
	// check if ip is valid
	i := net.ParseIP(ip)
	if i == nil {
		return ""
	}

	// lookup
	if res, ok := localDNSNamesDB[ip]; ok {
		return res
	}

	return ""
}
