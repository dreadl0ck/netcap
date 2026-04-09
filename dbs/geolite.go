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

package dbs

import (
	"log"
	"os"
	"path/filepath"

	"github.com/dreadl0ck/netcap/internal/env"
	"github.com/dreadl0ck/netcap/resolvers"
)

// DownloadGeoLite will download the GeoLite Database if the API key is set in the environment
func DownloadGeoLite() {

	apiKey := os.Getenv(env.GeoLiteAPIKey)
	if apiKey == "" {
		log.Fatal("please set the " + env.GeoLiteAPIKey + " env variable")
	}

	// check if database root path exists already
	if _, err := os.Stat(resolvers.ConfigRootPath); err != nil {
		log.Fatal("database root path: ", resolvers.DataBaseFolderPath, " does not exist")
	}

	for _, s := range []*datasource{
		makeSource("https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-ASN&license_key="+apiKey+"&suffix=tar.gz", "GeoLite2-ASN.mmdb", untarAndMoveGeoliteToDbs),
		makeSource("https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-Country&license_key="+apiKey+"&suffix=tar.gz", "GeoLite2-Country.mmdb", untarAndMoveGeoliteToDbs),
		makeSource("https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-City&license_key="+apiKey+"&suffix=tar.gz", "GeoLite2-City.mmdb", untarAndMoveGeoliteToDbs),
	} {

		var (
			out = filepath.Join(resolvers.ConfigRootPath, s.name)
		)

		// fetch via HTTP GET from single remote source if provided
		// if multiple sources need to be fetched, the logic can be implemented in the hook
		fetchResource(s, out)

		// run hook
		if s.hook != nil {
			err := s.hook(out, s, resolvers.ConfigRootPath)
			if err != nil {
				log.Println("hook for", s.name, "failed with error", err)
			}
		}
	}
}
