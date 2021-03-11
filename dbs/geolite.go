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

package dbs

import (
	"github.com/dreadl0ck/netcap/env"
	"github.com/dreadl0ck/netcap/resolvers"
	"log"
	"os"
	"path/filepath"
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
