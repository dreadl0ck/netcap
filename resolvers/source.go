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
	"os"
	"path/filepath"
)

var (
	quiet          bool
	CurrentConfig  Config
	DataBaseSource string
)

func init() {
	DataBaseSource = os.Getenv("NC_DATABASE_SOURCE")
	if DataBaseSource == "" {
		DataBaseSource = "/usr/local/etc/netcap/dbs"
	}
}

// Init can be used to initialize the resolvers package according to the provided configuration.
func Init(c Config, quietMode bool) {
	quiet = quietMode
	CurrentConfig = c

	if c.ReverseDNS {
		disableReverseDNS = false
	} else {
		var hostsFound bool
		_, err := os.Stat(filepath.Join(DataBaseSource, "hosts"))
		if err == nil {
			hostsFound = true
		}

		if c.LocalDNS || hostsFound {
			InitLocalDNS()
		}
	}

	if c.MACDB {
		initMACResolver()
	}
	if c.Ja3DB {
		initJa3Resolver()
	}
	if c.ServiceDB {
		InitServiceDB()
	}
	if c.GeolocationDB {
		initGeolocationDB()
	}
}
