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

	"github.com/dreadl0ck/netcap/env"
)

var (
	quiet bool

	// CurrentConfig holds the current configuration.
	CurrentConfig Config

	// ConfigRootPath points to the path for storing the netcap configuration and databases.
	// usually: /usr/local/etc/netcap
	ConfigRootPath string

	// DataBaseFolderPath points to the 'dbs' folder for storing the netcap databases.
	// usually: /usr/local/etc/netcap/dbs
	DataBaseFolderPath string

	// DataBaseBuildPath points to the build folder for db generation artifacts,
	// that are not tracked in version control.
	// usually: /usr/local/etc/netcap/build
	DataBaseBuildPath string
)

const (
	dataBaseFolderName = "dbs"
	buildFolderName    = "build"
)

func init() {
	ConfigRootPath = os.Getenv(env.ConfigRoot)
	if ConfigRootPath == "" {
		ConfigRootPath = filepath.Join("/usr", "local", "etc", "netcap")
	}
	DataBaseFolderPath = filepath.Join(ConfigRootPath, dataBaseFolderName)
	DataBaseBuildPath = filepath.Join(ConfigRootPath, buildFolderName)
}

// Init can be used to initialize the resolvers package according to the provided configuration.
func Init(c Config, quietMode bool) {
	quiet = quietMode
	CurrentConfig = c

	if c.ReverseDNS {
		disableReverseDNS = false
	} else {
		var hostsFound bool
		_, err := os.Stat(filepath.Join(DataBaseFolderPath, "hosts"))
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
