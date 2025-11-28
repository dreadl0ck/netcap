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
	"os"
	"path/filepath"

	"github.com/dreadl0ck/netcap/internal/env"
	"github.com/dreadl0ck/netcap/internal/performance"
	"go.uber.org/zap"
)

var (
	quiet bool

	// CurrentConfig holds the current configuration.
	CurrentConfig Config

	// perfTracker holds the performance tracker for measuring resolver operations
	perfTracker *performance.Tracker

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
		// Use XDG-compliant user config directory: ~/.config/netcap
		home, err := os.UserHomeDir()
		if err != nil {
			// Fallback to /usr/local/etc/netcap if home directory cannot be determined
			ConfigRootPath = filepath.Join("/usr", "local", "etc", "netcap")
		} else {
			ConfigRootPath = filepath.Join(home, ".config", "netcap")
		}
	}
	DataBaseFolderPath = filepath.Join(ConfigRootPath, dataBaseFolderName)
	DataBaseBuildPath = filepath.Join(ConfigRootPath, buildFolderName)
}

// SetPerfTracker sets the performance tracker for resolver operations
func SetPerfTracker(pt *performance.Tracker) {
	perfTracker = pt
}

// Init can be used to initialize the resolvers package according to the provided configuration.
func Init(c Config, quietMode bool) {
	quiet = quietMode
	CurrentConfig = c

	// Log database path (logger is set before Init is called)
	resolverLog.Info("loading netcap databases",
		zap.String("path", DataBaseFolderPath),
	)

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
	if c.DHCPDB {
		InitDHCPFingerprintDB()
	}

	// Log completion
	resolverLog.Info("successfully loaded netcap databases")
}
