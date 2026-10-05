/*
 * NETCAP - Traffic Analysis Framework
 * Copyright (c) Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
 * License: GNU General Public License v3.0
 */

package dbs

import "log"

// UpdateDBs installs the current community archive without replacing user-local GeoLite2 files.
func UpdateDBs() {
	if err := DownloadDBsWithProgress("", true, nil); err != nil {
		log.Printf("database update failed: %v", err)
	}
}
