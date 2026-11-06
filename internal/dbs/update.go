/*
 * NETCAP - Traffic Analysis Framework
 * Copyright (c) Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
 * License: GNU General Public License v3.0
 */

package dbs

// UpdateDBs installs a verified managed release, preserving ambient data only
// in an inactive backup directory.
func UpdateDBs() error {
	return DownloadDBsWithProgress("", false, nil)
}
