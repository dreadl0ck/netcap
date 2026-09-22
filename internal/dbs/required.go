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
	"os"
	"path/filepath"

	"github.com/dreadl0ck/netcap/internal/resolvers"
)

// RequiredDB describes a database file that a capture run depends on.
//
// "Required" means the analysis aborts without it, not that it is merely
// useful. The registry exists because that knowledge used to live only in the
// resolver that crashed on it: a fresh install shipped no databases on any
// platform, so `net capture` exited before the first packet and the GUI could
// only report "exit status 1".
type RequiredDB struct {
	// File is the basename inside resolvers.DataBaseFolderPath.
	File string
	// Flag is the capture flag that switches this dependency off. A caller
	// that cannot obtain the database can disable the feature instead of
	// failing, which is what keeps analysis possible offline.
	Flag string
	// Feature names the capability lost when the flag is used.
	Feature string
}

// requiredDBs lists every database whose absence aborts a capture run.
//
// Only the geolocation pair is listed. The MAC, service and DHCP resolvers
// log a warning and continue when their database is missing, so they do not
// gate a run and must not be treated as if they did.
var requiredDBs = []RequiredDB{
	{File: "GeoLite2-City.mmdb", Flag: "-geoDB=false", Feature: "geolocation enrichment"},
	{File: "GeoLite2-ASN.mmdb", Flag: "-geoDB=false", Feature: "geolocation enrichment"},
}

// RequiredDBs returns a copy of the registry.
func RequiredDBs() []RequiredDB {
	out := make([]RequiredDB, len(requiredDBs))
	copy(out, requiredDBs)

	return out
}

// MissingRequiredDBs returns the required databases that are not present in
// resolvers.DataBaseFolderPath, in registry order.
//
// A path that exists but is a directory, or is empty, counts as missing: a
// truncated download leaves a zero byte file behind, and reporting that as
// present sends the caller into the maxminddb parser instead of back here.
func MissingRequiredDBs() []RequiredDB {
	var missing []RequiredDB

	for _, db := range requiredDBs {
		if !dbFilePresent(filepath.Join(resolvers.DataBaseFolderPath, db.File)) {
			missing = append(missing, db)
		}
	}

	return missing
}

// DisableFlagsForMissingDBs returns the capture flags that switch off every
// feature whose database is absent, deduplicated and in registry order.
//
// Passing these lets a run proceed with reduced enrichment rather than
// aborting, which is the difference between a usable app and one that cannot
// open a single capture until a 91 MB download completes.
func DisableFlagsForMissingDBs() []string {
	var (
		flags []string
		seen  = make(map[string]bool)
	)

	for _, db := range MissingRequiredDBs() {
		if db.Flag == "" || seen[db.Flag] {
			continue
		}

		seen[db.Flag] = true
		flags = append(flags, db.Flag)
	}

	return flags
}

func dbFilePresent(path string) bool {
	info, err := os.Stat(path)
	if err != nil {
		return false
	}

	return !info.IsDir() && info.Size() > 0
}
