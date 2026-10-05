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
	"github.com/dreadl0ck/netcap/internal/vulndb"
)

// RequiredDB describes an enrichment file and the flag that disables its feature.
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

// One complete selected provider is sufficient; both providers are not required.
var requiredDBs = []RequiredDB{
	{File: "dbip-city-lite.mmdb", Flag: "-geoDB=false", Feature: "geolocation enrichment"},
	{File: "dbip-asn-lite.mmdb", Flag: "-geoDB=false", Feature: "geolocation enrichment"},
	{File: "GeoLite2-City.mmdb", Flag: "-geoDB=false", Feature: "geolocation enrichment"},
	{File: "GeoLite2-ASN.mmdb", Flag: "-geoDB=false", Feature: "geolocation enrichment"},
}

// recommendedDBs lists databases whose absence costs a feature but never
// aborts a run, so they carry no disable flag. They are still reported as
// missing so the UI offers the download: an install upgraded from the bleve
// layout has nvd.bleve but no netcap.sqlite, and without this it reported
// every database present while vulnerability and exploit lookups were off.
var recommendedDBs = []RequiredDB{
	{File: vulndb.FileName, Feature: "vulnerability and exploit lookups"},
}

// MissingDBs returns every required and recommended database that is absent,
// for reporting. Capture flags come from MissingRequiredDBs alone.
func MissingDBs(selection ...string) []RequiredDB {
	missing := MissingRequiredDBs(selection...)
	for _, db := range recommendedDBs {
		if !dbFilePresent(filepath.Join(resolvers.DataBaseFolderPath, db.File)) {
			missing = append(missing, db)
		}
	}

	return missing
}

// RecommendedDBs returns a copy of the recommended registry.
func RecommendedDBs() []RequiredDB {
	out := make([]RequiredDB, len(recommendedDBs))
	copy(out, recommendedDBs)

	return out
}

// RequiredDBs returns a copy of the registry.
func RequiredDBs() []RequiredDB {
	out := make([]RequiredDB, len(requiredDBs))
	copy(out, requiredDBs)

	return out
}

// MissingRequiredDBs returns unavailable files only when no selected pair is usable.
func MissingRequiredDBs(selection ...string) []RequiredDB {
	var missing []RequiredDB
	raw := ""
	if len(selection) > 0 {
		raw = selection[0]
	}
	order, err := resolvers.GeoProviderOrder(raw)
	if err != nil {
		return RequiredDBs()
	}
	for _, name := range order {
		files := resolvers.GeoFiles(name)
		var absent []RequiredDB
		for _, file := range []string{files.City, files.ASN} {
			kind := "City"
			if file == files.ASN {
				kind = "ASN"
			}
			reader, err := resolvers.OpenGeoDatabase(filepath.Join(resolvers.DataBaseFolderPath, file), name, kind)
			if err != nil {
				absent = append(absent, RequiredDB{file, "-geoDB=false", "geolocation enrichment"})
			} else {
				reader.Close()
			}
		}
		if len(absent) == 0 {
			return nil
		}
		missing = append(missing, absent...)
	}

	return missing
}

// DisableFlagsForMissingDBs returns the capture flags that switch off every
// feature whose database is absent, deduplicated and in registry order.
//
// Passing these lets a run proceed with reduced enrichment rather than
// aborting, which is the difference between a usable app and one that cannot
// open a single capture until a 91 MB download completes.
func DisableFlagsForMissingDBs(selection ...string) []string {
	var (
		flags []string
		seen  = make(map[string]bool)
	)

	for _, db := range MissingRequiredDBs(selection...) {
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
