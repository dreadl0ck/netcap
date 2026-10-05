/*
 * NETCAP - Traffic Analysis Framework
 * Copyright (c) Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
 * License: GNU General Public License v3.0
 */

package dbs

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/dreadl0ck/netcap/internal/resolvers"
	"github.com/dreadl0ck/netcap/internal/testutil"
	"github.com/dreadl0ck/netcap/internal/vulndb"
)

// withDatabaseDir points the resolver database path at a temporary directory
// for the duration of a test.
func withDatabaseDir(t *testing.T) string {
	t.Helper()
	t.Setenv("NC_GEO_PROVIDERS", resolvers.DefaultGeoProviders)

	original := resolvers.DataBaseFolderPath
	dir := t.TempDir()
	resolvers.DataBaseFolderPath = dir

	t.Cleanup(func() {
		resolvers.DataBaseFolderPath = original
	})

	return dir
}

func TestRequiredDBsRespectProviderSelection(t *testing.T) {
	dir := withDatabaseDir(t)
	writeDB(t, dir, "dbip-city-lite.mmdb", 1)
	writeDB(t, dir, "dbip-asn-lite.mmdb", 1)
	if flags := DisableFlagsForMissingDBs("dbip,geolite2"); len(flags) != 0 {
		t.Fatal("disabled usable DB-IP", flags)
	}
	if flags := DisableFlagsForMissingDBs("geolite2"); len(flags) != 1 {
		t.Fatal("used unselected DB-IP", flags)
	}
	os.WriteFile(filepath.Join(dir, "dbip-asn-lite.mmdb"), []byte("corrupt"), 0o644)
	if flags := DisableFlagsForMissingDBs("dbip"); len(flags) != 1 {
		t.Fatal("accepted corrupt provider", flags)
	}
}

func writeDB(t *testing.T, dir, name string, size int) {
	t.Helper()
	if size > 0 {
		kind := "GeoLite2-City"
		switch name {
		case "GeoLite2-ASN.mmdb":
			kind = "GeoLite2-ASN"
		case "dbip-city-lite.mmdb":
			kind = "DBIP-City-Lite"
		case "dbip-asn-lite.mmdb":
			kind = "DBIP-ASN-Lite"
		}
		testutil.WriteMMDB(t, filepath.Join(dir, name), kind, time.Now(), nil)
		return
	}

	if err := os.WriteFile(filepath.Join(dir, name), make([]byte, size), 0o644); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
}

func TestMissingRequiredDBsReportsAllOnEmptyDir(t *testing.T) {
	withDatabaseDir(t)

	missing := MissingRequiredDBs()
	if len(missing) != len(RequiredDBs()) {
		t.Fatalf("expected all %d databases missing, got %d", len(RequiredDBs()), len(missing))
	}
}

func TestMissingRequiredDBsIsEmptyWhenAllPresent(t *testing.T) {
	dir := withDatabaseDir(t)

	for _, db := range RequiredDBs() {
		writeDB(t, dir, db.File, 1)
	}

	if missing := MissingRequiredDBs(); len(missing) != 0 {
		t.Fatalf("expected no missing databases, got %v", missing)
	}
}

// A truncated download leaves a zero byte file. Treating that as present sends
// the caller into the maxminddb parser instead of back to the download.
func TestMissingRequiredDBsTreatsEmptyFileAsMissing(t *testing.T) {
	dir := withDatabaseDir(t)

	for _, db := range RequiredDBs() {
		writeDB(t, dir, db.File, 0)
	}

	if missing := MissingRequiredDBs(); len(missing) != len(RequiredDBs()) {
		t.Fatalf("expected empty files to count as missing, got %d", len(missing))
	}
}

func TestMissingRequiredDBsTreatsDirectoryAsMissing(t *testing.T) {
	dir := withDatabaseDir(t)

	for _, db := range RequiredDBs() {
		if err := os.MkdirAll(filepath.Join(dir, db.File), 0o755); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
	}

	if missing := MissingRequiredDBs(); len(missing) != len(RequiredDBs()) {
		t.Fatalf("expected directories to count as missing, got %d", len(missing))
	}
}

// The flags are what keep a clean install able to analyse anything at all, so
// pin both that they appear and that the shared geolocation flag appears once.
func TestDisableFlagsForMissingDBsAreDeduplicated(t *testing.T) {
	withDatabaseDir(t)

	flags := DisableFlagsForMissingDBs()
	if len(flags) == 0 {
		t.Fatal("expected disable flags when every database is missing")
	}

	seen := make(map[string]int)
	for _, f := range flags {
		seen[f]++
	}

	for flag, count := range seen {
		if count != 1 {
			t.Errorf("flag %q repeated %d times", flag, count)
		}
	}

	if seen["-geoDB=false"] != 1 {
		t.Errorf("expected -geoDB=false exactly once, got %d", seen["-geoDB=false"])
	}
}

func TestDisableFlagsForMissingDBsIsEmptyWhenSatisfied(t *testing.T) {
	dir := withDatabaseDir(t)

	for _, db := range RequiredDBs() {
		writeDB(t, dir, db.File, 1)
	}

	if flags := DisableFlagsForMissingDBs(); len(flags) != 0 {
		t.Fatalf("expected no disable flags, got %v", flags)
	}
}

// Every required database must name the flag that switches its feature off.
// A required database with no flag is one that can still abort a run, which is
// the failure mode this registry exists to remove.
func TestEveryRequiredDBHasADisableFlag(t *testing.T) {
	for _, db := range RequiredDBs() {
		if db.Flag == "" {
			t.Errorf("required database %q has no disable flag", db.File)
		}
		if db.Feature == "" {
			t.Errorf("required database %q has no feature name", db.File)
		}
	}
}

// RequiredDBs hands out a copy; mutating it must not corrupt the registry.
func TestRequiredDBsReturnsACopy(t *testing.T) {
	first := RequiredDBs()
	if len(first) == 0 {
		t.Fatal("registry is empty")
	}

	first[0].File = "mutated"

	if RequiredDBs()[0].File == "mutated" {
		t.Fatal("RequiredDBs exposed its backing array")
	}
}

// An install upgraded from the bleve layout has every required database but
// no netcap.sqlite. It must be reported so the UI offers the download, and it
// must not add a capture flag: its absence disables lookups, not the run.
func TestMissingDBsReportsVulnDBWithoutDisablingAnything(t *testing.T) {
	dir := withDatabaseDir(t)
	for _, db := range RequiredDBs() {
		writeDB(t, dir, db.File, 1)
	}
	writeDB(t, dir, "nvd.bleve", 1)

	missing := MissingDBs()
	if len(missing) != 1 || missing[0].File != vulndb.FileName {
		t.Fatalf("missing = %+v, want only %s", missing, vulndb.FileName)
	}
	if flags := DisableFlagsForMissingDBs(); len(flags) != 0 {
		t.Fatalf("a recommended database must not disable features, got %v", flags)
	}

	writeDB(t, dir, vulndb.FileName, 1)
	if missing := MissingDBs(); len(missing) != 0 {
		t.Fatalf("missing = %+v after installing %s", missing, vulndb.FileName)
	}
}
