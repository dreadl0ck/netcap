/*
 * NETCAP - Traffic Analysis Framework
 * Copyright (c) Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
 * License: GNU General Public License v3.0
 */

package resolvers

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// initGeolocationDB used to call log.Fatalf. A test cannot observe os.Exit, so
// this asserts the property that replaced it: an error comes back and the
// process is still running to read it. Every capture on every clean install
// died here, reported to the GUI as nothing but "exit status 1".
func TestInitGeolocationDBReturnsErrorInsteadOfExiting(t *testing.T) {
	original := DataBaseFolderPath
	DataBaseFolderPath = t.TempDir()

	t.Cleanup(func() { DataBaseFolderPath = original })

	err := initGeolocationDB()
	if err == nil {
		t.Fatal("expected an error for an empty database directory")
	}

	if !errors.Is(err, ErrGeolocationDBMissing) {
		t.Errorf("error %v does not match ErrGeolocationDBMissing", err)
	}
}

// The ASN database is checked separately from the city database, so a half
// populated directory must still be reported rather than reaching the parser.
func TestInitGeolocationDBDetectsPartiallyPopulatedDir(t *testing.T) {
	original := DataBaseFolderPath
	dir := t.TempDir()
	DataBaseFolderPath = dir

	t.Cleanup(func() { DataBaseFolderPath = original })

	if err := os.WriteFile(filepath.Join(dir, "GeoLite2-City.mmdb"), []byte{1}, 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}

	err := initGeolocationDB()
	if err == nil {
		t.Fatal("expected an error when only one database is present")
	}

	if !errors.Is(err, ErrGeolocationDBMissing) {
		t.Errorf("error %v does not match ErrGeolocationDBMissing", err)
	}
}

// A corrupt database is a different remedy from an absent one, so it must not
// report as missing.
func TestInitGeolocationDBDistinguishesCorruptFromMissing(t *testing.T) {
	original := DataBaseFolderPath
	dir := t.TempDir()
	DataBaseFolderPath = dir

	t.Cleanup(func() {
		DataBaseFolderPath = original
		cityReader, asnReader = nil, nil
	})

	for _, name := range []string{"GeoLite2-City.mmdb", "GeoLite2-ASN.mmdb"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("not a maxmind database"), 0o644); err != nil {
			t.Fatalf("write: %v", err)
		}
	}

	err := initGeolocationDB()
	if err == nil {
		t.Fatal("expected an error for a corrupt database")
	}

	if errors.Is(err, ErrGeolocationDBMissing) {
		t.Errorf("corrupt database reported as missing: %v", err)
	}
}

// Lookups must survive a failed init, because that is what makes degrading
// safe rather than a deferred nil dereference.
func TestLookupGeolocationIsSafeWithoutDatabases(t *testing.T) {
	original := DataBaseFolderPath
	originalCity, originalASN := cityReader, asnReader

	DataBaseFolderPath = t.TempDir()
	cityReader, asnReader = nil, nil

	t.Cleanup(func() {
		DataBaseFolderPath = original
		cityReader, asnReader = originalCity, originalASN
	})

	_ = initGeolocationDB()

	geoloc, asn := LookupGeolocation("8.8.8.8")
	if geoloc != "" || asn != "" {
		t.Errorf("LookupGeolocation() = (%q, %q), want empty strings", geoloc, asn)
	}
}
