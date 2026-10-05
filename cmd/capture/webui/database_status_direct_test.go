//go:build !appstore

/*
 * NETCAP - Traffic Analysis Framework
 * Copyright (c) Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
 * License: GNU General Public License v3.0
 */

package webui

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/dreadl0ck/netcap/internal/dbs"
	"github.com/dreadl0ck/netcap/internal/resolvers"
	"github.com/dreadl0ck/netcap/internal/testutil"
)

func withEmptyDatabaseDir(t *testing.T) string {
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

func resetDownloadTracker(t *testing.T) {
	t.Helper()

	dbDownload.mu.Lock()
	dbDownload.status = DatabaseDownloadStatus{State: DownloadIdle}
	dbDownload.mu.Unlock()

	t.Cleanup(func() {
		dbDownload.mu.Lock()
		dbDownload.status = DatabaseDownloadStatus{State: DownloadIdle}
		dbDownload.mu.Unlock()
	})
}

func TestDatabaseStatusReportsMissingDatabases(t *testing.T) {
	dir := withEmptyDatabaseDir(t)
	resetDownloadTracker(t)

	rec := httptest.NewRecorder()
	(&Server{}).handleDatabaseStatus(rec, httptest.NewRequest(http.MethodGet, "/api/dbs/status", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}

	var got DatabaseStatus
	if err := json.NewDecoder(rec.Body).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}

	if got.Satisfied {
		t.Error("expected satisfied=false with an empty database directory")
	}
	if want := len(dbs.RequiredDBs()) + len(dbs.RecommendedDBs()); len(got.Missing) != want {
		t.Errorf("missing = %d, want %d", len(got.Missing), want)
	}
	if got.DatabaseDir != dir {
		t.Errorf("databaseDir = %q, want %q", got.DatabaseDir, dir)
	}

	// Every entry must name the feature lost, or the prompt cannot say what
	// downloading buys.
	for _, m := range got.Missing {
		if m.File == "" || m.Feature == "" {
			t.Errorf("incomplete missing entry: %+v", m)
		}
	}
}

func TestDatabaseStatusIsSatisfiedWhenPresent(t *testing.T) {
	dir := withEmptyDatabaseDir(t)
	resetDownloadTracker(t)

	for _, db := range append(dbs.RequiredDBs(), dbs.RecommendedDBs()...) {
		writeGeoStatusFixture(t, dir, db.File)
	}

	rec := httptest.NewRecorder()
	(&Server{}).handleDatabaseStatus(rec, httptest.NewRequest(http.MethodGet, "/api/dbs/status", nil))

	var got DatabaseStatus
	if err := json.NewDecoder(rec.Body).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}

	if !got.Satisfied {
		t.Errorf("expected satisfied=true, missing=%v", got.Missing)
	}
}

// Missing must serialise as [] rather than null, so the UI can map over it
// without a guard that is easy to forget.
func TestDatabaseStatusMissingIsNeverNullJSON(t *testing.T) {
	dir := withEmptyDatabaseDir(t)
	resetDownloadTracker(t)

	for _, db := range append(dbs.RequiredDBs(), dbs.RecommendedDBs()...) {
		writeGeoStatusFixture(t, dir, db.File)
	}

	rec := httptest.NewRecorder()
	(&Server{}).handleDatabaseStatus(rec, httptest.NewRequest(http.MethodGet, "/api/dbs/status", nil))

	var raw map[string]json.RawMessage
	if err := json.Unmarshal(rec.Body.Bytes(), &raw); err != nil {
		t.Fatalf("decode: %v", err)
	}

	if string(raw["missing"]) != "[]" {
		t.Errorf("missing = %s, want []", raw["missing"])
	}
}

func writeGeoStatusFixture(t *testing.T, dir, file string) {
	kind := "GeoLite2-City"
	switch file {
	case "GeoLite2-ASN.mmdb":
		kind = "GeoLite2-ASN"
	case "dbip-city-lite.mmdb":
		kind = "DBIP-City-Lite"
	case "dbip-asn-lite.mmdb":
		kind = "DBIP-ASN-Lite"
	}
	testutil.WriteMMDB(t, filepath.Join(dir, file), kind, time.Now(), nil)
}

// A second start while one is running must be refused. Two concurrent 91 MB
// downloads into the same destination is the failure a double click causes.
func TestBeginDatabaseDownloadIsExclusive(t *testing.T) {
	resetDownloadTracker(t)

	if !beginDatabaseDownload() {
		t.Fatal("first claim was refused")
	}
	if beginDatabaseDownload() {
		t.Fatal("second claim was granted while a download was running")
	}

	finishDatabaseDownload(nil)

	if !beginDatabaseDownload() {
		t.Fatal("claim refused after the previous download finished")
	}
}

func TestFinishDatabaseDownloadRecordsFailure(t *testing.T) {
	resetDownloadTracker(t)

	if !beginDatabaseDownload() {
		t.Fatal("claim refused")
	}

	finishDatabaseDownload(errors.New("no route to host"))

	got := databaseDownloadStatus()
	if got.State != DownloadFailed {
		t.Errorf("state = %q, want %q", got.State, DownloadFailed)
	}
	if got.Error != "no route to host" {
		t.Errorf("error = %q, want the underlying cause", got.Error)
	}
	if got.FinishedAt == 0 {
		t.Error("finishedAt not set")
	}
}

// Progress arriving after a download settled must not resurrect the running
// state; a late callback from the previous run would otherwise leave the UI
// polling forever.
func TestUpdateDatabaseDownloadIgnoresLateProgress(t *testing.T) {
	resetDownloadTracker(t)

	if !beginDatabaseDownload() {
		t.Fatal("claim refused")
	}

	finishDatabaseDownload(nil)
	updateDatabaseDownload(dbs.DownloadProgress{Stage: dbs.StageDownload, Percent: 12})

	got := databaseDownloadStatus()
	if got.State != DownloadCompleted {
		t.Errorf("state = %q, want %q", got.State, DownloadCompleted)
	}
	if got.Percent != 100 {
		t.Errorf("percent = %v, want 100", got.Percent)
	}
}

func TestDatabaseStatusRejectsNonGet(t *testing.T) {
	withEmptyDatabaseDir(t)
	resetDownloadTracker(t)

	rec := httptest.NewRecorder()
	(&Server{}).handleDatabaseStatus(rec, httptest.NewRequest(http.MethodPost, "/api/dbs/status", nil))

	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want 405", rec.Code)
	}
}
