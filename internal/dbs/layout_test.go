package dbs

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

// The v0.10 server must keep serving the frozen bleve revision to old
// clients on the original routes while new clients use /dbs/v2/.
func TestLegacyAndLayoutRoutesAreSeparate(t *testing.T) {
	s := newTestServer(t)
	s.legacyDir = filepath.Join(s.buildDir, "dbs")
	s.dbsDir = filepath.Join(s.buildDir, layoutPrefix)
	for _, dir := range []string{s.legacyDir, s.dbsDir} {
		if err := mkdirs(dir); err != nil {
			t.Fatal(err)
		}
	}
	legacy := map[string]any{"version": "2026-10-04", "tarball": "2026-10-04.tar.gz"}
	if err := writeJSON(filepath.Join(s.legacyDir, "latest.json"), legacy); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(s.legacyDir, "2026-10-04.tar.gz"), []byte("bleve"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := writeJSON(filepath.Join(s.dbsDir, "2026-10-05.json"), map[string]any{"version": "2026-10-05", "layout": Layout}); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(s.dbsDir, "2026-10-05.tar.gz"), []byte("sqlite"), 0o644); err != nil {
		t.Fatal(err)
	}
	s.currentDate = "2026-10-05"

	mux := http.NewServeMux()
	mux.HandleFunc("/dbs/"+layoutPrefix+"/", s.handleDownload)
	mux.HandleFunc("/dbs/"+layoutPrefix+"/latest", s.handleLatest)
	mux.HandleFunc("/dbs/", s.handleLegacy)

	get := func(path string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		return rec
	}

	var meta map[string]any
	if err := json.Unmarshal(get("/dbs/latest").Body.Bytes(), &meta); err != nil || meta["version"] != "2026-10-04" {
		t.Fatalf("legacy latest: %v %v", meta, err)
	}
	if rec := get("/dbs/latest"); rec.Header().Get("Deprecation") != "true" {
		t.Error("legacy route not marked deprecated")
	}
	if body := get("/dbs/2026-10-04.tar.gz").Body.String(); body != "bleve" {
		t.Errorf("legacy tarball: %q", body)
	}
	if err := json.Unmarshal(get("/dbs/v2/latest").Body.Bytes(), &meta); err != nil || meta["version"] != "2026-10-05" {
		t.Fatalf("v2 latest: %v %v", meta, err)
	}
	if body := get("/dbs/v2/2026-10-05.tar.gz").Body.String(); body != "sqlite" {
		t.Errorf("v2 tarball: %q", body)
	}
	if code := get("/dbs/v2/2026-10-04.tar.gz").Code; code != http.StatusNotFound {
		t.Errorf("v2 served a legacy tarball: %d", code)
	}
	if code := get("/dbs/v2/2026-10-05.json").Code; code != http.StatusNotFound {
		t.Errorf("non-tarball served: %d", code)
	}
}

func TestFetchMetadataRejectsOldServer(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/dbs/latest" {
			w.Write([]byte(`{"version":"2026-10-04","tarball":"2026-10-04.tar.gz"}`))
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()
	if _, err := fetchMetadata(srv.URL); err == nil || !contains(err.Error(), "predates netcap v0.10") {
		t.Fatalf("got %v", err)
	}
}

func TestFetchMetadataRejectsOtherSchema(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte(`{"version":"x","layout":2,"vulndb_schema":99}`))
	}))
	defer srv.Close()
	if _, err := fetchMetadata(srv.URL); err == nil || !contains(err.Error(), "schema 99") {
		t.Fatalf("got %v", err)
	}
}

func TestVerifySHA256(t *testing.T) {
	p := filepath.Join(t.TempDir(), "f")
	if err := os.WriteFile(p, []byte("abc"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := verifySHA256(p, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"); err != nil {
		t.Fatal(err)
	}
	if verifySHA256(p, "00") == nil || verifySHA256(p, "") == nil {
		t.Fatal("mismatch or missing digest accepted")
	}
}
