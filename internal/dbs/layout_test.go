package dbs

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

// Legacy metadata and archive bodies are retired after v3 is ready.
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

	mux := s.Handler()

	get := func(path string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		return rec
	}

	if rec := get("/dbs/latest"); rec.Code != 503 {
		t.Fatalf("unready legacy route: %d", rec.Code)
	}
	s.ready.Store(true)
	for _, path := range []string{"/dbs/latest", "/dbs/list", "/dbs/2026-10-04.tar.gz", "/dbs/v2/latest", "/dbs/v2/2026-10-05.tar.gz"} {
		if rec := get(path); rec.Code != 410 {
			t.Fatalf("retired %s: %d", path, rec.Code)
		}
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
		w.Write([]byte(`{"version":"x","layout":3,"vulndb_schema":99}`))
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
