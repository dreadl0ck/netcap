/*
 * NETCAP - Traffic Analysis Framework
 * Copyright (c) Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
 * License: GNU General Public License v3.0
 */

package dbs

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

// --- small helpers used by tests ---

func contains(haystack, needle string) bool { return strings.Contains(haystack, needle) }

func mkdirs(path string) error { return os.MkdirAll(path, 0o755) }

func touch(path string) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	return f.Close()
}

func writeJSON(path string, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o644)
}

// newTestServer builds a DBServer wired to a temp dir, without touching the
// filesystem layout the real server expects. It does NOT call Start(); tests
// drive the handlers and lifecycle directly so they can be parallel-safe and
// avoid clashing on http.DefaultServeMux.
func newTestServer(t *testing.T) *DBServer {
	t.Helper()
	dir := t.TempDir()
	return &DBServer{
		addr:        ":0",
		buildDir:    dir,
		dbsDir:      dir + "/dbs",
		currentDate: "0000-00-00",
	}
}

// TestHandleHealth_BeforeReady asserts that /health returns 200 with
// status="initializing" before the readiness flag is flipped. This is the
// core of the fix: orchestrator healthchecks must pass while the initial
// rebuild is still running.
func TestHandleHealth_BeforeReady(t *testing.T) {
	s := newTestServer(t)
	if s.ready.Load() {
		t.Fatal("new server should not be ready")
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	s.handleHealth(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status: got %d, want %d", rec.Code, http.StatusOK)
	}
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got := body["status"]; got != "initializing" {
		t.Errorf("status field: got %v, want %q", got, "initializing")
	}
	if _, ok := body["timestamp"]; !ok {
		t.Errorf("timestamp missing")
	}
}

// TestHandleHealth_AfterReady asserts the steady-state body once the server
// has marked itself ready.
func TestHandleHealth_AfterReady(t *testing.T) {
	s := newTestServer(t)
	s.mu.Lock()
	s.currentDate = "2026-05-17"
	s.mu.Unlock()
	s.ready.Store(true)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	s.handleHealth(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status: got %d, want %d", rec.Code, http.StatusOK)
	}
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got := body["status"]; got != "healthy" {
		t.Errorf("status field: got %v, want %q", got, "healthy")
	}
	if got := body["current_version"]; got != "2026-05-17" {
		t.Errorf("current_version: got %v, want %q", got, "2026-05-17")
	}
}

// TestHandleHealth_ConcurrentReady stresses the readiness flag flip while
// concurrent /health probes run. Must be clean under -race.
func TestHandleHealth_ConcurrentReady(t *testing.T) {
	s := newTestServer(t)

	const numProbes = 50
	var wg sync.WaitGroup
	stop := make(chan struct{})

	// Probers
	for i := 0; i < numProbes; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				rec := httptest.NewRecorder()
				req := httptest.NewRequest(http.MethodGet, "/health", nil)
				s.handleHealth(rec, req)
				if rec.Code != http.StatusOK {
					t.Errorf("health returned %d during concurrent probing", rec.Code)
					return
				}
			}
		}()
	}

	// Flip ready after a brief delay; let probers run a bit more.
	time.Sleep(20 * time.Millisecond)
	s.ready.Store(true)
	time.Sleep(40 * time.Millisecond)
	close(stop)
	wg.Wait()
}

// TestHandleRoot_StatusLabel checks that the human-readable status page
// switches from INITIALIZING to HEALTHY based on the readiness flag.
func TestHandleRoot_StatusLabel(t *testing.T) {
	s := newTestServer(t)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	s.handleRoot(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("not-ready: status %d", rec.Code)
	}
	if got := rec.Body.String(); !contains(got, "Status: INITIALIZING") {
		t.Errorf("not-ready body missing INITIALIZING label:\n%s", got)
	}

	s.ready.Store(true)
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/", nil)
	s.handleRoot(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("ready: status %d", rec.Code)
	}
	if got := rec.Body.String(); !contains(got, "Status: HEALTHY") {
		t.Errorf("ready body missing HEALTHY label:\n%s", got)
	}
}

// TestInitialize_FastPathPreservesReadiness exercises the cached-revision
// branch of initialize(): a pre-existing tarball + metadata on disk should
// make the server ready without doing any network work.
func TestInitialize_FastPathPreservesReadiness(t *testing.T) {
	s := newTestServer(t)
	if err := mkdirs(s.dbsDir); err != nil {
		t.Fatal(err)
	}

	// Seed a fake "existing revision": empty tarball + metadata JSON. The
	// content is intentionally minimal; checkExistingDatabases only inspects
	// filenames and the presence of the JSON sibling.
	date := "2026-05-17"
	if err := touch(s.dbsDir + "/" + date + ".tar.gz"); err != nil {
		t.Fatal(err)
	}
	if err := writeJSON(s.dbsDir+"/"+date+".json", map[string]any{
		"version": date, "tarball": date + ".tar.gz",
	}); err != nil {
		t.Fatal(err)
	}

	if err := s.initialize(); err != nil {
		t.Fatalf("initialize returned: %v", err)
	}
	if !s.ready.Load() {
		t.Error("expected ready=true after fast-path initialize")
	}
	s.mu.RLock()
	got := s.currentDate
	s.mu.RUnlock()
	if got != date {
		t.Errorf("currentDate: got %q, want %q", got, date)
	}
}
