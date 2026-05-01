/*
 * NETCAP - Traffic Analysis Framework
 * Copyright (c) Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
 * License: GNU General Public License v3.0
 */

package webui

import (
	"net/http/httptest"
	"path/filepath"
	"testing"
)

// TestResolveChartScopeDirsCurrent confirms the legacy behavior: empty scope
// resolves to a single dir from the active outDir.
func TestResolveChartScopeDirsCurrent(t *testing.T) {
	tmp := t.TempDir()
	s := &Server{outDir: filepath.Join(tmp, "out")}
	r := httptest.NewRequest("GET", "/api/chart/data", nil)
	dirs, status, err := s.resolveChartScopeDirs("", r)
	if err != nil {
		t.Fatalf("unexpected err: %v (status=%d)", err, status)
	}
	if len(dirs) != 1 || dirs[0] != filepath.Join(tmp, "out") {
		t.Errorf("expected single active outDir, got %v", dirs)
	}
}

// TestResolveChartScopeDirsCurrentEmpty fails fast when no dir is configured.
func TestResolveChartScopeDirsCurrentEmpty(t *testing.T) {
	s := &Server{}
	r := httptest.NewRequest("GET", "/api/chart/data", nil)
	_, status, err := s.resolveChartScopeDirs("", r)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if status != 503 {
		t.Errorf("expected 503, got %d", status)
	}
}

// TestResolveChartScopeDirsAllLocal aggregates per-input-file output dirs in
// local mode by deriving them from baseOutDir + input basename.
func TestResolveChartScopeDirsAllLocal(t *testing.T) {
	base := t.TempDir()
	s := &Server{
		baseOutDir: base,
		inputFiles: []string{"/tmp/a.pcap", "/tmp/b.pcapng"},
	}
	r := httptest.NewRequest("GET", "/api/chart/data?scope=all", nil)
	dirs, _, err := s.resolveChartScopeDirs("all", r)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(dirs) != 2 {
		t.Fatalf("expected 2 dirs, got %d: %v", len(dirs), dirs)
	}
	want1 := filepath.Join(base, "a")
	want2 := filepath.Join(base, "b")
	if dirs[0] != want1 || dirs[1] != want2 {
		t.Errorf("unexpected dirs: %v want [%s %s]", dirs, want1, want2)
	}
}

// TestResolveChartScopeDirsByPcapPath resolves a specific pcap path back to
// its derived output dir without mutating the active outDir.
func TestResolveChartScopeDirsByPcapPath(t *testing.T) {
	base := t.TempDir()
	s := &Server{
		baseOutDir: base,
		outDir:     filepath.Join(base, "active"),
		inputFiles: []string{"/tmp/foo.pcap", "/tmp/bar.pcap"},
	}
	r := httptest.NewRequest("GET", "/", nil)
	dirs, _, err := s.resolveChartScopeDirs("/tmp/foo.pcap", r)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	want := filepath.Join(base, "foo")
	if len(dirs) != 1 || dirs[0] != want {
		t.Errorf("dirs=%v want [%s]", dirs, want)
	}
	if s.outDir != filepath.Join(base, "active") {
		t.Error("outDir was mutated by scope resolution")
	}
}

// TestResolveChartScopeDirsUnknownPcap returns 404.
func TestResolveChartScopeDirsUnknownPcap(t *testing.T) {
	s := &Server{baseOutDir: t.TempDir()}
	r := httptest.NewRequest("GET", "/", nil)
	_, status, err := s.resolveChartScopeDirs("nope.pcap", r)
	if err == nil {
		t.Fatal("expected error")
	}
	if status != 404 {
		t.Errorf("expected 404, got %d", status)
	}
}

// TestResolveChartScopeDirsServiceModeByPath: in service mode the frontend
// sends the file's full path (FileInfo.path) as scope. The resolver must look
// up the matching session by InputFile / InputFilename / basename, not just
// by SessionID.
func TestResolveChartScopeDirsServiceModeByPath(t *testing.T) {
	tmp := t.TempDir()
	sm := NewSessionManager(0, 0, 0)
	sm.sessions["sess-1"] = &SessionInfo{
		SessionID:     "sess-1",
		InputFile:     "/data/pcaps/bgp.pcap",
		InputFilename: "bgp.pcap",
		OutputDir:     filepath.Join(tmp, "out"),
		Status:        StatusCompleted,
	}
	s := &Server{
		isServiceMode:  true,
		sessionManager: sm,
	}
	r := httptest.NewRequest("GET", "/", nil)

	// Match by full path (the most common case from the scope selector).
	dirs, _, err := s.resolveChartScopeDirs("/data/pcaps/bgp.pcap", r)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	want := filepath.Join(tmp, "out")
	if len(dirs) != 1 || dirs[0] != want {
		t.Errorf("path scope: dirs=%v want [%s]", dirs, want)
	}

	// Match by basename.
	dirs, _, err = s.resolveChartScopeDirs("bgp.pcap", r)
	if err != nil {
		t.Fatalf("basename: unexpected err: %v", err)
	}
	if len(dirs) != 1 || dirs[0] != want {
		t.Errorf("basename scope: dirs=%v want [%s]", dirs, want)
	}

	// Direct session-id lookup still works.
	dirs, _, err = s.resolveChartScopeDirs("sess-1", r)
	if err != nil {
		t.Fatalf("session id: unexpected err: %v", err)
	}
	if len(dirs) != 1 || dirs[0] != want {
		t.Errorf("session id scope: dirs=%v want [%s]", dirs, want)
	}
}
