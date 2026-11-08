package dbs

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestAtomicBytesWaitsForWindowsReader(t *testing.T) {
	path := filepath.Join(t.TempDir(), "latest.json")
	if err := atomicBytes(path, []byte("old")); err != nil {
		t.Fatal(err)
	}
	reader, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	done := make(chan error, 1)
	go func() { done <- atomicBytes(path, []byte("new")) }()
	select {
	case err := <-done:
		t.Fatalf("replacement returned while reader held the file: %v", err)
	case <-time.After(50 * time.Millisecond):
	}
	if err := reader.Close(); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if b, err := os.ReadFile(path); err != nil || string(b) != "new" {
		t.Fatalf("replacement = %q, %v", b, err)
	}
}

func TestAtomicBytesPreservesWindowsLockedTarget(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "latest.json")
	if err := atomicBytes(path, []byte("old")); err != nil {
		t.Fatal(err)
	}
	reader, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	if err := atomicBytes(path, []byte("new")); err == nil {
		t.Fatal("replaced a locked target")
	}
	if b, err := os.ReadFile(path); err != nil || string(b) != "old" {
		t.Fatalf("original = %q, %v", b, err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 1 {
		t.Fatalf("temporary file cleanup: %v, %v", entries, err)
	}
}

func TestReplaceAtomicFileMissingSource(t *testing.T) {
	dir := t.TempDir()
	err := replaceAtomicFile(filepath.Join(dir, "missing"), filepath.Join(dir, "latest.json"))
	if !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing source: %v", err)
	}
}
