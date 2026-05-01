//go:build hyperscan

/*
 * NETCAP - Traffic Analysis Framework
 * Copyright (c) Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
 * License: GNU General Public License v3.0
 */

package hsmatch

import (
	"errors"
	"sort"
	"sync"
	"sync/atomic"
	"testing"
)

func TestCompileAndMatch(t *testing.T) {
	patterns := []Pattern{
		{ID: 1, Expr: `foo`, Flags: FlagSingleMatch},
		{ID: 2, Expr: `BAR`, Flags: FlagCaseless | FlagSingleMatch},
		{ID: 3, Expr: `\d{3}`, Flags: FlagSingleMatch},
	}

	db, rejections, err := Compile(patterns)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	if len(rejections) != 0 {
		t.Fatalf("expected 0 rejections, got %v", rejections)
	}
	defer func() { _ = db.Close() }()

	var (
		mu  sync.Mutex
		ids []int
	)
	err = db.Match([]byte("foo bar baz 4242"), func(h Hit) error {
		mu.Lock()
		ids = append(ids, h.ID)
		mu.Unlock()
		return nil
	})
	if err != nil {
		t.Fatalf("match: %v", err)
	}

	sort.Ints(ids)
	if len(ids) != 3 || ids[0] != 1 || ids[1] != 2 || ids[2] != 3 {
		t.Fatalf("expected ids [1 2 3], got %v", ids)
	}

	stats := db.Stats()
	if stats.Patterns != 3 {
		t.Errorf("expected 3 patterns in stats, got %d", stats.Patterns)
	}
	if stats.Matches != 3 {
		t.Errorf("expected 3 matches in stats, got %d", stats.Matches)
	}
	if stats.Scans != 1 {
		t.Errorf("expected 1 scan in stats, got %d", stats.Scans)
	}
	if stats.ScanErrors != 0 {
		t.Errorf("expected 0 scan errors, got %d", stats.ScanErrors)
	}
}

func TestCompilePartitionsRejected(t *testing.T) {
	patterns := []Pattern{
		{ID: 0, Expr: `valid\d+`},
		{ID: 1, Expr: `(\w+)\1`}, // backreference: not supported by Hyperscan core
		{ID: 2, Expr: `also-valid`},
	}

	db, rejections, err := Compile(patterns)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	if len(rejections) != 1 {
		t.Fatalf("expected 1 rejection, got %v", rejections)
	}
	r := rejections[0]
	if r.Index != 1 || r.ID != 1 {
		t.Errorf("expected rejection of pattern index/id 1, got %+v", r)
	}
	if r.Reason == "" {
		t.Error("expected non-empty rejection reason")
	}
	if r.Expr != `(\w+)\1` {
		t.Errorf("expected rejection to carry original expr, got %q", r.Expr)
	}
	if db == nil {
		t.Fatal("expected non-nil db when at least one pattern compiles")
	}
	if got := db.Stats().Rejections; got != 1 {
		t.Errorf("expected stats.Rejections=1, got %d", got)
	}
	_ = db.Close()
}

func TestEmpty(t *testing.T) {
	db, rejections, err := Compile(nil)
	if err != nil || db != nil || rejections != nil {
		t.Fatalf("expected (nil,nil,nil) for empty input, got (%v,%v,%v)", db, rejections, err)
	}
}

func TestMatchAbort(t *testing.T) {
	db, _, err := Compile([]Pattern{{ID: 7, Expr: `x`}})
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	defer func() { _ = db.Close() }()

	sentinel := errStop{}
	err = db.Match([]byte("xxxx"), func(Hit) error { return sentinel })
	if err != sentinel {
		t.Fatalf("expected sentinel error to propagate, got %v", err)
	}
	// Aborted scan must not be counted as a scan error.
	if got := db.Stats().ScanErrors; got != 0 {
		t.Errorf("expected ScanErrors=0 after handler abort, got %d", got)
	}
}

func TestMatchAfterClose(t *testing.T) {
	db, _, err := Compile([]Pattern{{ID: 0, Expr: `x`}})
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	// Idempotent close.
	if err := db.Close(); err != nil {
		t.Fatalf("second close: %v", err)
	}

	err = db.Match([]byte("xxxx"), func(Hit) error { return nil })
	if !errors.Is(err, ErrClosed) {
		t.Fatalf("expected ErrClosed after Close, got %v", err)
	}
}

func TestMatchEmptyBuffer(t *testing.T) {
	db, _, err := Compile([]Pattern{{ID: 0, Expr: `x`}})
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	defer func() { _ = db.Close() }()

	if err := db.Match(nil, func(Hit) error {
		t.Fatal("handler must not fire on empty buffer")
		return nil
	}); err != nil {
		t.Fatalf("expected nil for empty input, got %v", err)
	}
	// Should not increment scans counter for empty buffer.
	if got := db.Stats().Scans; got != 0 {
		t.Errorf("expected Scans=0 for empty buffer, got %d", got)
	}
}

func TestConcurrentMatch(t *testing.T) {
	db, _, err := Compile([]Pattern{{ID: 0, Expr: `needle`}})
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	defer func() { _ = db.Close() }()

	const goroutines = 32
	const iterations = 50
	var hits atomic.Uint64
	var wg sync.WaitGroup
	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < iterations; j++ {
				if err := db.Match([]byte("haystack with a needle in it"), func(Hit) error {
					hits.Add(1)
					return nil
				}); err != nil {
					t.Errorf("match failed: %v", err)
					return
				}
			}
		}()
	}
	wg.Wait()

	if got := hits.Load(); got != goroutines*iterations {
		t.Errorf("expected %d hits, got %d", goroutines*iterations, got)
	}
	if got := db.Stats().Scans; got != goroutines*iterations {
		t.Errorf("expected stats.Scans=%d, got %d", goroutines*iterations, got)
	}
}

func TestVersion(t *testing.T) {
	if v := Version(); v == "" || v == "disabled" {
		t.Errorf("expected non-empty libhs version, got %q", v)
	}
}

type errStop struct{}

func (errStop) Error() string { return "stop" }
