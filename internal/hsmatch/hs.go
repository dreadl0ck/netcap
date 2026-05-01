//go:build hyperscan

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

package hsmatch

import (
	"errors"
	"fmt"
	"sync"
	"sync/atomic"

	"github.com/flier/gohs/hyperscan"
)

// Enabled reports whether this build was compiled with Hyperscan support.
const Enabled = true

// Version reports the runtime libhs version string (e.g. "5.4.12 ...").
// Useful for surfacing in UIs and logs.
func Version() string { return hyperscan.Version() }

// ErrDisabled is returned by stub implementations when Hyperscan is not
// compiled in. The real implementation does not return it.
var ErrDisabled = errors.New("hsmatch: hyperscan support not compiled in")

// ErrClosed is returned by [DB.Match] when invoked after [DB.Close].
var ErrClosed = errors.New("hsmatch: database closed")

// Flag is a bitmask controlling pattern compile behaviour. The values map 1:1
// to the corresponding gohs (and underlying libhs) compile flags but are
// re-exported here so callers do not need to import gohs directly.
type Flag uint32

// Flag values mirror hyperscan.CompileFlag.
const (
	FlagCaseless    Flag = Flag(hyperscan.Caseless)
	FlagDotAll      Flag = Flag(hyperscan.DotAll)
	FlagMultiLine   Flag = Flag(hyperscan.MultiLine)
	FlagSingleMatch Flag = Flag(hyperscan.SingleMatch)
	FlagAllowEmpty  Flag = Flag(hyperscan.AllowEmpty)
	FlagUtf8        Flag = Flag(hyperscan.Utf8Mode)
	FlagPrefilter   Flag = Flag(hyperscan.PrefilterMode)
	FlagSomLeftMost Flag = Flag(hyperscan.SomLeftMost)
)

// Pattern describes one regex to be added to a Hyperscan database.
type Pattern struct {
	// ID is the identifier reported back to the match handler when this
	// pattern fires. Callers normally use the index in their own pattern
	// list so a hit can be mapped to caller-side metadata in O(1).
	ID int

	// Expr is the PCRE-syntax regular expression. Hyperscan supports a subset
	// of PCRE (no backreferences, no lookaround, no possessive quantifiers).
	Expr string

	// Flags modify compilation behaviour for this pattern.
	Flags Flag
}

// Hit describes a single match returned by [DB.Match].
//
// `From` is only populated when the pattern was compiled with
// [FlagSomLeftMost]. Otherwise it is reported as 0 by libhs and callers
// should treat it as "unknown".
type Hit struct {
	ID   int
	From uint64
	To   uint64
}

// Rejection records a pattern that Hyperscan refused to compile.
//
// Caller-side index in the input slice plus the reason (gohs / libhs error
// message) so logs and UI surfaces can show why a probe was excluded.
type Rejection struct {
	Index  int    // index into the input []Pattern
	ID     int    // Pattern.ID
	Expr   string // Pattern.Expr (truncated by caller if long)
	Reason string // libhs / gohs error message
}

// Stats summarises the runtime state of a [DB] for monitoring / UI.
type Stats struct {
	// Patterns is the number of patterns Hyperscan accepted into the DB.
	Patterns int
	// Rejections counts patterns Hyperscan refused at compile time.
	Rejections int
	// Matches is the cumulative number of (pattern,id) hits emitted across
	// the lifetime of the database.
	Matches uint64
	// Scans is the cumulative number of [DB.Match] invocations.
	Scans uint64
	// ScanErrors is the cumulative number of failed [DB.Match] invocations.
	ScanErrors uint64
}

// DB is a compiled multi-pattern Hyperscan block-mode database with an
// internal pool of scratch buffers (one allocated per concurrent matcher).
type DB struct {
	db    hyperscan.BlockDatabase
	proto *hyperscan.Scratch

	pool sync.Pool // *hyperscan.Scratch (cloned per Get)

	// scratchMu guards the scratches slice. Every cloned scratch is tracked
	// here so Close() can free them deterministically (sync.Pool may drop
	// entries between GC cycles, which would leak C memory otherwise).
	scratchMu sync.Mutex
	scratches []*hyperscan.Scratch

	closed atomic.Bool

	// counters – atomically updated.
	patterns   int
	rejections int
	matches    atomic.Uint64
	scans      atomic.Uint64
	scanErrors atomic.Uint64
}

// Compile builds a Hyperscan database out of the supplied patterns.
//
// Patterns whose expressions Hyperscan refuses to compile are skipped and
// their indices are reported in `rejections`. The returned DB is built only
// from the remaining patterns. If every pattern is unsupported the returned
// DB is nil but err is also nil – callers must handle that case.
func Compile(patterns []Pattern) (db *DB, rejections []Rejection, err error) {
	if len(patterns) == 0 {
		return nil, nil, nil
	}

	hsPatterns := make([]*hyperscan.Pattern, 0, len(patterns))
	for i, p := range patterns {
		hp := &hyperscan.Pattern{
			Expression: p.Expr,
			Flags:      hyperscan.CompileFlag(p.Flags),
			Id:         p.ID,
		}
		// Probe the pattern individually first. Hyperscan's batch compiler
		// fails the whole DB on any single bad pattern, which would defeat
		// the partition fallback.
		if _, infoErr := hp.Info(); infoErr != nil {
			rejections = append(rejections, Rejection{
				Index:  i,
				ID:     p.ID,
				Expr:   p.Expr,
				Reason: infoErr.Error(),
			})
			continue
		}
		hsPatterns = append(hsPatterns, hp)
	}

	if len(hsPatterns) == 0 {
		return nil, rejections, nil
	}

	bdb, buildErr := hyperscan.NewBlockDatabase(hsPatterns...)
	if buildErr != nil {
		return nil, rejections, fmt.Errorf("hsmatch: build block database: %w", buildErr)
	}

	proto, scratchErr := hyperscan.NewScratch(bdb)
	if scratchErr != nil {
		_ = bdb.Close()
		return nil, rejections, fmt.Errorf("hsmatch: alloc prototype scratch: %w", scratchErr)
	}

	d := &DB{
		db:         bdb,
		proto:      proto,
		patterns:   len(hsPatterns),
		rejections: len(rejections),
	}
	d.pool.New = func() any {
		// pool.New cannot return an error; on failure we surface a typed
		// nil and Match() handles the fall-through path.
		s, cloneErr := proto.Clone()
		if cloneErr != nil {
			return (*hyperscan.Scratch)(nil)
		}
		d.scratchMu.Lock()
		d.scratches = append(d.scratches, s)
		d.scratchMu.Unlock()
		return s
	}

	return d, rejections, nil
}

// Match scans `buf` and invokes `fn` for every pattern hit.
//
// Returning a non-nil error from `fn` aborts the scan and that error is
// propagated to the caller. Returning nil continues scanning.
func (d *DB) Match(buf []byte, fn func(Hit) error) error {
	if d == nil {
		return ErrDisabled
	}
	if d.closed.Load() {
		return ErrClosed
	}
	if len(buf) == 0 {
		return nil
	}

	d.scans.Add(1)

	scratch, _ := d.pool.Get().(*hyperscan.Scratch)
	releaseScratch := func() { d.pool.Put(scratch) }
	if scratch == nil {
		// Clone failed in pool.New. Allocate a one-off scratch and free
		// it at the end of this call so we don't leak.
		s, err := hyperscan.NewScratch(d.db)
		if err != nil {
			d.scanErrors.Add(1)
			return fmt.Errorf("hsmatch: alloc scratch: %w", err)
		}
		scratch = s
		releaseScratch = func() { _ = s.Free() }
	}
	defer releaseScratch()

	var cbErr error
	handler := func(id uint, from, to uint64, _ uint, _ any) error {
		d.matches.Add(1)
		if err := fn(Hit{ID: int(id), From: from, To: to}); err != nil {
			cbErr = err
			return err
		}
		return nil
	}

	if err := d.db.Scan(buf, scratch, handler, nil); err != nil {
		// gohs returns an error when the handler aborts; prefer the
		// caller's own error in that case rather than the wrapped libhs
		// "scan terminated" code.
		if cbErr != nil {
			return cbErr
		}
		d.scanErrors.Add(1)
		return fmt.Errorf("hsmatch: scan: %w", err)
	}
	return cbErr
}

// Stats returns a snapshot of runtime counters.
func (d *DB) Stats() Stats {
	if d == nil {
		return Stats{}
	}
	return Stats{
		Patterns:   d.patterns,
		Rejections: d.rejections,
		Matches:    d.matches.Load(),
		Scans:      d.scans.Load(),
		ScanErrors: d.scanErrors.Load(),
	}
}

// Close releases the underlying database, prototype scratch and every
// cloned scratch ever produced by the pool.
//
// After Close the DB is unusable; subsequent [DB.Match] calls return
// [ErrClosed]. Close is safe to call multiple times.
func (d *DB) Close() error {
	if d == nil {
		return nil
	}
	if !d.closed.CompareAndSwap(false, true) {
		return nil
	}

	// Free every tracked scratch first; the pool may still reference some
	// of them but the items are no longer reachable through Match because
	// closed=true short-circuits before pool.Get.
	d.scratchMu.Lock()
	for _, s := range d.scratches {
		_ = s.Free()
	}
	d.scratches = nil
	d.scratchMu.Unlock()

	if d.proto != nil {
		_ = d.proto.Free()
		d.proto = nil
	}

	var firstErr error
	if d.db != nil {
		if err := d.db.Close(); err != nil {
			firstErr = fmt.Errorf("hsmatch: close database: %w", err)
		}
		d.db = nil
	}
	return firstErr
}
