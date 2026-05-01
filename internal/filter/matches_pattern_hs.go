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

package filter

import (
	"sync"
	"sync/atomic"

	"github.com/dreadl0ck/netcap/internal/hsmatch"
)

// FilterHyperscanStatus is a JSON-friendly snapshot of the
// MatchesPattern Hyperscan acceleration layer.
type FilterHyperscanStatus struct {
	Enabled        bool   `json:"enabled"`
	LibVersion     string `json:"lib_version"`
	PatternsCached int    `json:"patterns_cached"`
	PatternsHS     int    `json:"patterns_hyperscan"`
	PatternsRE2    int    `json:"patterns_re2_only"`
	HSDecisions    uint64 `json:"hs_decisions"`
	HSEarlyExits   uint64 `json:"hs_early_exits"`
	HSScanErrors   uint64 `json:"hs_scan_errors"`
}

// hsPatternEntry is the cache entry for one user-supplied pattern.
//   - db != nil  → Hyperscan accepted the pattern; precheck is HS-backed.
//   - db == nil  → Hyperscan rejected the pattern; precheck cannot decide
//     and falls through to the legacy RE2 path.
type hsPatternEntry struct {
	db       *hsmatch.DB
	rejected bool
}

var (
	hsPatternCache sync.Map // pattern string -> *hsPatternEntry

	// Lazily updated counters surfaced via GetFilterHyperscanStatus.
	hsPatternsHS  atomic.Int64 // patterns successfully compiled by HS
	hsPatternsRE2 atomic.Int64 // patterns HS rejected (RE2-only path)
	hsDecisions   atomic.Uint64
	hsEarlyExits  atomic.Uint64
	hsScanErrors  atomic.Uint64
)

// hsMatchesPatternPrecheck performs the optional Hyperscan-backed
// pre-check for MatchesPattern.
//
// Return semantics:
//   - decided == false: "no decision; caller must run the RE2 path".
//     Used for patterns Hyperscan refuses to compile, scan errors, or
//     until the per-pattern entry is built.
//   - decided == true && matched == false: HS proved no match exists.
//     Caller can return false directly without invoking RE2.
//   - decided == true && matched == true: HS reports a possible match.
//     Caller is expected to run RE2 to confirm exact semantics.
//
// HS is a superset filter: a "match event" implies an actual match for
// the patterns Hyperscan accepts (single-pattern block-mode DBs in
// particular). We still confirm via RE2 to preserve byte-for-byte
// identical behaviour with the legacy path in case of subtle edge
// cases (e.g. the RE2 subset rejects a pattern HS happily compiles,
// in which case both will agree on "no match" and the result stands).
func hsMatchesPatternPrecheck(str, pattern string) (matched, decided bool) {
	entry := getHSEntry(pattern)
	if entry == nil || entry.rejected || entry.db == nil {
		return false, false
	}

	hsDecisions.Add(1)

	var hit bool
	err := entry.db.Match([]byte(str), func(hsmatch.Hit) error {
		hit = true
		return errStopScan
	})
	if err != nil && err != errStopScan {
		hsScanErrors.Add(1)
		return false, false
	}

	if !hit {
		hsEarlyExits.Add(1)
		return false, true
	}
	return true, true
}

// errStopScan is returned from the Match handler to abort scanning as
// soon as the first hit is observed (we only care about the boolean).
var errStopScan = stopScanErr{}

type stopScanErr struct{}

func (stopScanErr) Error() string { return "stop" }

func getHSEntry(pattern string) *hsPatternEntry {
	if cached, ok := hsPatternCache.Load(pattern); ok {
		return cached.(*hsPatternEntry)
	}
	entry := buildHSEntry(pattern)
	if existing, loaded := hsPatternCache.LoadOrStore(pattern, entry); loaded {
		// Someone else built the entry first – release ours.
		if entry.db != nil {
			_ = entry.db.Close()
		}
		return existing.(*hsPatternEntry)
	}
	if entry.db != nil {
		hsPatternsHS.Add(1)
	} else {
		hsPatternsRE2.Add(1)
	}
	return entry
}

func buildHSEntry(pattern string) *hsPatternEntry {
	db, rejections, err := hsmatch.Compile([]hsmatch.Pattern{
		{ID: 0, Expr: pattern, Flags: hsmatch.FlagSingleMatch},
	})
	if err != nil || db == nil {
		// Either compile failed or HS rejected the only pattern.
		_ = rejections // already enumerated; nothing to surface here
		return &hsPatternEntry{rejected: true}
	}
	return &hsPatternEntry{db: db}
}

// GetFilterHyperscanStatus returns a snapshot for /api/hyperscan.
func GetFilterHyperscanStatus() FilterHyperscanStatus {
	cached := 0
	hsPatternCache.Range(func(_, _ any) bool { cached++; return true })
	return FilterHyperscanStatus{
		Enabled:        hsmatch.Enabled,
		LibVersion:     hsmatch.Version(),
		PatternsCached: cached,
		PatternsHS:     int(hsPatternsHS.Load()),
		PatternsRE2:    int(hsPatternsRE2.Load()),
		HSDecisions:    hsDecisions.Load(),
		HSEarlyExits:   hsEarlyExits.Load(),
		HSScanErrors:   hsScanErrors.Load(),
	}
}

func init() {
	hsmatch.RegisterSubsystem(hsmatch.SubsystemFunc{
		N: "filter_matches_pattern",
		F: func() any { return GetFilterHyperscanStatus() },
	})
}
