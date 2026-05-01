//go:build hyperscan

/*
 * NETCAP - Traffic Analysis Framework
 * Copyright (c) Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
 * License: GNU General Public License v3.0
 */

package service

import "testing"

// resetServiceProbeHSIndexForBench (re)builds or clears the per-category
// Hyperscan index so a single benchmark binary can compare the HS path
// against a runtime-disabled fall-back path without rebuilding.
//
//   - want == true  → build (or rebuild) the HS index from the currently
//     loaded serviceProbes.
//   - want == false → free the index and replace it with an empty map so
//     hsCandidatesForCategory always returns nil → matchProbes runs the
//     pure RE2 path.
//
// Available only in tagged builds; the stub-build twin is a no-op.
func resetServiceProbeHSIndexForBench(tb testing.TB, want bool) {
	tb.Helper()

	if !want {
		serviceProbeHSIndexMu.Lock()
		for _, c := range serviceProbeHSIndex {
			_ = c.db.Close()
		}
		serviceProbeHSIndex = make(map[string]*serviceProbeHSCategory)
		serviceProbeHSIndexMu.Unlock()
		return
	}

	buildServiceProbeHSIndex()
}
