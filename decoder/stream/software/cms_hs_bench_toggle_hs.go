//go:build hyperscan

/*
 * NETCAP - Traffic Analysis Framework
 * Copyright (c) Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
 * License: GNU General Public License v3.0
 */

package software

import "testing"

// resetCMSHSIndexForBench (re)builds or clears the per-source CMS HS
// indices so a single benchmark binary can A/B compare the HS prefilter
// against the fall-back nested-loop without rebuilding.
//
//   - want == true  → rebuild from the currently loaded cmsDB.
//   - want == false → clear so cmsHeaderCandidates / cmsCookieCandidates
//     return nil and generateSoftware iterates the whole cmsDB.
func resetCMSHSIndexForBench(tb testing.TB, want bool) {
	tb.Helper()

	if !want {
		if hdb := cmsHeaderHSDB.Load(); hdb != nil && hdb.db != nil {
			_ = hdb.db.Close()
		}
		if cdb := cmsCookieHSDB.Load(); cdb != nil && cdb.db != nil {
			_ = cdb.db.Close()
		}
		cmsHeaderHSDB.Store(nil)
		cmsCookieHSDB.Store(nil)
		return
	}

	buildCMSHSIndex()
}
