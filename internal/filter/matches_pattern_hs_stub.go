//go:build !hyperscan

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

import "github.com/dreadl0ck/netcap/internal/hsmatch"

// FilterHyperscanStatus mirrors the tagged-build type so the web UI
// handler renders the same JSON schema in both build configurations.
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

// hsMatchesPatternPrecheck always reports "no decision" in stub builds,
// so MatchesPattern falls through to the existing RE2 path.
func hsMatchesPatternPrecheck(_ string, _ string) (matched, decided bool) {
	return false, false
}

// GetFilterHyperscanStatus reports a "disabled" snapshot.
func GetFilterHyperscanStatus() FilterHyperscanStatus {
	return FilterHyperscanStatus{Enabled: false, LibVersion: "disabled"}
}

func init() {
	// Self-register even in stub builds so the web UI can render a
	// "disabled" badge for this subsystem.
	hsmatch.RegisterSubsystem(hsmatch.SubsystemFunc{
		N: "filter_matches_pattern",
		F: func() any { return GetFilterHyperscanStatus() },
	})
}
