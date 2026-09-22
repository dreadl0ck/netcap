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

package software

import "github.com/dreadl0ck/netcap/internal/hsmatch"

// CMSHyperscanBuildStats describes the outcome of buildCMSHSIndex.
//
// Re-exported in stub builds so the web UI handler can render the same
// schema regardless of how netcap was compiled.
type CMSHyperscanBuildStats struct {
	HeaderPatterns          int `json:"header_patterns"`
	HeaderRejections        int `json:"header_rejections"`
	CookiePatterns          int `json:"cookie_patterns"`
	CookieRejections        int `json:"cookie_rejections"`
	HeaderProductCandidates int `json:"header_product_candidates"`
	CookieProductCandidates int `json:"cookie_product_candidates"`
}

// CMSHyperscanStatus is the JSON-friendly snapshot of the CMS Hyperscan
// integration. In stub builds, Enabled is false and counters are zero.
type CMSHyperscanStatus struct {
	Enabled       bool                   `json:"enabled"`
	LibVersion    string                 `json:"lib_version"`
	Build         CMSHyperscanBuildStats `json:"build"`
	BuildError    string                 `json:"build_error,omitempty"`
	HeaderScans   uint64                 `json:"header_scans"`
	HeaderMatches uint64                 `json:"header_matches"`
	HeaderErrors  uint64                 `json:"header_errors"`
	CookieScans   uint64                 `json:"cookie_scans"`
	CookieMatches uint64                 `json:"cookie_matches"`
	CookieErrors  uint64                 `json:"cookie_errors"`
	ScanFallbacks uint64                 `json:"scan_fallbacks"`
}

// buildCMSHSIndex is a no-op in stub builds.
func buildCMSHSIndex() {}

// cmsHeaderCandidates returns nil so callers fall back to the full nested
// loop. Returning nil (rather than an empty map) is deliberate – the
// caller distinguishes "no prefilter available" from "prefilter says no
// product matches".
func cmsHeaderCandidates(_ string, _ string) map[string]struct{} { return nil }

// cmsCookieCandidates is the cookie twin of cmsHeaderCandidates.
func cmsCookieCandidates(_ string, _ string) map[string]struct{} { return nil }

// GetCMSHyperscanStatus returns a "disabled" snapshot.
func GetCMSHyperscanStatus() CMSHyperscanStatus {
	return CMSHyperscanStatus{Enabled: false, LibVersion: "disabled"}
}

func init() {
	// Self-register even in stub builds so the web UI can render a
	// "disabled" badge for this subsystem.
	hsmatch.RegisterSubsystem(hsmatch.SubsystemFunc{
		N: "cms",
		F: func() any { return GetCMSHyperscanStatus() },
	})
}
