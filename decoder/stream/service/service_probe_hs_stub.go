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

package service

import "github.com/dreadl0ck/netcap/internal/hsmatch"

func init() {
	// Register even in stub builds so the web UI can render a clear
	// "disabled" badge for this subsystem instead of an empty section.
	hsmatch.RegisterSubsystem(hsmatch.SubsystemFunc{
		N: "service_probes",
		F: func() any { return GetHyperscanStatus() },
	})
}

// HyperscanBuildStats is the stub-build twin of the tagged type.
type HyperscanBuildStats struct {
	Categories     int `json:"categories"`
	PatternsTotal  int `json:"patterns_total"`
	PatternsHS     int `json:"patterns_hyperscan"`
	PatternsFallbk int `json:"patterns_fallback"`
}

// HyperscanCategory is the stub-build twin of the tagged type.
type HyperscanCategory struct {
	Name        string `json:"name"`
	Patterns    int    `json:"patterns"`
	Rejections  int    `json:"rejections"`
	Matches     uint64 `json:"matches"`
	Scans       uint64 `json:"scans"`
	ScanErrors  uint64 `json:"scan_errors"`
	SampleError string `json:"sample_error,omitempty"`
}

// HyperscanStatus is the stub-build twin of the tagged type.
type HyperscanStatus struct {
	Enabled       bool                `json:"enabled"`
	LibVersion    string              `json:"lib_version"`
	Build         HyperscanBuildStats `json:"build"`
	BuildError    string              `json:"build_error,omitempty"`
	ScanFallbacks uint64              `json:"scan_fallbacks"`
	Categories    []HyperscanCategory `json:"categories,omitempty"`
}

// buildServiceProbeHSIndex is a no-op without the hyperscan build tag.
func buildServiceProbeHSIndex() {}

// hsCandidatesForCategory returns nil so matchProbes falls back to the
// linear RE2/regexp2 scan over all probes.
//
// Returning nil (rather than an empty map) is meaningful: matchProbes treats
// a nil map as "no prefilter available" and skips the membership check.
func hsCandidatesForCategory(_ string, _ []*serviceProbe, _ []byte) map[int]struct{} {
	return nil
}

// GetHyperscanStatus reports the integration as compiled-out so UI surfaces
// can render a clear "disabled" badge instead of guessing.
func GetHyperscanStatus() HyperscanStatus {
	return HyperscanStatus{Enabled: false, LibVersion: "disabled"}
}
