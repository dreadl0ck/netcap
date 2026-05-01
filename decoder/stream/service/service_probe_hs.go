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

package service

import (
	"sort"
	"sync"
	"sync/atomic"

	"go.uber.org/zap"

	decoderconfig "github.com/dreadl0ck/netcap/decoder/config"
	"github.com/dreadl0ck/netcap/internal/hsmatch"
)

// serviceProbeHSCategory holds the compiled Hyperscan database for one
// probe category and the set of probe indices that the database covers.
// Probe indices NOT in `supported` are kept on the linear RE2 path.
type serviceProbeHSCategory struct {
	db        *hsmatch.DB
	supported map[int]struct{}

	// rejections lists patterns Hyperscan refused to compile, with reason.
	// Surfaced through HyperscanStatus so the web UI can show why a probe
	// was excluded.
	rejections []hsmatch.Rejection
}

var (
	serviceProbeHSIndex   = make(map[string]*serviceProbeHSCategory)
	serviceProbeHSIndexMu sync.RWMutex

	// scanFallbacks counts how often a Hyperscan scan failed and the
	// caller had to fall back to the linear RE2 loop. Surfaced via
	// HyperscanStatus.
	hsScanFallbacks atomic.Uint64

	// build state captured at probe-load time so /api/system can render it.
	hsLastBuildErr   atomic.Pointer[string]
	hsLastBuildStats atomic.Pointer[HyperscanBuildStats]
)

// HyperscanBuildStats summarises the outcome of buildServiceProbeHSIndex.
type HyperscanBuildStats struct {
	Categories     int `json:"categories"`
	PatternsTotal  int `json:"patterns_total"`
	PatternsHS     int `json:"patterns_hyperscan"`
	PatternsFallbk int `json:"patterns_fallback"`
}

// buildServiceProbeHSIndex compiles a per-category Hyperscan block-mode
// database from the regex of every probe in serviceProbes. Probes whose
// regex Hyperscan rejects (e.g. unsupported PCRE features) are skipped –
// they will continue to be evaluated by the linear RE2 loop.
//
// Only meaningful for the RE2 engine path (UseRE2=true). The .NET-backed
// regexp2 path keeps backreferences / lookaround that Hyperscan does not
// support, so we leave it untouched.
func buildServiceProbeHSIndex() {
	if !decoderconfig.Instance.UseRE2 {
		serviceLog.Info("hyperscan: skipping index build (UseRE2=false; .NET regex engine in use)")
		hsLastBuildErr.Store(nil)
		hsLastBuildStats.Store(&HyperscanBuildStats{})
		return
	}

	serviceProbeHSIndexMu.Lock()
	defer serviceProbeHSIndexMu.Unlock()

	// Reset any previously-built state (initServiceProbes can be called
	// repeatedly across processed PCAPs). Close every DB so the underlying
	// scratches and libhs allocations are freed.
	for cat, entry := range serviceProbeHSIndex {
		if err := entry.db.Close(); err != nil {
			serviceLog.Warn("hyperscan: error closing previous category database",
				zap.String("category", cat),
				zap.Error(err),
			)
		}
	}
	serviceProbeHSIndex = make(map[string]*serviceProbeHSCategory, len(serviceProbes))

	var (
		stats          HyperscanBuildStats
		buildErrors    []string
		totalAttempted int
	)

	// Iterate categories in deterministic order so logs are reproducible
	// across runs (Go map iteration is random).
	cats := make([]string, 0, len(serviceProbes))
	for c := range serviceProbes {
		cats = append(cats, c)
	}
	sort.Strings(cats)

	for _, category := range cats {
		probes := serviceProbes[category]
		if len(probes) == 0 {
			continue
		}

		patterns := make([]hsmatch.Pattern, 0, len(probes))
		for i, p := range probes {
			if p.RegEx == nil || p.RegExRaw == "" {
				continue
			}
			patterns = append(patterns, hsmatch.Pattern{
				ID:    i,
				Expr:  p.RegExRaw,
				Flags: hsmatch.FlagSingleMatch,
			})
		}
		if len(patterns) == 0 {
			continue
		}
		totalAttempted += len(patterns)

		db, rejections, err := hsmatch.Compile(patterns)
		if err != nil {
			msg := "hyperscan: compile failed for category, falling back to RE2 for entire category"
			buildErrors = append(buildErrors, category+": "+err.Error())
			serviceLog.Warn(msg,
				zap.String("category", category),
				zap.Int("patterns", len(patterns)),
				zap.Error(err),
			)
			stats.PatternsFallbk += len(patterns)
			continue
		}

		// Log every rejected pattern at Debug level so users can investigate
		// without flooding default logs. Aggregate counts go to Info.
		for _, r := range rejections {
			expr := r.Expr
			if len(expr) > 200 {
				expr = expr[:200] + "...(truncated)"
			}
			serviceLog.Debug("hyperscan: pattern rejected (kept on RE2 path)",
				zap.String("category", category),
				zap.Int("probe_index", r.Index),
				zap.String("reason", r.Reason),
				zap.String("expr", expr),
			)
		}

		if db == nil {
			// Every pattern in this category was rejected.
			serviceLog.Info("hyperscan: all patterns in category rejected, full RE2 fallback",
				zap.String("category", category),
				zap.Int("patterns", len(patterns)),
			)
			stats.PatternsFallbk += len(patterns)
			continue
		}

		supported := make(map[int]struct{}, len(patterns)-len(rejections))
		rejectedSlots := make(map[int]struct{}, len(rejections))
		for _, r := range rejections {
			rejectedSlots[r.Index] = struct{}{}
		}
		for slot, pat := range patterns {
			if _, skip := rejectedSlots[slot]; skip {
				continue
			}
			supported[pat.ID] = struct{}{}
		}

		serviceProbeHSIndex[category] = &serviceProbeHSCategory{
			db:         db,
			supported:  supported,
			rejections: rejections,
		}
		stats.Categories++
		stats.PatternsHS += len(supported)
		stats.PatternsFallbk += len(rejections)
	}

	stats.PatternsTotal = totalAttempted
	hsLastBuildStats.Store(&stats)

	if len(buildErrors) > 0 {
		joined := joinFirst(buildErrors, 5)
		hsLastBuildErr.Store(&joined)
	} else {
		hsLastBuildErr.Store(nil)
	}

	serviceLog.Info("hyperscan: probe index built",
		zap.String("libhs_version", hsmatch.Version()),
		zap.Int("categories", stats.Categories),
		zap.Int("patterns_total", stats.PatternsTotal),
		zap.Int("patterns_hyperscan", stats.PatternsHS),
		zap.Int("patterns_fallback", stats.PatternsFallbk),
		zap.Int("category_build_errors", len(buildErrors)),
	)
}

// hsCandidatesForCategory consults the Hyperscan index for the named
// category and returns the union of:
//   - probe indices that fired in HS, AND
//   - probe indices that were never registered with HS (so we don't drop
//     them from evaluation).
//
// Returning nil disables the prefilter (caller falls back to the full
// linear scan). Returning an empty map means "HS examined every probe and
// none matched"; the caller will then iterate but skip every entry, which
// is the desired fast-path outcome on miss.
func hsCandidatesForCategory(category string, probes []*serviceProbe, banner []byte) map[int]struct{} {
	if !decoderconfig.Instance.UseRE2 || category == "" || len(probes) == 0 || len(banner) == 0 {
		return nil
	}

	serviceProbeHSIndexMu.RLock()
	cat, ok := serviceProbeHSIndex[category]
	serviceProbeHSIndexMu.RUnlock()
	if !ok || cat == nil {
		return nil
	}

	// Pre-seed candidates with all probes the HS DB does NOT cover so they
	// stay in the linear loop. For covered probes we add only HS hits.
	cand := make(map[int]struct{}, 8)
	for i := range probes {
		if _, covered := cat.supported[i]; !covered {
			cand[i] = struct{}{}
		}
	}

	if err := cat.db.Match(banner, func(h hsmatch.Hit) error {
		if h.ID >= 0 && h.ID < len(probes) {
			cand[h.ID] = struct{}{}
		}
		return nil
	}); err != nil {
		// Surface the failure: bump a counter (visible via /api/system) and
		// log at Warn so operators see it without enabling Debug. Caller
		// gets nil and will perform the safe full linear scan.
		hsScanFallbacks.Add(1)
		serviceLog.Warn("hyperscan: scan failed, falling back to linear RE2",
			zap.String("category", category),
			zap.Int("banner_bytes", len(banner)),
			zap.Error(err),
		)
		return nil
	}

	return cand
}

// HyperscanStatus is a snapshot of the Hyperscan integration suitable for
// rendering in the web UI / system info page.
type HyperscanStatus struct {
	Enabled       bool                `json:"enabled"`
	LibVersion    string              `json:"lib_version"`
	Build         HyperscanBuildStats `json:"build"`
	BuildError    string              `json:"build_error,omitempty"`
	ScanFallbacks uint64              `json:"scan_fallbacks"`
	Categories    []HyperscanCategory `json:"categories,omitempty"`
}

// HyperscanCategory exposes per-category counters for monitoring.
type HyperscanCategory struct {
	Name        string `json:"name"`
	Patterns    int    `json:"patterns"`
	Rejections  int    `json:"rejections"`
	Matches     uint64 `json:"matches"`
	Scans       uint64 `json:"scans"`
	ScanErrors  uint64 `json:"scan_errors"`
	SampleError string `json:"sample_error,omitempty"`
}

// GetHyperscanStatus returns a JSON-friendly snapshot of the integration
// state. Safe to call from any goroutine.
func GetHyperscanStatus() HyperscanStatus {
	st := HyperscanStatus{
		Enabled:       hsmatch.Enabled,
		LibVersion:    hsmatch.Version(),
		ScanFallbacks: hsScanFallbacks.Load(),
	}
	if bs := hsLastBuildStats.Load(); bs != nil {
		st.Build = *bs
	}
	if be := hsLastBuildErr.Load(); be != nil {
		st.BuildError = *be
	}

	serviceProbeHSIndexMu.RLock()
	defer serviceProbeHSIndexMu.RUnlock()

	st.Categories = make([]HyperscanCategory, 0, len(serviceProbeHSIndex))
	cats := make([]string, 0, len(serviceProbeHSIndex))
	for c := range serviceProbeHSIndex {
		cats = append(cats, c)
	}
	sort.Strings(cats)
	for _, c := range cats {
		entry := serviceProbeHSIndex[c]
		s := entry.db.Stats()
		hc := HyperscanCategory{
			Name:       c,
			Patterns:   s.Patterns,
			Rejections: s.Rejections,
			Matches:    s.Matches,
			Scans:      s.Scans,
			ScanErrors: s.ScanErrors,
		}
		if len(entry.rejections) > 0 {
			// First rejection reason gives operators a quick clue about
			// why a probe set is partially on the fallback path.
			hc.SampleError = entry.rejections[0].Reason
		}
		st.Categories = append(st.Categories, hc)
	}
	return st
}

// joinFirst joins up to n strings of `lines` with "; " and appends a count
// suffix when truncated. Used to keep the UI build_error field bounded.
func joinFirst(lines []string, n int) string {
	if len(lines) == 0 {
		return ""
	}
	if len(lines) <= n {
		return joinSemi(lines)
	}
	out := joinSemi(lines[:n])
	return out + "; ... and more"
}

func joinSemi(lines []string) string {
	out := ""
	for i, l := range lines {
		if i > 0 {
			out += "; "
		}
		out += l
	}
	return out
}
