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

package software

import (
	"sort"
	"strings"
	"sync"
	"sync/atomic"

	"go.uber.org/zap"

	"github.com/dreadl0ck/netcap/internal/hsmatch"
)

// CMSHyperscanBuildStats describes the outcome of buildCMSHSIndex.
type CMSHyperscanBuildStats struct {
	// HeaderPatterns is the number of header-value regexes Hyperscan
	// successfully compiled.
	HeaderPatterns int `json:"header_patterns"`
	// HeaderRejections is the number of header-value regexes Hyperscan
	// refused (kept on the RE2 fall-back path).
	HeaderRejections int `json:"header_rejections"`
	// CookiePatterns / CookieRejections mirror the above for cookies.
	CookiePatterns   int `json:"cookie_patterns"`
	CookieRejections int `json:"cookie_rejections"`

	// HeaderProductCandidates is the number of distinct (product, header
	// name) tuples covered by the HS DB. Useful for sanity-checking the
	// index against the cmsDB size.
	HeaderProductCandidates int `json:"header_product_candidates"`
	CookieProductCandidates int `json:"cookie_product_candidates"`
}

// CMSHyperscanStatus is the JSON-friendly snapshot exposed via
// /api/hyperscan and the cross-subsystem hsmatch registry.
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

// cmsCandidate is the resolver entry pointed to by an HS pattern ID.
type cmsCandidate struct {
	product    string
	headerName string // lower-cased for cheap EqualFold equivalent
}

type cmsHSDB struct {
	db *hsmatch.DB
	// patternRefs[id] -> (product, headerName)
	patternRefs []cmsCandidate
	// byHeader[lower(headerName)] -> set of products to expand candidate
	// sets for raw header-name matches that did not require regex.
	byHeader map[string]map[string]struct{}
}

var (
	cmsHeaderHSDB atomic.Pointer[cmsHSDB]
	cmsCookieHSDB atomic.Pointer[cmsHSDB]

	cmsBuildErr   atomic.Pointer[string]
	cmsBuildStats atomic.Pointer[CMSHyperscanBuildStats]

	cmsHeaderScans   atomic.Uint64
	cmsHeaderMatches atomic.Uint64
	cmsHeaderErrors  atomic.Uint64
	cmsCookieScans   atomic.Uint64
	cmsCookieMatches atomic.Uint64
	cmsCookieErrors  atomic.Uint64
	cmsScanFallbacks atomic.Uint64

	cmsBuildOnce sync.Mutex
)

// buildCMSHSIndex compiles the per-source (headers / cookies) Hyperscan
// databases out of the cmsDB regexes that were just loaded by loadCmsDB.
//
// Patterns Hyperscan rejects (e.g. backreferences) stay on the existing
// linear loop: the candidate-set returned by [cmsHeaderCandidates] /
// [cmsCookieCandidates] always includes those products so the regex is
// still evaluated for them.
func buildCMSHSIndex() {
	cmsBuildOnce.Lock()
	defer cmsBuildOnce.Unlock()

	// Free any previously built DB (initialiser may run more than once
	// across PCAPs in service mode).
	if old := cmsHeaderHSDB.Load(); old != nil && old.db != nil {
		_ = old.db.Close()
	}
	if old := cmsCookieHSDB.Load(); old != nil && old.db != nil {
		_ = old.db.Close()
	}

	headerDB, headerStats, headerErr := buildCMSGroup(true)
	cookieDB, cookieStats, cookieErr := buildCMSGroup(false)

	stats := CMSHyperscanBuildStats{
		HeaderPatterns:          headerStats.compiled,
		HeaderRejections:        headerStats.rejected,
		HeaderProductCandidates: headerStats.refs,
		CookiePatterns:          cookieStats.compiled,
		CookieRejections:        cookieStats.rejected,
		CookieProductCandidates: cookieStats.refs,
	}
	cmsBuildStats.Store(&stats)

	cmsHeaderHSDB.Store(headerDB)
	cmsCookieHSDB.Store(cookieDB)

	switch {
	case headerErr != nil && cookieErr != nil:
		joined := "headers: " + headerErr.Error() + "; cookies: " + cookieErr.Error()
		cmsBuildErr.Store(&joined)
	case headerErr != nil:
		s := "headers: " + headerErr.Error()
		cmsBuildErr.Store(&s)
	case cookieErr != nil:
		s := "cookies: " + cookieErr.Error()
		cmsBuildErr.Store(&s)
	default:
		cmsBuildErr.Store(nil)
	}

	if softwareLog != nil {
		softwareLog.Info("hyperscan: CMS index built",
			zap.String("libhs_version", hsmatch.Version()),
			zap.Int("header_patterns", stats.HeaderPatterns),
			zap.Int("header_rejections", stats.HeaderRejections),
			zap.Int("header_product_candidates", stats.HeaderProductCandidates),
			zap.Int("cookie_patterns", stats.CookiePatterns),
			zap.Int("cookie_rejections", stats.CookieRejections),
			zap.Int("cookie_product_candidates", stats.CookieProductCandidates),
		)
	}
}

type cmsGroupBuildStats struct {
	compiled int
	rejected int
	refs     int
}

// buildCMSGroup compiles either the header or cookie regexes from the
// loaded cmsDB into a single block-mode database.
func buildCMSGroup(headers bool) (*cmsHSDB, cmsGroupBuildStats, error) {
	var stats cmsGroupBuildStats

	// Iterate cmsDB in deterministic order so HS pattern IDs remain
	// reproducible across runs (helpful for debugging).
	products := make([]string, 0, len(cmsDB))
	for p := range cmsDB {
		products = append(products, p)
	}
	sort.Strings(products)

	patterns := make([]hsmatch.Pattern, 0, 64)
	refs := make([]cmsCandidate, 0, 64)
	byHeader := make(map[string]map[string]struct{}, 32)

	for _, product := range products {
		info := cmsDB[product]
		var src map[string]uniqueRegex
		if headers {
			src = collectFromHeaders(info)
		} else {
			src = collectFromCookies(info)
		}
		for headerName, ur := range src {
			lower := strings.ToLower(headerName)
			set, ok := byHeader[lower]
			if !ok {
				set = make(map[string]struct{})
				byHeader[lower] = set
			}
			set[product] = struct{}{}

			if ur.expr == "" {
				// header-name-only match, no value regex – no HS work.
				continue
			}

			patterns = append(patterns, hsmatch.Pattern{
				ID:    len(refs),
				Expr:  ur.expr,
				Flags: hsmatch.FlagSingleMatch,
			})
			refs = append(refs, cmsCandidate{product: product, headerName: lower})
		}
	}

	stats.refs = len(refs)
	if len(patterns) == 0 {
		return &cmsHSDB{patternRefs: refs, byHeader: byHeader}, stats, nil
	}

	db, rejections, err := hsmatch.Compile(patterns)
	stats.rejected = len(rejections)
	stats.compiled = len(patterns) - len(rejections)
	if err != nil {
		return &cmsHSDB{patternRefs: refs, byHeader: byHeader}, stats, err
	}

	if softwareLog != nil {
		for _, r := range rejections {
			expr := r.Expr
			if len(expr) > 200 {
				expr = expr[:200] + "...(truncated)"
			}
			source := "cookie"
			if headers {
				source = "header"
			}
			softwareLog.Debug("hyperscan: CMS pattern rejected (kept on RE2 path)",
				zap.String("source", source),
				zap.Int("pattern_index", r.Index),
				zap.String("reason", r.Reason),
				zap.String("expr", expr),
			)
		}
	}

	return &cmsHSDB{db: db, patternRefs: refs, byHeader: byHeader}, stats, nil
}

// uniqueRegex pairs the regex source string with a flag for "name-only"
// (re == nil) entries. We don't carry the *regexp.Regexp here because the
// HS DB rebuilds compile from the source string; the existing cmsDB
// retains the *regexp.Regexp for the RE2 fall-back path.
type uniqueRegex struct {
	expr string
}

func collectFromHeaders(info *cmsInfo) map[string]uniqueRegex {
	if info == nil || len(info.Headers) == 0 {
		return nil
	}
	out := make(map[string]uniqueRegex, len(info.Headers))
	for name, re := range info.Headers {
		var expr string
		if re != nil {
			expr = re.String()
		}
		out[name] = uniqueRegex{expr: expr}
	}
	return out
}

func collectFromCookies(info *cmsInfo) map[string]uniqueRegex {
	if info == nil || len(info.Cookies) == 0 {
		return nil
	}
	out := make(map[string]uniqueRegex, len(info.Cookies))
	for name, re := range info.Cookies {
		var expr string
		if re != nil {
			expr = re.String()
		}
		out[name] = uniqueRegex{expr: expr}
	}
	return out
}

// cmsHeaderCandidates returns the set of product names that *could*
// match the given (headerName, headerValue) pair according to the
// Hyperscan prefilter.
//
// Membership is the union of:
//   - products registered via this header name with no value regex,
//   - products whose value regex Hyperscan flagged on `value`.
//
// Returning nil disables the prefilter (caller does the full cmsDB sweep).
// Returning an empty map means "HS examined every covered product and
// none matched" — the caller's nested loop will then iterate but skip
// every entry, which is the desired fast-path outcome on miss.
func cmsHeaderCandidates(headerName, value string) map[string]struct{} {
	return cmsCandidatesFor(cmsHeaderHSDB.Load(), headerName, value, true)
}

// cmsCookieCandidates is the cookie twin of cmsHeaderCandidates.
func cmsCookieCandidates(cookieName, value string) map[string]struct{} {
	return cmsCandidatesFor(cmsCookieHSDB.Load(), cookieName, value, false)
}

func cmsCandidatesFor(idx *cmsHSDB, name, value string, headers bool) map[string]struct{} {
	if idx == nil {
		return nil
	}
	lower := strings.ToLower(name)

	cand := make(map[string]struct{}, 4)

	// Products registered through this header name with NO value regex
	// always need to be evaluated — the existing matcher treats those as
	// pure name-equality matches.
	if set, ok := idx.byHeader[lower]; ok {
		for p := range set {
			cand[p] = struct{}{}
		}
	}

	if idx.db == nil || value == "" {
		return cand
	}

	if headers {
		cmsHeaderScans.Add(1)
	} else {
		cmsCookieScans.Add(1)
	}

	err := idx.db.Match([]byte(value), func(h hsmatch.Hit) error {
		if h.ID < 0 || h.ID >= len(idx.patternRefs) {
			return nil
		}
		ref := idx.patternRefs[h.ID]
		// Filter by header name: only the regex whose registered name
		// matches this header is a real candidate. Other products
		// registered the same regex under a *different* header name
		// remain irrelevant.
		if ref.headerName != lower {
			return nil
		}
		if headers {
			cmsHeaderMatches.Add(1)
		} else {
			cmsCookieMatches.Add(1)
		}
		cand[ref.product] = struct{}{}
		return nil
	})
	if err != nil {
		cmsScanFallbacks.Add(1)
		if headers {
			cmsHeaderErrors.Add(1)
		} else {
			cmsCookieErrors.Add(1)
		}
		if softwareLog != nil {
			softwareLog.Warn("hyperscan: CMS scan failed, falling back to full nested loop",
				zap.String("name", name),
				zap.Int("value_bytes", len(value)),
				zap.Bool("headers", headers),
				zap.Error(err),
			)
		}
		return nil
	}
	return cand
}

// GetCMSHyperscanStatus returns a JSON-friendly snapshot.
func GetCMSHyperscanStatus() CMSHyperscanStatus {
	st := CMSHyperscanStatus{
		Enabled:       hsmatch.Enabled,
		LibVersion:    hsmatch.Version(),
		HeaderScans:   cmsHeaderScans.Load(),
		HeaderMatches: cmsHeaderMatches.Load(),
		HeaderErrors:  cmsHeaderErrors.Load(),
		CookieScans:   cmsCookieScans.Load(),
		CookieMatches: cmsCookieMatches.Load(),
		CookieErrors:  cmsCookieErrors.Load(),
		ScanFallbacks: cmsScanFallbacks.Load(),
	}
	if bs := cmsBuildStats.Load(); bs != nil {
		st.Build = *bs
	}
	if be := cmsBuildErr.Load(); be != nil {
		st.BuildError = *be
	}
	return st
}

func init() {
	hsmatch.RegisterSubsystem(hsmatch.SubsystemFunc{
		N: "cms",
		F: func() any { return GetCMSHyperscanStatus() },
	})
}
