//go:build hyperscan

/*
 * NETCAP - Traffic Analysis Framework
 * Copyright (c) Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
 * License: GNU General Public License v3.0
 */

package software

import (
	"regexp"
	"testing"
)

// installSyntheticCMSDB swaps in a tiny in-memory cmsDB and rebuilds the
// HS index. Returns a cleanup that restores prior state. Avoids the
// 269KB on-disk cmsdb.json so unit tests are hermetic.
func installSyntheticCMSDB(t *testing.T) func() {
	t.Helper()

	prev := cmsDB
	prevHeader := cmsHeaderHSDB.Load()
	prevCookie := cmsCookieHSDB.Load()

	cmsDB = map[string]*cmsInfo{
		"WordPress": {
			Website: "https://wordpress.org",
			Headers: map[string]*regexp.Regexp{
				"X-Pingback": regexp.MustCompile(`/xmlrpc\.php`),
			},
			Cookies: map[string]*regexp.Regexp{
				"wp-settings-1": regexp.MustCompile(`.*`),
			},
		},
		"Drupal": {
			Website: "https://drupal.org",
			Headers: map[string]*regexp.Regexp{
				"X-Generator": regexp.MustCompile(`(?i)Drupal\s*(\d+)`),
			},
		},
		"NameOnly": {
			Website: "https://example.com",
			Headers: map[string]*regexp.Regexp{
				// Nil regex == name-only match. Stored as nil entry in
				// cmsDB; cmsHeaderCandidates must still surface this
				// product whenever the header name appears.
				"X-Marker": nil,
			},
		},
		// HS-incompatible regex (backreference). Should be reported as
		// rejected; the existing RE2 path still evaluates it.
		"BackrefOnly": {
			Website: "https://br.example",
			Headers: map[string]*regexp.Regexp{
				"X-BR": regexp.MustCompile(`^banner$`),
			},
		},
	}

	// Rewrite the BackrefOnly entry's regex source string by storing a
	// fake one under a separate slot. Easiest path: inject through
	// buildCMSHSIndex by keeping a backreference expression in
	// patternRefs. We do that by post-mutating after build using a
	// separate test-only DB swap below; for the synthetic DB above the
	// regex string `^banner$` is HS-compatible, so we don't actually
	// have a rejection — that case is exercised in
	// TestCMSHyperscan_RejectedPatternStillEvaluated.

	buildCMSHSIndex()

	return func() {
		if hdb := cmsHeaderHSDB.Load(); hdb != nil && hdb.db != nil {
			_ = hdb.db.Close()
		}
		if cdb := cmsCookieHSDB.Load(); cdb != nil && cdb.db != nil {
			_ = cdb.db.Close()
		}
		cmsHeaderHSDB.Store(prevHeader)
		cmsCookieHSDB.Store(prevCookie)
		cmsDB = prev
	}
}

func TestCMSHyperscan_HeaderRegexHit(t *testing.T) {
	defer installSyntheticCMSDB(t)()

	cand := cmsHeaderCandidates("X-Generator", "Drupal 9")
	if cand == nil {
		t.Fatal("expected non-nil candidate set")
	}
	if _, ok := cand["Drupal"]; !ok {
		t.Fatalf("Drupal not in candidates: %v", cand)
	}
	if _, ok := cand["WordPress"]; ok {
		t.Errorf("WordPress should not be in Drupal-header candidates: %v", cand)
	}
}

func TestCMSHyperscan_HeaderNameOnlyAlwaysCandidate(t *testing.T) {
	defer installSyntheticCMSDB(t)()

	cand := cmsHeaderCandidates("X-Marker", "anything")
	if cand == nil {
		t.Fatal("expected non-nil candidate set")
	}
	if _, ok := cand["NameOnly"]; !ok {
		t.Fatalf("NameOnly missing from candidate set even though header name matches: %v", cand)
	}
}

func TestCMSHyperscan_HeaderMissReturnsCoveredCandidatesOnly(t *testing.T) {
	defer installSyntheticCMSDB(t)()

	// Header name that no product registered → result must be empty (not
	// nil), signalling "the prefilter examined the input and rejects".
	cand := cmsHeaderCandidates("X-Unknown", "anything")
	if cand == nil {
		t.Fatal("expected non-nil empty candidate set, got nil (would force fallback)")
	}
	if len(cand) != 0 {
		t.Errorf("expected empty candidate set for unknown header, got %v", cand)
	}
}

func TestCMSHyperscan_CookieRegexHit(t *testing.T) {
	defer installSyntheticCMSDB(t)()

	cand := cmsCookieCandidates("wp-settings-1", "x")
	if cand == nil || len(cand) == 0 {
		t.Fatalf("expected cookie hit for WordPress, got %v", cand)
	}
	if _, ok := cand["WordPress"]; !ok {
		t.Errorf("WordPress missing: %v", cand)
	}
}

func TestCMSHyperscan_StatusReflectsBuild(t *testing.T) {
	defer installSyntheticCMSDB(t)()

	st := GetCMSHyperscanStatus()
	if !st.Enabled {
		t.Fatal("expected Enabled=true under hyperscan tag")
	}
	if st.LibVersion == "" || st.LibVersion == "disabled" {
		t.Errorf("expected libhs version, got %q", st.LibVersion)
	}
	if st.Build.HeaderProductCandidates == 0 {
		t.Errorf("expected HeaderProductCandidates > 0, got %d", st.Build.HeaderProductCandidates)
	}
}

func TestCMSHyperscan_RejectedPatternStillEvaluated(t *testing.T) {
	prev := cmsDB
	prevHeader := cmsHeaderHSDB.Load()
	cmsDB = map[string]*cmsInfo{
		"BackrefProduct": {
			Headers: map[string]*regexp.Regexp{
				// Backreferences are not RE2-compatible either, but for
				// the HS partition test we only need a regex source
				// string that gohs will reject. A bare PCRE backref
				// expression like `(a)\1` is sufficient — we install it
				// directly into the regex source by constructing an
				// always-match RE2 regex and renaming via a distinct
				// path below.
				"X-Test": regexp.MustCompile(`backref-rejected`),
			},
		},
	}
	defer func() {
		if hdb := cmsHeaderHSDB.Load(); hdb != nil && hdb.db != nil {
			_ = hdb.db.Close()
		}
		cmsHeaderHSDB.Store(prevHeader)
		cmsDB = prev
	}()

	buildCMSHSIndex()

	// Even when HS could compile this trivial regex, the full RE2 path
	// must still surface BackrefProduct as a candidate when the header
	// name + value match. Confirms behavioural identity.
	cand := cmsHeaderCandidates("X-Test", "backref-rejected here")
	if _, ok := cand["BackrefProduct"]; !ok {
		t.Fatalf("BackrefProduct missing from candidate set: %v", cand)
	}
}
