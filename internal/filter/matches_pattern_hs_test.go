//go:build hyperscan

/*
 * NETCAP - Traffic Analysis Framework
 * Copyright (c) Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
 * License: GNU General Public License v3.0
 */

package filter

import "testing"

func TestHSMatchesPatternPrecheck_DecidesOnSimplePattern(t *testing.T) {
	matched, decided := hsMatchesPatternPrecheck("hello world", `world`)
	if !decided {
		t.Fatal("expected HS to decide on a trivial literal pattern")
	}
	if !matched {
		t.Fatal("expected matched=true")
	}
}

func TestHSMatchesPatternPrecheck_NoMatchEarlyExit(t *testing.T) {
	matched, decided := hsMatchesPatternPrecheck("hello world", `nope`)
	if !decided {
		t.Fatal("expected HS to decide")
	}
	if matched {
		t.Fatal("expected matched=false")
	}
}

func TestHSMatchesPatternPrecheck_RejectedPatternNoDecision(t *testing.T) {
	// Backreference: gohs rejects, the function must return undecided
	// so the caller falls back to RE2.
	_, decided := hsMatchesPatternPrecheck("aa", `(a)\1`)
	if decided {
		t.Fatal("expected no decision for an HS-rejected pattern")
	}
}

func TestMatchesPattern_HSAndRE2Agree(t *testing.T) {
	cases := []struct {
		str, pattern string
		want         bool
	}{
		{"GET /admin/login HTTP/1.1", `(?i)/login`, true},
		{"GET /admin/login HTTP/1.1", `(?i)/auth`, false},
		{"User-Agent: nikto", `(?i)nikto`, true},
		{"normal traffic", `(?i)nikto`, false},
		{"' OR '1'='1", `(?i)or.*=`, true},
		{"https://example.com/wpad.dat", `(?i)wpad\.dat|proxy\.pac`, true},
	}
	for _, c := range cases {
		got := MatchesPattern(c.str, c.pattern)
		if got != c.want {
			t.Errorf("MatchesPattern(%q, %q) = %v, want %v", c.str, c.pattern, got, c.want)
		}
	}
}

func TestFilterHyperscanStatus_ReportsCounters(t *testing.T) {
	// Ensure at least one HS-decided call has happened so counters move.
	_ = MatchesPattern("hello", `world`)

	st := GetFilterHyperscanStatus()
	if !st.Enabled {
		t.Fatal("expected Enabled=true under hyperscan tag")
	}
	if st.LibVersion == "" || st.LibVersion == "disabled" {
		t.Errorf("expected libhs version, got %q", st.LibVersion)
	}
	if st.PatternsCached < 1 {
		t.Errorf("expected PatternsCached>=1, got %d", st.PatternsCached)
	}
}
