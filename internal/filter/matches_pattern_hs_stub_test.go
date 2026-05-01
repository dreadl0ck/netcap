//go:build !hyperscan

/*
 * NETCAP - Traffic Analysis Framework
 * Copyright (c) Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
 * License: GNU General Public License v3.0
 */

package filter

import "testing"

func TestHSMatchesPatternPrecheck_StubAlwaysUndecided(t *testing.T) {
	matched, decided := hsMatchesPatternPrecheck("any", "any")
	if decided {
		t.Fatal("stub must always be undecided so RE2 still runs")
	}
	if matched {
		t.Fatal("stub must report matched=false when undecided")
	}
}

func TestFilterHyperscanStatus_StubReportsDisabled(t *testing.T) {
	st := GetFilterHyperscanStatus()
	if st.Enabled {
		t.Fatal("stub must report Enabled=false")
	}
	if st.LibVersion != "disabled" {
		t.Errorf("expected LibVersion=\"disabled\", got %q", st.LibVersion)
	}
}
