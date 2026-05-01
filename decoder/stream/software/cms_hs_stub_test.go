//go:build !hyperscan

/*
 * NETCAP - Traffic Analysis Framework
 * Copyright (c) Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
 * License: GNU General Public License v3.0
 */

package software

import "testing"

func TestCMSHyperscan_StubReturnsNilCandidates(t *testing.T) {
	if cmsHeaderCandidates("X-Generator", "Drupal 9") != nil {
		t.Fatal("stub must return nil candidates so the full nested loop runs")
	}
	if cmsCookieCandidates("wp-settings-1", "x") != nil {
		t.Fatal("stub must return nil candidates")
	}
	st := GetCMSHyperscanStatus()
	if st.Enabled {
		t.Fatal("stub must report Enabled=false")
	}
	if st.LibVersion != "disabled" {
		t.Errorf("stub must report LibVersion=\"disabled\", got %q", st.LibVersion)
	}
}
