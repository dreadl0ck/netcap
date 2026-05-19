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

package webui

import (
	"encoding/json"
	"fmt"
	"net/url"
	"reflect"
	"testing"
)

// TestFingerprintSummaryJSON verifies the FingerprintSummary struct marshals communityIds correctly.
func TestFingerprintSummaryJSON(t *testing.T) {
	summary := FingerprintSummary{
		Fingerprint:  "t13d1516h2_8daaf6152771",
		Type:         "JA4",
		Count:        5,
		Hosts:        []string{"10.0.0.1", "10.0.0.2"},
		Description:  "Chrome Browser",
		FirstSeen:    1000,
		LastSeen:     2000,
		CommunityIDs: []string{"1:abc123", "1:def456"},
	}

	data, err := json.Marshal(summary)
	if err != nil {
		t.Fatalf("Failed to marshal FingerprintSummary: %v", err)
	}

	var decoded map[string]any
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Failed to unmarshal FingerprintSummary: %v", err)
	}

	// Verify communityIds field is present in JSON
	cids, ok := decoded["communityIds"]
	if !ok {
		t.Fatal("Expected communityIds field in JSON output")
	}

	cidSlice, ok := cids.([]any)
	if !ok {
		t.Fatal("Expected communityIds to be a JSON array")
	}

	if len(cidSlice) != 2 {
		t.Fatalf("Expected 2 community IDs, got %d", len(cidSlice))
	}

	if cidSlice[0].(string) != "1:abc123" {
		t.Errorf("Expected first community ID '1:abc123', got '%s'", cidSlice[0])
	}
}

// TestFingerprintSummaryEmptyCommunityIDs verifies that empty communityIds
// serializes as an empty array, not null.
func TestFingerprintSummaryEmptyCommunityIDs(t *testing.T) {
	summary := FingerprintSummary{
		Fingerprint:  "t13d1516h2_8daaf6152771",
		Type:         "JA4",
		Count:        1,
		Hosts:        []string{},
		CommunityIDs: []string{},
	}

	data, err := json.Marshal(summary)
	if err != nil {
		t.Fatalf("Failed to marshal FingerprintSummary: %v", err)
	}

	var decoded map[string]any
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Failed to unmarshal FingerprintSummary: %v", err)
	}

	cids, ok := decoded["communityIds"]
	if !ok {
		t.Fatal("Expected communityIds field in JSON output")
	}

	cidSlice, ok := cids.([]any)
	if !ok {
		t.Fatal("Expected communityIds to be a JSON array")
	}

	if len(cidSlice) != 0 {
		t.Fatalf("Expected 0 community IDs, got %d", len(cidSlice))
	}
}

// TestFingerprintAggregatorCommunityIDs verifies the aggregator correctly tracks community IDs.
func TestFingerprintAggregatorCommunityIDs(t *testing.T) {
	agg := &fingerprintAggregator{
		fingerprint:  "test_fp",
		fpType:       "JA4",
		hosts:        make(map[string]bool),
		communityIDs: make(map[string]bool),
		firstSeen:    1000,
		lastSeen:     2000,
	}

	// Add community IDs (with duplicates)
	agg.communityIDs["1:abc123"] = true
	agg.communityIDs["1:def456"] = true
	agg.communityIDs["1:abc123"] = true // duplicate

	if len(agg.communityIDs) != 2 {
		t.Fatalf("Expected 2 unique community IDs, got %d", len(agg.communityIDs))
	}

	if !agg.communityIDs["1:abc123"] {
		t.Error("Expected community ID '1:abc123' to be present")
	}

	if !agg.communityIDs["1:def456"] {
		t.Error("Expected community ID '1:def456' to be present")
	}
}

// TestFingerprintsResponseJSON verifies the full response includes communityIds.
func TestFingerprintsResponseJSON(t *testing.T) {
	response := FingerprintsResponse{
		Fingerprints: []FingerprintSummary{
			{
				Fingerprint:  "fp1",
				Type:         "JA4",
				Count:        3,
				Hosts:        []string{"10.0.0.1"},
				CommunityIDs: []string{"1:abc123"},
			},
			{
				Fingerprint:  "fp2",
				Type:         "JA4SSH",
				Count:        1,
				Hosts:        []string{"10.0.0.2"},
				CommunityIDs: []string{},
			},
		},
		TotalCount: 2,
	}

	data, err := json.Marshal(response)
	if err != nil {
		t.Fatalf("Failed to marshal FingerprintsResponse: %v", err)
	}

	var decoded FingerprintsResponse
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Failed to unmarshal FingerprintsResponse: %v", err)
	}

	if len(decoded.Fingerprints) != 2 {
		t.Fatalf("Expected 2 fingerprints, got %d", len(decoded.Fingerprints))
	}

	if len(decoded.Fingerprints[0].CommunityIDs) != 1 {
		t.Errorf("Expected 1 community ID for fp1, got %d", len(decoded.Fingerprints[0].CommunityIDs))
	}

	if decoded.Fingerprints[0].CommunityIDs[0] != "1:abc123" {
		t.Errorf("Expected community ID '1:abc123', got '%s'", decoded.Fingerprints[0].CommunityIDs[0])
	}

	if len(decoded.Fingerprints[1].CommunityIDs) != 0 {
		t.Errorf("Expected 0 community IDs for fp2, got %d", len(decoded.Fingerprints[1].CommunityIDs))
	}
}

// TestFilterFingerprintsByCommunityID verifies that fingerprints can be filtered
// by community IDs using the same logic as the menu count handler.
func TestFilterFingerprintsByCommunityID(t *testing.T) {
	fingerprints := []FingerprintSummary{
		{
			Fingerprint:  "fp1",
			Type:         "JA4",
			CommunityIDs: []string{"1:abc123", "1:def456"},
		},
		{
			Fingerprint:  "fp2",
			Type:         "JA4S",
			CommunityIDs: []string{"1:def456", "1:ghi789"},
		},
		{
			Fingerprint:  "fp3",
			Type:         "JA4T",
			CommunityIDs: []string{},
		},
		{
			Fingerprint:  "fp4",
			Type:         "DHCP",
			CommunityIDs: nil,
		},
	}

	tests := []struct {
		name         string
		communityIDs map[string]bool
		expected     int
	}{
		{
			name:         "filter matches one fingerprint",
			communityIDs: map[string]bool{"1:abc123": true},
			expected:     1,
		},
		{
			name:         "filter matches two fingerprints",
			communityIDs: map[string]bool{"1:def456": true},
			expected:     2,
		},
		{
			name:         "filter matches all with community IDs",
			communityIDs: map[string]bool{"1:abc123": true, "1:ghi789": true},
			expected:     2,
		},
		{
			name:         "filter matches none",
			communityIDs: map[string]bool{"1:nonexistent": true},
			expected:     0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			count := int64(0)
			for _, fp := range fingerprints {
				for _, cid := range fp.CommunityIDs {
					if tt.communityIDs[cid] {
						count++
						break
					}
				}
			}
			if count != int64(tt.expected) {
				t.Errorf("Expected %d filtered fingerprints, got %d", tt.expected, count)
			}
		})
	}
}


// TestCapFingerprintSummaryCapsCommunityIDs verifies that CommunityIDs are
// capped to maxCommunityIDsPerRow with totals and the truncated flag preserved.
func TestCapFingerprintSummaryCapsCommunityIDs(t *testing.T) {
	cids := make([]string, 0, 25)
	for i := 0; i < 25; i++ {
		cids = append(cids, fmt.Sprintf("1:cid%02d", i))
	}
	in := FingerprintSummary{
		Fingerprint:  "fp",
		Type:         "JA4",
		CommunityIDs: cids,
	}

	out := capFingerprintSummary(in, nil)

	if got, want := out.CommunityIDsTotal, 25; got != want {
		t.Errorf("CommunityIDsTotal: got %d, want %d", got, want)
	}
	if got, want := len(out.CommunityIDs), maxCommunityIDsPerRow; got != want {
		t.Errorf("CommunityIDs length: got %d, want %d", got, want)
	}
	if !out.CommunityIDsTruncated {
		t.Error("CommunityIDsTruncated: got false, want true")
	}
	// First 10 are the smallest 10 after sort.
	want := []string{
		"1:cid00", "1:cid01", "1:cid02", "1:cid03", "1:cid04",
		"1:cid05", "1:cid06", "1:cid07", "1:cid08", "1:cid09",
	}
	if !reflect.DeepEqual(out.CommunityIDs, want) {
		t.Errorf("CommunityIDs order:\n got: %v\nwant: %v", out.CommunityIDs, want)
	}
}

// TestCapFingerprintSummaryPromotesMatches verifies that community IDs in
// the filter set are placed at the front of the per-row slice.
func TestCapFingerprintSummaryPromotesMatches(t *testing.T) {
	cids := make([]string, 0, 25)
	for i := 0; i < 25; i++ {
		cids = append(cids, fmt.Sprintf("1:cid%02d", i))
	}
	in := FingerprintSummary{
		Fingerprint:  "fp",
		Type:         "JA4",
		CommunityIDs: cids,
	}

	filter := map[string]struct{}{
		"1:cid17": {},
		"1:cid23": {},
	}
	out := capFingerprintSummary(in, filter)

	if got, want := out.CommunityIDsTotal, 25; got != want {
		t.Errorf("CommunityIDsTotal: got %d, want %d", got, want)
	}
	if got, want := len(out.CommunityIDs), maxCommunityIDsPerRow; got != want {
		t.Errorf("CommunityIDs length: got %d, want %d", got, want)
	}
	// Matches first (sorted), then non-matches (sorted) filling the cap.
	if got := out.CommunityIDs[0]; got != "1:cid17" {
		t.Errorf("position 0: got %s, want 1:cid17", got)
	}
	if got := out.CommunityIDs[1]; got != "1:cid23" {
		t.Errorf("position 1: got %s, want 1:cid23", got)
	}
	// Remaining slots are the smallest non-matching cids.
	want := []string{
		"1:cid17", "1:cid23",
		"1:cid00", "1:cid01", "1:cid02", "1:cid03",
		"1:cid04", "1:cid05", "1:cid06", "1:cid07",
	}
	if !reflect.DeepEqual(out.CommunityIDs, want) {
		t.Errorf("CommunityIDs order:\n got: %v\nwant: %v", out.CommunityIDs, want)
	}
	if !out.CommunityIDsTruncated {
		t.Error("CommunityIDsTruncated: got false, want true")
	}
}

// TestCapFingerprintSummaryShortInputNoTruncation verifies short inputs are
// left untouched (sorted, but not truncated).
func TestCapFingerprintSummaryShortInputNoTruncation(t *testing.T) {
	in := FingerprintSummary{
		Fingerprint:  "fp",
		Type:         "JA4",
		CommunityIDs: []string{"1:b", "1:a", "1:c"},
		Hosts:        []string{"10.0.0.2", "10.0.0.1"},
	}
	out := capFingerprintSummary(in, nil)

	if out.CommunityIDsTruncated {
		t.Error("CommunityIDsTruncated: got true, want false")
	}
	wantCIDs := []string{"1:a", "1:b", "1:c"}
	if !reflect.DeepEqual(out.CommunityIDs, wantCIDs) {
		t.Errorf("CommunityIDs:\n got: %v\nwant: %v", out.CommunityIDs, wantCIDs)
	}
	if out.HostsTruncated {
		t.Error("HostsTruncated: got true, want false")
	}
	wantHosts := []string{"10.0.0.1", "10.0.0.2"}
	if !reflect.DeepEqual(out.Hosts, wantHosts) {
		t.Errorf("Hosts:\n got: %v\nwant: %v", out.Hosts, wantHosts)
	}
}

// TestCapFingerprintSummaryCapsHosts verifies the host list is capped.
func TestCapFingerprintSummaryCapsHosts(t *testing.T) {
	hosts := make([]string, 0, maxHostsPerRow+10)
	for i := 0; i < maxHostsPerRow+10; i++ {
		hosts = append(hosts, fmt.Sprintf("10.0.%d.%d", i/256, i%256))
	}
	in := FingerprintSummary{Fingerprint: "fp", Type: "JA4", Hosts: hosts}
	out := capFingerprintSummary(in, nil)

	if got, want := out.HostsTotal, maxHostsPerRow+10; got != want {
		t.Errorf("HostsTotal: got %d, want %d", got, want)
	}
	if got, want := len(out.Hosts), maxHostsPerRow; got != want {
		t.Errorf("len(Hosts): got %d, want %d", got, want)
	}
	if !out.HostsTruncated {
		t.Error("HostsTruncated: got false, want true")
	}
}

// TestParseFingerprintListOptionsDefaults verifies sensible defaults when no
// query parameters are supplied.
func TestParseFingerprintListOptionsDefaults(t *testing.T) {
	opts := parseFingerprintListOptions(url.Values{})

	if opts.limit != defaultFingerprintsLimit {
		t.Errorf("limit: got %d, want %d", opts.limit, defaultFingerprintsLimit)
	}
	if opts.offset != 0 {
		t.Errorf("offset: got %d, want 0", opts.offset)
	}
	if opts.typeFilter != "" {
		t.Errorf("typeFilter: got %q, want empty", opts.typeFilter)
	}
	if opts.search != "" {
		t.Errorf("search: got %q, want empty", opts.search)
	}
	if opts.communityIDFilter != nil {
		t.Errorf("communityIDFilter: got %v, want nil", opts.communityIDFilter)
	}
	if opts.sortField != "count" {
		t.Errorf("sortField: got %q, want count", opts.sortField)
	}
	if opts.sortOrder != "desc" {
		t.Errorf("sortOrder: got %q, want desc", opts.sortOrder)
	}
}

// TestParseFingerprintListOptionsClampsLimit verifies the limit is clamped to
// the per-request hard cap.
func TestParseFingerprintListOptionsClampsLimit(t *testing.T) {
	opts := parseFingerprintListOptions(url.Values{"limit": {"5000"}})
	if opts.limit != maxFingerprintsLimit {
		t.Errorf("limit clamp: got %d, want %d", opts.limit, maxFingerprintsLimit)
	}
}

// TestParseFingerprintListOptionsCommunityIDSet verifies repeated communityId
// query params accumulate into the filter set.
func TestParseFingerprintListOptionsCommunityIDSet(t *testing.T) {
	opts := parseFingerprintListOptions(url.Values{
		"communityId": {"1:abc", "1:def", "", "1:abc"},
	})
	if len(opts.communityIDFilter) != 2 {
		t.Fatalf("expected 2 unique community IDs in filter, got %d", len(opts.communityIDFilter))
	}
	if _, ok := opts.communityIDFilter["1:abc"]; !ok {
		t.Error("missing 1:abc")
	}
	if _, ok := opts.communityIDFilter["1:def"]; !ok {
		t.Error("missing 1:def")
	}
}

// TestFilterFingerprintsAppliesAllFilters verifies type + search + communityId
// filters are AND-combined.
func TestFilterFingerprintsAppliesAllFilters(t *testing.T) {
	in := []FingerprintSummary{
		{Fingerprint: "t13d_a", Type: "JA4", Description: "Chrome", CommunityIDs: []string{"1:abc"}},
		{Fingerprint: "t13d_b", Type: "JA4", Description: "Firefox", CommunityIDs: []string{"1:def"}},
		{Fingerprint: "q13d_c", Type: "JA4", Description: "Chrome", CommunityIDs: []string{"1:ghi"}},
		{Fingerprint: "ssh_a", Type: "JA4SSH", Description: "OpenSSH", CommunityIDs: []string{"1:abc"}},
	}

	got := filterFingerprints(in, fingerprintListOptions{
		typeFilter:        "JA4",
		search:            "chrome",
		communityIDFilter: map[string]struct{}{"1:abc": {}},
	})

	if len(got) != 1 {
		t.Fatalf("expected 1 row, got %d", len(got))
	}
	if got[0].Fingerprint != "t13d_a" {
		t.Errorf("expected t13d_a, got %s", got[0].Fingerprint)
	}
}

// TestSortFingerprintsCountDesc verifies the default sort order.
func TestSortFingerprintsCountDesc(t *testing.T) {
	in := []FingerprintSummary{
		{Fingerprint: "b", Count: 5},
		{Fingerprint: "a", Count: 10},
		{Fingerprint: "c", Count: 5},
	}
	sortFingerprints(in, "count", "desc")

	wantOrder := []string{"a", "b", "c"} // 10, then 5/5 stable by fingerprint asc
	for i, w := range wantOrder {
		if in[i].Fingerprint != w {
			t.Errorf("position %d: got %s, want %s", i, in[i].Fingerprint, w)
		}
	}
}

// TestSortFingerprintsFingerprintAsc verifies sort by fingerprint ascending.
func TestSortFingerprintsFingerprintAsc(t *testing.T) {
	in := []FingerprintSummary{
		{Fingerprint: "c", Count: 1},
		{Fingerprint: "a", Count: 1},
		{Fingerprint: "b", Count: 1},
	}
	sortFingerprints(in, "fingerprint", "asc")
	wantOrder := []string{"a", "b", "c"}
	for i, w := range wantOrder {
		if in[i].Fingerprint != w {
			t.Errorf("position %d: got %s, want %s", i, in[i].Fingerprint, w)
		}
	}
}

// TestComputeFingerprintStats verifies per-type counts and total occurrences
// are computed over the full dataset.
func TestComputeFingerprintStats(t *testing.T) {
	in := []FingerprintSummary{
		{Type: "JA4", Count: 3},
		{Type: "JA4", Count: 2},
		{Type: "JA4S", Count: 5},
		{Type: "DHCP", Count: 1},
	}
	stats := computeFingerprintStats(in)
	if stats.TotalFingerprints != 4 {
		t.Errorf("TotalFingerprints: got %d, want 4", stats.TotalFingerprints)
	}
	if stats.TotalOccurrences != 11 {
		t.Errorf("TotalOccurrences: got %d, want 11", stats.TotalOccurrences)
	}
	if stats.CountsByType["JA4"] != 2 {
		t.Errorf("CountsByType[JA4]: got %d, want 2", stats.CountsByType["JA4"])
	}
	if stats.CountsByType["JA4S"] != 1 {
		t.Errorf("CountsByType[JA4S]: got %d, want 1", stats.CountsByType["JA4S"])
	}
	if stats.CountsByType["DHCP"] != 1 {
		t.Errorf("CountsByType[DHCP]: got %d, want 1", stats.CountsByType["DHCP"])
	}
}


// TestParseSearchQuery verifies tokenisation and the !-prefix negation flag
// mirror the frontend parseSearchQuery in tableSearch.ts.
func TestParseSearchQuery(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  []searchTerm
	}{
		{name: "empty", input: "", want: nil},
		{name: "whitespace only", input: "   \t  ", want: nil},
		{name: "single positive", input: "JA4", want: []searchTerm{{term: "ja4", negate: false}}},
		{name: "single negative", input: "!JA3", want: []searchTerm{{term: "ja3", negate: true}}},
		{
			name:  "mixed",
			input: "HTTP !FTP admin",
			want: []searchTerm{
				{term: "http", negate: false},
				{term: "ftp", negate: true},
				{term: "admin", negate: false},
			},
		},
		{
			name:  "lone bang stays literal",
			input: "!",
			want:  []searchTerm{{term: "!", negate: false}},
		},
		{
			name:  "extra whitespace collapsed",
			input: "  HTTP   !FTP\tadmin\n",
			want: []searchTerm{
				{term: "http", negate: false},
				{term: "ftp", negate: true},
				{term: "admin", negate: false},
			},
		},
		{
			name:  "case folded to lower",
			input: "ChRoMe !FireFox",
			want: []searchTerm{
				{term: "chrome", negate: false},
				{term: "firefox", negate: true},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseSearchQuery(tt.input)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("parseSearchQuery(%q):\n got: %#v\nwant: %#v", tt.input, got, tt.want)
			}
		})
	}
}

// TestFingerprintMatchesSearch covers OR-on-positives, AND-on-negatives, and
// the cross-field combined haystack so that a negated term occurring in any
// field excludes the row.
func TestFingerprintMatchesSearch(t *testing.T) {
	fp := FingerprintSummary{
		Fingerprint: "t13d1516h2_8daaf6152771",
		Type:        "JA4",
		Description: "Chrome Browser",
		Hosts:       []string{"10.0.0.1", "192.168.1.42"},
	}

	tests := []struct {
		name  string
		query string
		want  bool
	}{
		{name: "empty matches", query: "", want: true},
		{name: "positive matches fingerprint", query: "t13d", want: true},
		{name: "positive matches type", query: "JA4", want: true},
		{name: "positive matches description", query: "chrome", want: true},
		{name: "positive matches host", query: "192.168", want: true},
		{name: "positive no match", query: "firefox", want: false},
		{name: "OR across positives - one hit", query: "firefox 192.168", want: true},
		{name: "OR across positives - both miss", query: "firefox edge", want: false},
		{name: "negation excludes on description hit", query: "!chrome", want: false},
		{name: "negation excludes on host hit", query: "!10.0.0.1", want: false},
		{name: "negation passes when miss", query: "!firefox", want: true},
		{name: "positive + negation, positive hits, negation misses", query: "JA4 !firefox", want: true},
		{name: "positive + negation, positive hits but negation also hits", query: "JA4 !chrome", want: false},
		{name: "positive misses but negation also misses", query: "edge !firefox", want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			terms := parseSearchQuery(tt.query)
			if got := fingerprintMatchesSearch(fp, terms); got != tt.want {
				t.Errorf("fingerprintMatchesSearch(%q) = %v, want %v", tt.query, got, tt.want)
			}
		})
	}
}

// TestFilterFingerprintsHonoursNegation verifies the handler-level filter
// pipeline excludes rows matching a negated search term.
func TestFilterFingerprintsHonoursNegation(t *testing.T) {
	in := []FingerprintSummary{
		{Fingerprint: "a", Type: "JA4", Description: "Chrome on macOS"},
		{Fingerprint: "b", Type: "JA4", Description: "Firefox on Linux"},
		{Fingerprint: "c", Type: "JA4S", Description: "Some server"},
	}

	got := filterFingerprints(in, fingerprintListOptions{search: "JA4 !chrome"})
	if len(got) != 2 {
		t.Fatalf("expected 2 rows, got %d (%v)", len(got), got)
	}
	for _, fp := range got {
		if fp.Fingerprint == "a" {
			t.Errorf("row a (Chrome) should have been excluded by !chrome")
		}
	}
}
