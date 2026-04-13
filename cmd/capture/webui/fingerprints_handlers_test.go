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
	"sort"
	"testing"
)

// TestFingerprintSummaryJSON tests JSON serialization of FingerprintSummary,
// including the new CommunityIDs field.
func TestFingerprintSummaryJSON(t *testing.T) {
	tests := []struct {
		name     string
		input    FingerprintSummary
		checkFn  func(t *testing.T, data []byte, decoded FingerprintSummary)
	}{
		{
			name: "with community IDs",
			input: FingerprintSummary{
				Fingerprint:  "t13d1516h2_8daaf6152771_b0da82dd1658",
				Type:         "JA4",
				Count:        5,
				Hosts:        []string{"192.168.1.1", "10.0.0.1"},
				Description:  "Chrome Browser",
				FirstSeen:    1000,
				LastSeen:     2000,
				CommunityIDs: []string{"1:abc123", "1:def456"},
			},
			checkFn: func(t *testing.T, data []byte, decoded FingerprintSummary) {
				// Verify JSON field name is "communityIDs"
				var raw map[string]json.RawMessage
				if err := json.Unmarshal(data, &raw); err != nil {
					t.Fatalf("Failed to unmarshal to map: %v", err)
				}
				if _, ok := raw["communityIDs"]; !ok {
					t.Error("JSON output missing 'communityIDs' field")
				}

				if len(decoded.CommunityIDs) != 2 {
					t.Errorf("Expected 2 community IDs, got %d", len(decoded.CommunityIDs))
				}
				if decoded.Fingerprint != "t13d1516h2_8daaf6152771_b0da82dd1658" {
					t.Errorf("Unexpected fingerprint: %s", decoded.Fingerprint)
				}
			},
		},
		{
			name: "empty community IDs",
			input: FingerprintSummary{
				Fingerprint:  "c02b_c02f_c02c_c030_009e",
				Type:         "JA4S",
				Count:        1,
				Hosts:        []string{"10.0.0.2"},
				Description:  "",
				FirstSeen:    3000,
				LastSeen:     3000,
				CommunityIDs: []string{},
			},
			checkFn: func(t *testing.T, data []byte, decoded FingerprintSummary) {
				if len(decoded.CommunityIDs) != 0 {
					t.Errorf("Expected 0 community IDs, got %d", len(decoded.CommunityIDs))
				}
			},
		},
		{
			name: "nil community IDs",
			input: FingerprintSummary{
				Fingerprint:  "fp_hash",
				Type:         "DHCP",
				Count:        3,
				Hosts:        []string{},
				CommunityIDs: nil,
			},
			checkFn: func(t *testing.T, data []byte, decoded FingerprintSummary) {
				// nil slice serializes as null in JSON; after decode it will be nil
				if decoded.CommunityIDs != nil {
					t.Errorf("Expected nil community IDs, got %v", decoded.CommunityIDs)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := json.Marshal(tt.input)
			if err != nil {
				t.Fatalf("Failed to marshal: %v", err)
			}

			var decoded FingerprintSummary
			if err := json.Unmarshal(data, &decoded); err != nil {
				t.Fatalf("Failed to unmarshal: %v", err)
			}

			tt.checkFn(t, data, decoded)
		})
	}
}

// TestFingerprintsResponseJSON tests JSON serialization of the full API response.
func TestFingerprintsResponseJSON(t *testing.T) {
	response := FingerprintsResponse{
		Fingerprints: []FingerprintSummary{
			{
				Fingerprint:  "fp1",
				Type:         "JA4",
				Count:        10,
				Hosts:        []string{"192.168.1.1"},
				CommunityIDs: []string{"1:abc"},
			},
			{
				Fingerprint:  "fp2",
				Type:         "JA4SSH",
				Count:        5,
				Hosts:        []string{"10.0.0.1"},
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

	if decoded.TotalCount != 2 {
		t.Errorf("Expected TotalCount 2, got %d", decoded.TotalCount)
	}
	if len(decoded.Fingerprints) != 2 {
		t.Errorf("Expected 2 fingerprints, got %d", len(decoded.Fingerprints))
	}
	if len(decoded.Fingerprints[0].CommunityIDs) != 1 {
		t.Errorf("Expected 1 community ID in first fingerprint, got %d", len(decoded.Fingerprints[0].CommunityIDs))
	}
}

// TestFingerprintAggregatorCommunityIDs tests the aggregation logic for tracking
// Community IDs across multiple records.
func TestFingerprintAggregatorCommunityIDs(t *testing.T) {
	t.Run("collects unique community IDs", func(t *testing.T) {
		agg := &fingerprintAggregator{
			fingerprint:  "test_fp",
			fpType:       "JA4",
			hosts:        make(map[string]bool),
			communityIDs: make(map[string]bool),
			firstSeen:    1000,
			lastSeen:     1000,
		}

		// Simulate adding multiple records with some duplicate community IDs
		ids := []string{"1:abc123", "1:def456", "1:abc123", "1:ghi789", "1:def456"}
		for _, id := range ids {
			agg.communityIDs[id] = true
		}

		if len(agg.communityIDs) != 3 {
			t.Errorf("Expected 3 unique community IDs, got %d", len(agg.communityIDs))
		}
		if !agg.communityIDs["1:abc123"] {
			t.Error("Missing community ID '1:abc123'")
		}
		if !agg.communityIDs["1:def456"] {
			t.Error("Missing community ID '1:def456'")
		}
		if !agg.communityIDs["1:ghi789"] {
			t.Error("Missing community ID '1:ghi789'")
		}
	})

	t.Run("empty community IDs when no records have them", func(t *testing.T) {
		agg := &fingerprintAggregator{
			fingerprint:  "test_fp",
			fpType:       "JA4T",
			hosts:        make(map[string]bool),
			communityIDs: make(map[string]bool),
			firstSeen:    1000,
			lastSeen:     1000,
		}

		// Simulate records with empty community IDs (e.g., TCP records)
		emptyIDs := []string{"", "", ""}
		for _, id := range emptyIDs {
			if id != "" {
				agg.communityIDs[id] = true
			}
		}

		if len(agg.communityIDs) != 0 {
			t.Errorf("Expected 0 community IDs, got %d", len(agg.communityIDs))
		}
	})

	t.Run("conversion to FingerprintSummary preserves community IDs", func(t *testing.T) {
		agg := &fingerprintAggregator{
			fingerprint:  "test_fp",
			fpType:       "JA4H",
			count:        3,
			hosts:        map[string]bool{"192.168.1.1": true},
			communityIDs: map[string]bool{"1:aaa": true, "1:bbb": true},
			description:  "Test",
			firstSeen:    1000,
			lastSeen:     2000,
		}

		// Convert like readFingerprints does
		communityIDs := make([]string, 0, len(agg.communityIDs))
		for id := range agg.communityIDs {
			communityIDs = append(communityIDs, id)
		}

		summary := FingerprintSummary{
			Fingerprint:  agg.fingerprint,
			Type:         agg.fpType,
			Count:        agg.count,
			CommunityIDs: communityIDs,
		}

		if len(summary.CommunityIDs) != 2 {
			t.Errorf("Expected 2 community IDs in summary, got %d", len(summary.CommunityIDs))
		}

		// Sort for deterministic comparison
		sort.Strings(summary.CommunityIDs)
		if summary.CommunityIDs[0] != "1:aaa" || summary.CommunityIDs[1] != "1:bbb" {
			t.Errorf("Unexpected community IDs: %v", summary.CommunityIDs)
		}
	})
}

// TestFilterFingerprintsByCommunityID tests the filtering logic for matching
// fingerprints by Community ID.
func TestFilterFingerprintsByCommunityID(t *testing.T) {
	fingerprints := []FingerprintSummary{
		{
			Fingerprint:  "fp1",
			Type:         "JA4",
			Count:        10,
			CommunityIDs: []string{"1:abc123", "1:def456"},
		},
		{
			Fingerprint:  "fp2",
			Type:         "JA4S",
			Count:        5,
			CommunityIDs: []string{"1:def456", "1:ghi789"},
		},
		{
			Fingerprint:  "fp3",
			Type:         "JA4SSH",
			Count:        3,
			CommunityIDs: []string{"1:xyz000"},
		},
		{
			Fingerprint:  "fp4",
			Type:         "DHCP",
			Count:        1,
			CommunityIDs: []string{},
		},
		{
			Fingerprint:  "fp5",
			Type:         "JA4T",
			Count:        2,
			CommunityIDs: nil,
		},
	}

	tests := []struct {
		name               string
		communityID        string
		expectedCount      int
		expectedFPs        []string
	}{
		{
			name:          "empty filter returns all",
			communityID:   "",
			expectedCount: 5,
			expectedFPs:   []string{"fp1", "fp2", "fp3", "fp4", "fp5"},
		},
		{
			name:          "filter by shared community ID",
			communityID:   "1:def456",
			expectedCount: 2,
			expectedFPs:   []string{"fp1", "fp2"},
		},
		{
			name:          "filter by unique community ID",
			communityID:   "1:abc123",
			expectedCount: 1,
			expectedFPs:   []string{"fp1"},
		},
		{
			name:          "filter by another unique community ID",
			communityID:   "1:xyz000",
			expectedCount: 1,
			expectedFPs:   []string{"fp3"},
		},
		{
			name:          "filter by non-existent community ID",
			communityID:   "1:nonexistent",
			expectedCount: 0,
			expectedFPs:   []string{},
		},
		{
			name:          "fingerprints with empty/nil community IDs are excluded",
			communityID:   "1:abc123",
			expectedCount: 1,
			expectedFPs:   []string{"fp1"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := FilterFingerprintsByCommunityID(fingerprints, tt.communityID)

			if len(result) != tt.expectedCount {
				t.Errorf("Expected %d results, got %d", tt.expectedCount, len(result))
			}

			// Verify the correct fingerprints are returned
			resultFPs := make([]string, len(result))
			for i, fp := range result {
				resultFPs[i] = fp.Fingerprint
			}
			sort.Strings(resultFPs)
			sort.Strings(tt.expectedFPs)

			if len(resultFPs) != len(tt.expectedFPs) {
				t.Errorf("Expected fingerprints %v, got %v", tt.expectedFPs, resultFPs)
				return
			}
			for i := range resultFPs {
				if resultFPs[i] != tt.expectedFPs[i] {
					t.Errorf("Expected fingerprints %v, got %v", tt.expectedFPs, resultFPs)
					break
				}
			}
		})
	}
}

// TestFilterFingerprintsByCommunityIDPreservesOrder tests that filtering
// preserves the original ordering of fingerprints.
func TestFilterFingerprintsByCommunityIDPreservesOrder(t *testing.T) {
	fingerprints := []FingerprintSummary{
		{Fingerprint: "first", Count: 10, CommunityIDs: []string{"1:shared"}},
		{Fingerprint: "second", Count: 5, CommunityIDs: []string{"1:other"}},
		{Fingerprint: "third", Count: 3, CommunityIDs: []string{"1:shared"}},
	}

	result := FilterFingerprintsByCommunityID(fingerprints, "1:shared")
	if len(result) != 2 {
		t.Fatalf("Expected 2 results, got %d", len(result))
	}
	if result[0].Fingerprint != "first" {
		t.Errorf("Expected first result to be 'first', got %q", result[0].Fingerprint)
	}
	if result[1].Fingerprint != "third" {
		t.Errorf("Expected second result to be 'third', got %q", result[1].Fingerprint)
	}
}

// TestFilterFingerprintsByCommunityIDNilSlice tests filtering when input is nil.
func TestFilterFingerprintsByCommunityIDNilSlice(t *testing.T) {
	result := FilterFingerprintsByCommunityID(nil, "1:abc")
	if result != nil {
		t.Errorf("Expected nil result for nil input with filter, got %v", result)
	}

	result = FilterFingerprintsByCommunityID(nil, "")
	if result != nil {
		t.Errorf("Expected nil result for nil input without filter, got %v", result)
	}
}
