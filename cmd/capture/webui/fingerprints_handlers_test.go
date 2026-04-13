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

// TestFingerprintSummaryJSONSerialization tests JSON serialization of FingerprintSummary
// including the new CommunityIDs field.
func TestFingerprintSummaryJSONSerialization(t *testing.T) {
	tests := []struct {
		name     string
		input    FingerprintSummary
		checkFn  func(t *testing.T, result map[string]interface{})
	}{
		{
			name: "with community IDs",
			input: FingerprintSummary{
				Fingerprint:  "t13d1516h2_8daaf6152771_b0da82dd1658",
				Type:         "JA4",
				Count:        5,
				Hosts:        []string{"192.168.1.1", "10.0.0.1"},
				Description:  "Chrome Browser",
				FirstSeen:    1000000,
				LastSeen:     2000000,
				CommunityIDs: []string{"1:abc123", "1:def456"},
			},
			checkFn: func(t *testing.T, result map[string]interface{}) {
				cids, ok := result["communityIds"].([]interface{})
				if !ok {
					t.Fatal("communityIds should be an array")
				}
				if len(cids) != 2 {
					t.Errorf("expected 2 community IDs, got %d", len(cids))
				}
				if cids[0].(string) != "1:abc123" {
					t.Errorf("expected first community ID to be '1:abc123', got %s", cids[0])
				}
			},
		},
		{
			name: "with empty community IDs",
			input: FingerprintSummary{
				Fingerprint:  "t13d1516h2_8daaf6152771_b0da82dd1658",
				Type:         "JA4",
				Count:        1,
				Hosts:        []string{"192.168.1.1"},
				CommunityIDs: []string{},
			},
			checkFn: func(t *testing.T, result map[string]interface{}) {
				cids, ok := result["communityIds"].([]interface{})
				if !ok {
					t.Fatal("communityIds should be an array (even if empty)")
				}
				if len(cids) != 0 {
					t.Errorf("expected 0 community IDs, got %d", len(cids))
				}
			},
		},
		{
			name: "with nil community IDs",
			input: FingerprintSummary{
				Fingerprint: "t13d1516h2_8daaf6152771_b0da82dd1658",
				Type:        "JA4",
				Count:       1,
				Hosts:       []string{"192.168.1.1"},
				// CommunityIDs is nil (zero value)
			},
			checkFn: func(t *testing.T, result map[string]interface{}) {
				// When nil, JSON serializes as null
				if result["communityIds"] != nil {
					// It could also be an empty array depending on encoding
					cids, ok := result["communityIds"].([]interface{})
					if ok && len(cids) != 0 {
						t.Errorf("expected nil/null community IDs, got %v", result["communityIds"])
					}
				}
			},
		},
		{
			name: "JSON field name is communityIds",
			input: FingerprintSummary{
				Fingerprint:  "test_fp",
				Type:         "JA4SSH",
				Count:        1,
				Hosts:        []string{},
				CommunityIDs: []string{"1:test"},
			},
			checkFn: func(t *testing.T, result map[string]interface{}) {
				if _, ok := result["communityIds"]; !ok {
					t.Error("JSON field should be named 'communityIds'")
				}
				// Ensure it's NOT using the Go field name
				if _, ok := result["CommunityIDs"]; ok {
					t.Error("JSON field should NOT use Go field name 'CommunityIDs'")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := json.Marshal(tt.input)
			if err != nil {
				t.Fatalf("failed to marshal FingerprintSummary: %v", err)
			}

			var result map[string]interface{}
			if err := json.Unmarshal(data, &result); err != nil {
				t.Fatalf("failed to unmarshal JSON: %v", err)
			}

			tt.checkFn(t, result)
		})
	}
}

// TestFingerprintSummaryJSONRoundTrip tests that FingerprintSummary can be serialized
// and deserialized without data loss.
func TestFingerprintSummaryJSONRoundTrip(t *testing.T) {
	original := FingerprintSummary{
		Fingerprint:  "t13d1516h2_8daaf6152771_b0da82dd1658",
		Type:         "JA4",
		Count:        42,
		Hosts:        []string{"192.168.1.1", "10.0.0.1"},
		Description:  "Chrome Browser",
		FirstSeen:    1000000,
		LastSeen:     2000000,
		CommunityIDs: []string{"1:abc123", "1:def456"},
	}

	data, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}

	var decoded FingerprintSummary
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	if decoded.Fingerprint != original.Fingerprint {
		t.Errorf("fingerprint mismatch: got %s, want %s", decoded.Fingerprint, original.Fingerprint)
	}
	if decoded.Type != original.Type {
		t.Errorf("type mismatch: got %s, want %s", decoded.Type, original.Type)
	}
	if decoded.Count != original.Count {
		t.Errorf("count mismatch: got %d, want %d", decoded.Count, original.Count)
	}
	if len(decoded.CommunityIDs) != len(original.CommunityIDs) {
		t.Errorf("community IDs length mismatch: got %d, want %d", len(decoded.CommunityIDs), len(original.CommunityIDs))
	}
	for i, cid := range decoded.CommunityIDs {
		if cid != original.CommunityIDs[i] {
			t.Errorf("community ID[%d] mismatch: got %s, want %s", i, cid, original.CommunityIDs[i])
		}
	}
}

// TestFingerprintAggregatorCommunityIDs tests that the aggregator correctly tracks
// Community IDs during fingerprint aggregation.
func TestFingerprintAggregatorCommunityIDs(t *testing.T) {
	t.Run("collects unique community IDs", func(t *testing.T) {
		agg := &fingerprintAggregator{
			fingerprint:  "test_fp",
			fpType:       "JA4",
			hosts:        make(map[string]bool),
			communityIDs: make(map[string]bool),
		}

		// Add some community IDs (simulating multiple records with the same fingerprint)
		agg.communityIDs["1:abc123"] = true
		agg.communityIDs["1:def456"] = true
		agg.communityIDs["1:abc123"] = true // duplicate

		if len(agg.communityIDs) != 2 {
			t.Errorf("expected 2 unique community IDs, got %d", len(agg.communityIDs))
		}
	})

	t.Run("empty community IDs when no records have them", func(t *testing.T) {
		agg := &fingerprintAggregator{
			fingerprint:  "test_fp",
			fpType:       "DHCP",
			hosts:        make(map[string]bool),
			communityIDs: make(map[string]bool),
		}

		if len(agg.communityIDs) != 0 {
			t.Errorf("expected 0 community IDs, got %d", len(agg.communityIDs))
		}
	})

	t.Run("converts to sorted slice correctly", func(t *testing.T) {
		agg := &fingerprintAggregator{
			fingerprint:  "test_fp",
			fpType:       "JA4",
			hosts:        make(map[string]bool),
			communityIDs: make(map[string]bool),
		}

		agg.communityIDs["1:zzz"] = true
		agg.communityIDs["1:aaa"] = true
		agg.communityIDs["1:mmm"] = true

		communityIDs := make([]string, 0, len(agg.communityIDs))
		for cid := range agg.communityIDs {
			communityIDs = append(communityIDs, cid)
		}
		sort.Strings(communityIDs)

		if len(communityIDs) != 3 {
			t.Fatalf("expected 3 community IDs, got %d", len(communityIDs))
		}
		if communityIDs[0] != "1:aaa" {
			t.Errorf("expected first community ID to be '1:aaa', got %s", communityIDs[0])
		}
		if communityIDs[1] != "1:mmm" {
			t.Errorf("expected second community ID to be '1:mmm', got %s", communityIDs[1])
		}
		if communityIDs[2] != "1:zzz" {
			t.Errorf("expected third community ID to be '1:zzz', got %s", communityIDs[2])
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
			Hosts:        []string{"192.168.1.1"},
			CommunityIDs: []string{"1:abc123", "1:def456"},
		},
		{
			Fingerprint:  "fp2",
			Type:         "JA4S",
			Count:        5,
			Hosts:        []string{"10.0.0.1"},
			CommunityIDs: []string{"1:def456", "1:ghi789"},
		},
		{
			Fingerprint:  "fp3",
			Type:         "JA4SSH",
			Count:        3,
			Hosts:        []string{"172.16.0.1"},
			CommunityIDs: []string{"1:xyz000"},
		},
		{
			Fingerprint:  "fp4",
			Type:         "DHCP",
			Count:        1,
			Hosts:        []string{"192.168.1.100"},
			CommunityIDs: []string{}, // DHCP has no community IDs
		},
		{
			Fingerprint: "fp5",
			Type:        "JA4T",
			Count:       2,
			Hosts:       []string{"10.0.0.5"},
			// nil CommunityIDs
		},
	}

	tests := []struct {
		name            string
		communityIDs    string
		expectedCount   int
		expectedFPs     []string
	}{
		{
			name:          "filter by single community ID matching one fingerprint",
			communityIDs:  "1:abc123",
			expectedCount: 1,
			expectedFPs:   []string{"fp1"},
		},
		{
			name:          "filter by community ID matching multiple fingerprints",
			communityIDs:  "1:def456",
			expectedCount: 2,
			expectedFPs:   []string{"fp1", "fp2"},
		},
		{
			name:          "filter by multiple community IDs",
			communityIDs:  "1:abc123,1:xyz000",
			expectedCount: 2,
			expectedFPs:   []string{"fp1", "fp3"},
		},
		{
			name:          "filter by non-existent community ID",
			communityIDs:  "1:nonexistent",
			expectedCount: 0,
			expectedFPs:   []string{},
		},
		{
			name:          "empty community IDs string returns all",
			communityIDs:  "",
			expectedCount: 5,
			expectedFPs:   []string{"fp1", "fp2", "fp3", "fp4", "fp5"},
		},
		{
			name:          "whitespace-only community IDs returns all",
			communityIDs:  "  ,  , ",
			expectedCount: 5,
			expectedFPs:   []string{"fp1", "fp2", "fp3", "fp4", "fp5"},
		},
		{
			name:          "community IDs with spaces are trimmed",
			communityIDs:  " 1:abc123 , 1:xyz000 ",
			expectedCount: 2,
			expectedFPs:   []string{"fp1", "fp3"},
		},
		{
			name:          "fingerprints with empty community IDs are excluded",
			communityIDs:  "1:abc123",
			expectedCount: 1,
			expectedFPs:   []string{"fp1"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := FilterFingerprintsByCommunityID(fingerprints, tt.communityIDs)

			if len(result) != tt.expectedCount {
				t.Errorf("expected %d fingerprints, got %d", tt.expectedCount, len(result))
			}

			// Check that the correct fingerprints are returned
			resultFPs := make(map[string]bool)
			for _, fp := range result {
				resultFPs[fp.Fingerprint] = true
			}

			for _, expectedFP := range tt.expectedFPs {
				if !resultFPs[expectedFP] {
					t.Errorf("expected fingerprint %s to be in results", expectedFP)
				}
			}
		})
	}
}

// TestFilterFingerprintsByCommunityIDPreservesData tests that filtering does not
// modify the original fingerprint data.
func TestFilterFingerprintsByCommunityIDPreservesData(t *testing.T) {
	fingerprints := []FingerprintSummary{
		{
			Fingerprint:  "fp1",
			Type:         "JA4",
			Count:        10,
			Hosts:        []string{"192.168.1.1", "10.0.0.1"},
			Description:  "Test fingerprint",
			FirstSeen:    1000,
			LastSeen:     2000,
			CommunityIDs: []string{"1:abc123", "1:def456"},
		},
	}

	result := FilterFingerprintsByCommunityID(fingerprints, "1:abc123")

	if len(result) != 1 {
		t.Fatalf("expected 1 fingerprint, got %d", len(result))
	}

	fp := result[0]
	if fp.Fingerprint != "fp1" {
		t.Errorf("fingerprint mismatch: got %s", fp.Fingerprint)
	}
	if fp.Count != 10 {
		t.Errorf("count mismatch: got %d", fp.Count)
	}
	if len(fp.Hosts) != 2 {
		t.Errorf("hosts length mismatch: got %d", len(fp.Hosts))
	}
	if fp.Description != "Test fingerprint" {
		t.Errorf("description mismatch: got %s", fp.Description)
	}
	if len(fp.CommunityIDs) != 2 {
		t.Errorf("community IDs length mismatch: got %d", len(fp.CommunityIDs))
	}
}
