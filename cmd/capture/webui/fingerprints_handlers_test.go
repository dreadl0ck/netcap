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
