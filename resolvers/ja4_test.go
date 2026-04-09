/*
 * NETCAP - Traffic Analysis Framework
 * Copyright (c) Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
 * License: GNU General Public License v3.0
 */

package resolvers

import (
	"encoding/json"
	"testing"
)

func TestJA4EntryGetDescription(t *testing.T) {
	testCases := []struct {
		name     string
		entry    JA4Entry
		expected string
	}{
		{
			name: "Application only",
			entry: JA4Entry{
				Application: "Chrome",
				Verified:    false,
			},
			expected: "Chrome",
		},
		{
			name: "Application with OS",
			entry: JA4Entry{
				Application: "Firefox",
				OS:          "Windows 10",
				Verified:    false,
			},
			expected: "Firefox / Windows 10",
		},
		{
			name: "Full entry verified",
			entry: JA4Entry{
				Application: "Safari",
				Library:     "WebKit",
				OS:          "macOS",
				Device:      "MacBook",
				Verified:    true,
				Notes:       "common browser",
			},
			expected: "Safari / WebKit / macOS / MacBook [verified] (common browser)",
		},
		{
			name: "Library only with notes",
			entry: JA4Entry{
				Library:  "Python requests",
				Verified: true,
				Notes:    "automated scanner",
			},
			expected: "Python requests [verified] (automated scanner)",
		},
		{
			name: "Entry with observation count",
			entry: JA4Entry{
				Application:      "curl",
				ObservationCount: 42,
				Verified:         true,
			},
			expected: "curl [verified]",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := tc.entry.GetDescription()
			if result != tc.expected {
				t.Errorf("Expected %q, got %q", tc.expected, result)
			}
		})
	}
}

func TestLookupJA4Empty(t *testing.T) {
	// Test that looking up a non-existent fingerprint returns empty string
	result := LookupJA4("nonexistent_fingerprint_12345")
	if result != "" {
		t.Errorf("Expected empty string for non-existent fingerprint, got %q", result)
	}
}

func TestLookupJA4SEmpty(t *testing.T) {
	// Test that looking up a non-existent fingerprint returns empty string
	result := LookupJA4S("nonexistent_fingerprint_12345")
	if result != "" {
		t.Errorf("Expected empty string for non-existent fingerprint, got %q", result)
	}
}

func TestLookupJA4HEmpty(t *testing.T) {
	result := LookupJA4H("nonexistent_fingerprint_12345")
	if result != "" {
		t.Errorf("Expected empty string for non-existent fingerprint, got %q", result)
	}
}

func TestLookupJA4XEmpty(t *testing.T) {
	result := LookupJA4X("nonexistent_fingerprint_12345")
	if result != "" {
		t.Errorf("Expected empty string for non-existent fingerprint, got %q", result)
	}
}

func TestLookupJA4TEmpty(t *testing.T) {
	result := LookupJA4T("nonexistent_fingerprint_12345")
	if result != "" {
		t.Errorf("Expected empty string for non-existent fingerprint, got %q", result)
	}
}

func TestLookupJA4TSEmpty(t *testing.T) {
	result := LookupJA4TS("nonexistent_fingerprint_12345")
	if result != "" {
		t.Errorf("Expected empty string for non-existent fingerprint, got %q", result)
	}
}

func TestLookupJA4TScanEmpty(t *testing.T) {
	result := LookupJA4TScan("nonexistent_fingerprint_12345")
	if result != "" {
		t.Errorf("Expected empty string for non-existent fingerprint, got %q", result)
	}
}

func TestLookupJA4EntryEmpty(t *testing.T) {
	entry := LookupJA4Entry("nonexistent_fingerprint_12345")
	if entry != nil {
		t.Errorf("Expected nil for non-existent fingerprint, got %v", entry)
	}
}

func TestGetJA4DBSize(t *testing.T) {
	// Without initialization, size should be 0
	size := GetJA4DBSize()
	// This just verifies the function works - actual size depends on whether DB is loaded
	t.Logf("JA4 DB size: %d entries", size)
}

func TestGetJA4SDBSize(t *testing.T) {
	// Without initialization, size should be 0
	size := GetJA4SDBSize()
	t.Logf("JA4S DB size: %d entries", size)
}

func TestGetJA4HDBSize(t *testing.T) {
	size := GetJA4HDBSize()
	t.Logf("JA4H DB size: %d entries", size)
}

func TestGetJA4XDBSize(t *testing.T) {
	size := GetJA4XDBSize()
	t.Logf("JA4X DB size: %d entries", size)
}

func TestGetJA4TDBSize(t *testing.T) {
	size := GetJA4TDBSize()
	t.Logf("JA4T DB size: %d entries", size)
}

func TestGetJA4TSDBSize(t *testing.T) {
	size := GetJA4TSDBSize()
	t.Logf("JA4TS DB size: %d entries", size)
}

func TestGetJA4TScanDBSize(t *testing.T) {
	size := GetJA4TScanDBSize()
	t.Logf("JA4TScan DB size: %d entries", size)
}

func TestJA4EntryJSONParsing(t *testing.T) {
	// Test JSON parsing matches the ja4db.com format with null values
	sampleJSON := `[
		{
			"application": null,
			"library": null,
			"device": null,
			"os": null,
			"user_agent_string": "Mozilla/5.0 (compatible; Example/1.0)",
			"certificate_authority": null,
			"observation_count": 7,
			"verified": false,
			"notes": null,
			"ja4_fingerprint": "t13d291300_723694b0fccc_899037bd0b8c",
			"ja4_fingerprint_string": "t13d...",
			"ja4s_fingerprint": null,
			"ja4h_fingerprint": "ge11nr12enus_adf4493e07de_000000000000_e3b0c44298fc",
			"ja4x_fingerprint": null,
			"ja4t_fingerprint": null,
			"ja4ts_fingerprint": null,
			"ja4tscan_fingerprint": null
		},
		{
			"application": "Chrome",
			"library": "BoringSSL",
			"device": "Desktop",
			"os": "Windows 10",
			"user_agent_string": "Chrome/120",
			"certificate_authority": null,
			"observation_count": 1500,
			"verified": true,
			"notes": "Common browser fingerprint",
			"ja4_fingerprint": "t13d1516h2_8daaf6152771_02713d6af862",
			"ja4_fingerprint_string": "t13d1516h2...",
			"ja4s_fingerprint": "t130200_1302_a56c5b993250",
			"ja4h_fingerprint": null,
			"ja4x_fingerprint": "a_b_c",
			"ja4t_fingerprint": "64_2_1460_00",
			"ja4ts_fingerprint": "28960_2-4-8-1-3_1460_8",
			"ja4tscan_fingerprint": "scan_fp_123"
		}
	]`

	var entries []JA4Entry
	err := json.Unmarshal([]byte(sampleJSON), &entries)
	if err != nil {
		t.Fatalf("Failed to parse sample JSON: %v", err)
	}

	if len(entries) != 2 {
		t.Fatalf("Expected 2 entries, got %d", len(entries))
	}

	// Check first entry (with null values)
	e1 := entries[0]
	if e1.Application != "" {
		t.Errorf("Expected empty Application for null, got %q", e1.Application)
	}
	if e1.JA4Fingerprint != "t13d291300_723694b0fccc_899037bd0b8c" {
		t.Errorf("Unexpected JA4 fingerprint: %s", e1.JA4Fingerprint)
	}
	if e1.JA4HFingerprint != "ge11nr12enus_adf4493e07de_000000000000_e3b0c44298fc" {
		t.Errorf("Unexpected JA4H fingerprint: %s", e1.JA4HFingerprint)
	}
	if e1.ObservationCount != 7 {
		t.Errorf("Expected observation_count 7, got %d", e1.ObservationCount)
	}
	if e1.JA4SFingerprint != "" {
		t.Errorf("Expected empty JA4S for null, got %q", e1.JA4SFingerprint)
	}

	// Check second entry (with all values)
	e2 := entries[1]
	if e2.Application != "Chrome" {
		t.Errorf("Expected Application 'Chrome', got %q", e2.Application)
	}
	if e2.Library != "BoringSSL" {
		t.Errorf("Expected Library 'BoringSSL', got %q", e2.Library)
	}
	if e2.OS != "Windows 10" {
		t.Errorf("Expected OS 'Windows 10', got %q", e2.OS)
	}
	if !e2.Verified {
		t.Error("Expected Verified to be true")
	}
	if e2.ObservationCount != 1500 {
		t.Errorf("Expected observation_count 1500, got %d", e2.ObservationCount)
	}
	if e2.JA4SFingerprint != "t130200_1302_a56c5b993250" {
		t.Errorf("Unexpected JA4S fingerprint: %s", e2.JA4SFingerprint)
	}
	if e2.JA4XFingerprint != "a_b_c" {
		t.Errorf("Unexpected JA4X fingerprint: %s", e2.JA4XFingerprint)
	}
	if e2.JA4TFingerprint != "64_2_1460_00" {
		t.Errorf("Unexpected JA4T fingerprint: %s", e2.JA4TFingerprint)
	}
	if e2.JA4TSFingerprint != "28960_2-4-8-1-3_1460_8" {
		t.Errorf("Unexpected JA4TS fingerprint: %s", e2.JA4TSFingerprint)
	}
	if e2.JA4TScanFingerprint != "scan_fp_123" {
		t.Errorf("Unexpected JA4TScan fingerprint: %s", e2.JA4TScanFingerprint)
	}

	// Test description generation
	desc := e2.GetDescription()
	expected := "Chrome / BoringSSL / Windows 10 / Desktop [verified] (Common browser fingerprint)"
	if desc != expected {
		t.Errorf("Expected description %q, got %q", expected, desc)
	}
}

