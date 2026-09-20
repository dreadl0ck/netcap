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
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/dreadl0ck/netcap/rules"
	"gopkg.in/yaml.v2"
)

func TestRuleDistinctConfigRoundTrip(t *testing.T) {
	for _, tagged := range []bool{false, true} {
		name := "orphan"
		if tagged {
			name = "ruleset"
		}
		t.Run(name, func(t *testing.T) {
			s := &Server{outDir: filepath.Join(t.TempDir(), "capture"), rulesConfig: &rules.Config{}}
			payload := map[string]any{
				"name": "cardinality", "type": "TCP", "expression": "true", "severity": "medium",
				"enabled": true, "threshold": 9, "thresholdWindow": 120,
				"distinctField": "DstIP", "distinctThreshold": 5,
			}
			filename := "cardinality.yml"
			if tagged {
				payload["tags"] = []string{"ruleset:custom"}
				filename = "custom.yml"
			}
			for _, stage := range []string{"create", "update", "clear"} {
				t.Run(stage, func(t *testing.T) {
					if stage == "update" {
						payload["distinctField"] = "DstPort"
						payload["distinctThreshold"] = 7
					} else if stage == "clear" {
						payload["distinctField"] = ""
						payload["distinctThreshold"] = 0
					}
					field := payload["distinctField"].(string)
					count := payload["distinctThreshold"].(int)
					assertRule := func(rule RuleResponse) {
						t.Helper()
						if rule.DistinctField != field || rule.DistinctThreshold != count || rule.Threshold != 9 || rule.ThresholdWindow != 120 {
							t.Fatalf("threshold settings lost: %+v", rule)
						}
					}
					body, err := json.Marshal(payload)
					if err != nil {
						t.Fatal(err)
					}
					w := httptest.NewRecorder()
					if stage == "create" {
						s.handleRules(w, httptest.NewRequest(http.MethodPost, "/api/rules", strings.NewReader(string(body))))
						if w.Code != http.StatusCreated {
							t.Fatalf("create: %d %s", w.Code, w.Body.String())
						}
						var response struct {
							Rule RuleResponse `json:"rule"`
						}
						if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
							t.Fatal(err)
						}
						assertRule(response.Rule)
					} else {
						s.handleRule(w, httptest.NewRequest(http.MethodPut, "/api/rules/cardinality", strings.NewReader(string(body))))
						if w.Code != http.StatusOK {
							t.Fatalf("update: %d %s", w.Code, w.Body.String())
						}
					}
					data, err := os.ReadFile(filepath.Join(s.getRulesFolderPath(), filename))
					if err != nil {
						t.Fatal(err)
					}
					var saved rules.Config
					if err := yaml.Unmarshal(data, &saved); err != nil {
						t.Fatal(err)
					}
					if len(saved.Rules) != 1 || saved.Rules[0].DistinctField != field || saved.Rules[0].DistinctThreshold != count {
						t.Fatalf("saved settings lost: %s", data)
					}
					s.invalidateRulesCache()
					w = httptest.NewRecorder()
					s.handleRules(w, httptest.NewRequest(http.MethodGet, "/api/rules", nil))
					var listed RulesConfigResponse
					if err := json.Unmarshal(w.Body.Bytes(), &listed); err != nil || w.Code != http.StatusOK {
						t.Fatalf("list: %d %s (%v)", w.Code, w.Body.String(), err)
					}
					found := false
					for _, rule := range listed.Rules {
						if rule.Name == "cardinality" {
							assertRule(rule)
							found = true
						}
					}
					if !found {
						t.Fatal("rule missing after reload")
					}
					w = httptest.NewRecorder()
					s.handleRule(w, httptest.NewRequest(http.MethodGet, "/api/rules/cardinality", nil))
					var fetched RuleResponse
					if err := json.Unmarshal(w.Body.Bytes(), &fetched); err != nil || w.Code != http.StatusOK {
						t.Fatalf("get: %d %s (%v)", w.Code, w.Body.String(), err)
					}
					assertRule(fetched)
					// Keep subsequent saves scoped to the test rule, not embedded defaults.
					s.rulesConfig = &saved
					if tagged {
						saved.Rules[0].Tags = []string{"ruleset:custom"}
					}
				})
			}
		})
	}
}

// TestRuleSetToggleKeepsDistinctConfig guards the rule set override writer:
// toggling a set must not silently downgrade a cardinality rule into a plain
// per-match rule, which would flood alerts and lose the operator's config.
func TestRuleSetToggleKeepsDistinctConfig(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		name := "disable"
		if enabled {
			name = "enable"
		}
		t.Run(name, func(t *testing.T) {
			s := &Server{outDir: filepath.Join(t.TempDir(), "capture")}
			s.rulesConfig = &rules.Config{Rules: []*rules.Rule{{
				Name: "fan-out", Type: "TCP", Expression: "true", Severity: "medium",
				Enabled: !enabled, Threshold: 1, ThresholdWindow: 300,
				DistinctField: "DstIP", DistinctThreshold: 5,
				Sequence: &rules.Sequence{
					After: "true", GroupBy: []string{"SrcIP", "DstIP"}, Within: 900,
				},
				Tags: []string{"scan", "ruleset:cardinality"},
			}}}

			body := strings.NewReader(fmt.Sprintf(`{"enabled":%v}`, enabled))
			w := httptest.NewRecorder()
			s.handleRuleSet(w, httptest.NewRequest(http.MethodPut, "/api/rule-sets/cardinality", body))
			if w.Code != http.StatusOK {
				t.Fatalf("toggle: %d %s", w.Code, w.Body.String())
			}

			data, err := os.ReadFile(filepath.Join(s.getRulesFolderPath(), "cardinality.yml"))
			if err != nil {
				t.Fatal(err)
			}
			var saved rules.Config
			if err := yaml.Unmarshal(data, &saved); err != nil {
				t.Fatal(err)
			}
			if len(saved.Rules) != 1 {
				t.Fatalf("got %d rules, want 1: %s", len(saved.Rules), data)
			}
			rule := saved.Rules[0]
			if rule.DistinctField != "DstIP" || rule.DistinctThreshold != 5 {
				t.Fatalf("cardinality settings lost, rule downgraded to per-match: %s", data)
			}
			// Losing the sequence would turn a gated rule into one that alerts
			// on every matching record.
			if rule.Sequence == nil || rule.Sequence.After != "true" ||
				rule.Sequence.Within != 900 || len(rule.Sequence.GroupBy) != 2 {
				t.Fatalf("sequence configuration lost: %s", data)
			}
			if rule.Enabled != enabled || rule.ThresholdWindow != 300 {
				t.Fatalf("toggle or window lost: %s", data)
			}
			if slices.Contains(rule.Tags, "ruleset:cardinality") || !slices.Contains(rule.Tags, "scan") {
				t.Fatalf("internal tags mishandled: %v", rule.Tags)
			}
		})
	}
}

// TestSanitizeFilename tests the sanitization of rule names for use as filenames.
// This is critical for preventing path traversal issues and filesystem errors when
// rule names contain special characters like forward slashes.
func TestSanitizeFilename(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "forward slash",
			input:    "RTP Audio/Video Stream Detected",
			expected: "RTP_Audio_Video_Stream_Detected",
		},
		{
			name:     "backslash",
			input:    "Windows\\Path\\Rule",
			expected: "Windows_Path_Rule",
		},
		{
			name:     "multiple special characters",
			input:    "Rule: Name (with) [special] {chars}!",
			expected: "Rule__Name__with___special___chars__",
		},
		{
			name:     "spaces",
			input:    "My Rule Name",
			expected: "My_Rule_Name",
		},
		{
			name:     "already safe",
			input:    "Safe_Rule_Name-123",
			expected: "Safe_Rule_Name-123",
		},
		{
			name:     "empty string",
			input:    "",
			expected: "rule",
		},
		{
			name:     "only special characters",
			input:    "///:::***",
			expected: "_________",
		},
		{
			name:     "unicode characters",
			input:    "Rule_中文_Name",
			expected: "Rule____Name",
		},
		{
			name:     "dots and colons",
			input:    "DNS:A:Record.Query",
			expected: "DNS_A_Record_Query",
		},
		{
			name:     "ampersand and plus",
			input:    "HTTP&HTTPS+Rule",
			expected: "HTTP_HTTPS_Rule",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := sanitizeFilename(tt.input)
			if result != tt.expected {
				t.Errorf("sanitizeFilename(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

// TestSanitizeFilenamePropertiespreserves properties that safe filenames should have
func TestSanitizeFilenameProperties(t *testing.T) {
	tests := []string{
		"RTP Audio/Video Stream Detected",
		"Windows\\Path",
		"../../../etc/passwd",
		"Rule: Name",
		"",
		"!@#$%^&*()",
	}

	for _, input := range tests {
		t.Run(input, func(t *testing.T) {
			result := sanitizeFilename(input)

			// Must not be empty
			if result == "" {
				t.Error("sanitizeFilename returned empty string")
			}

			// Must not contain path separators
			if strings.Contains(result, "/") || strings.Contains(result, "\\") {
				t.Errorf("sanitizeFilename(%q) = %q contains path separator", input, result)
			}

			// Must only contain safe characters
			for _, r := range result {
				if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_') {
					t.Errorf("sanitizeFilename(%q) = %q contains unsafe character %q", input, result, string(r))
				}
			}
		})
	}
}
