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

package rules

import (
	"embed"
	"fmt"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v2"
)

// Embed all example detection rules
//
//go:embed examples/*.yml
var embeddedRulesFS embed.FS

// LoadEmbeddedRules loads all embedded default detection rules.
// These are bundled into the binary at compile time.
func LoadEmbeddedRules() (*Config, error) {
	config := &Config{
		Description: "Embedded default detection rules",
		Rules:       []*Rule{},
	}

	entries, err := embeddedRulesFS.ReadDir("examples")
	if err != nil {
		return nil, fmt.Errorf("failed to read embedded rules directory: %w", err)
	}

	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".yml") {
			continue
		}

		data, err := embeddedRulesFS.ReadFile(filepath.Join("examples", entry.Name()))
		if err != nil {
			return nil, fmt.Errorf("failed to read embedded rule file %s: %w", entry.Name(), err)
		}

		var fileConfig Config
		if err := yaml.Unmarshal(data, &fileConfig); err != nil {
			return nil, fmt.Errorf("failed to parse embedded rule file %s: %w", entry.Name(), err)
		}

		// Tag each rule with its source file (used for rule set management)
		ruleSetName := strings.TrimSuffix(entry.Name(), ".yml")
		for _, rule := range fileConfig.Rules {
			if rule.Tags == nil {
				rule.Tags = []string{}
			}
			// Add embedded tag and ruleset tag
			rule.Tags = append(rule.Tags, "embedded", "ruleset:"+ruleSetName)
		}

		config.Rules = append(config.Rules, fileConfig.Rules...)
	}

	return config, nil
}

// LoadRulesWithEmbeddedDefaults loads rules from a directory path,
// but first loads embedded defaults. File rules override embedded rules
// with the same name.
func LoadRulesWithEmbeddedDefaults(dirPath string) (*Config, error) {
	// Start with embedded defaults
	config, err := LoadEmbeddedRules()
	if err != nil {
		// If embedded rules fail, start with empty config
		config = &Config{Rules: []*Rule{}}
	}

	// If no path specified, just return embedded rules
	if dirPath == "" {
		return config, nil
	}

	// Try to load from directory
	fileConfig, err := LoadRulesFromDirectory(dirPath)
	if err != nil {
		// If directory loading fails, just return embedded rules
		return config, nil
	}

	// Merge file rules with embedded (file rules override by name)
	config = MergeConfigs(config, fileConfig)

	return config, nil
}

// MergeConfigs merges two configs, with override rules taking precedence.
// Rules with matching names in override replace rules in base.
func MergeConfigs(base, override *Config) *Config {
	if base == nil {
		return override
	}
	if override == nil {
		return base
	}

	// Create a map of base rules by name for efficient lookup
	baseRuleMap := make(map[string]*Rule)
	for _, rule := range base.Rules {
		baseRuleMap[rule.Name] = rule
	}

	// Override/add rules from override config
	for _, rule := range override.Rules {
		baseRuleMap[rule.Name] = rule
	}

	// Rebuild rules slice
	merged := &Config{
		Description: base.Description,
		Rules:       make([]*Rule, 0, len(baseRuleMap)),
	}

	// Keep description from override if present
	if override.Description != "" {
		merged.Description = override.Description
	}

	// First add all rules from base (maintains original order for embedded rules)
	addedNames := make(map[string]bool)
	for _, rule := range base.Rules {
		merged.Rules = append(merged.Rules, baseRuleMap[rule.Name])
		addedNames[rule.Name] = true
	}

	// Then add new rules from override that weren't in base
	for _, rule := range override.Rules {
		if !addedNames[rule.Name] {
			merged.Rules = append(merged.Rules, rule)
		}
	}

	return merged
}

// GetEmbeddedRuleSetNames returns a list of embedded rule set names (without .yml extension).
func GetEmbeddedRuleSetNames() ([]string, error) {
	entries, err := embeddedRulesFS.ReadDir("examples")
	if err != nil {
		return nil, fmt.Errorf("failed to read embedded rules directory: %w", err)
	}

	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".yml") {
			continue
		}
		names = append(names, strings.TrimSuffix(entry.Name(), ".yml"))
	}

	return names, nil
}

// EmbeddedRuleSetInfo contains information about an embedded rule set.
type EmbeddedRuleSetInfo struct {
	Name        string
	Description string
	RuleCount   int
}

// GetEmbeddedRuleSetInfo returns information about all embedded rule sets including descriptions.
func GetEmbeddedRuleSetInfo() (map[string]EmbeddedRuleSetInfo, error) {
	entries, err := embeddedRulesFS.ReadDir("examples")
	if err != nil {
		return nil, fmt.Errorf("failed to read embedded rules directory: %w", err)
	}

	info := make(map[string]EmbeddedRuleSetInfo)
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".yml") {
			continue
		}

		name := strings.TrimSuffix(entry.Name(), ".yml")

		data, err := embeddedRulesFS.ReadFile(filepath.Join("examples", entry.Name()))
		if err != nil {
			continue
		}

		var fileConfig Config
		if err := yaml.Unmarshal(data, &fileConfig); err != nil {
			continue
		}

		info[name] = EmbeddedRuleSetInfo{
			Name:        name,
			Description: fileConfig.Description,
			RuleCount:   len(fileConfig.Rules),
		}
	}

	return info, nil
}
