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

package injection

import (
	"embed"
	"fmt"

	"gopkg.in/yaml.v2"
)

// Embed the default injection rules
//
//go:embed rules/injection-rules.yml
var embeddedRulesFS embed.FS

// LoadEmbeddedRules loads the embedded default injection rules.
// These are bundled into the binary at compile time.
func LoadEmbeddedRules() (*Config, error) {
	data, err := embeddedRulesFS.ReadFile("rules/injection-rules.yml")
	if err != nil {
		return nil, fmt.Errorf("failed to read embedded rules: %w", err)
	}

	var config Config
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to parse embedded rules: %w", err)
	}

	return &config, nil
}

// LoadRulesWithEmbeddedDefaults loads rules from a file/directory path,
// but first loads embedded defaults. File rules override embedded rules
// with the same name.
func LoadRulesWithEmbeddedDefaults(path string) (*Config, error) {
	// Start with embedded defaults
	config, err := LoadEmbeddedRules()
	if err != nil {
		// If embedded rules fail, start with empty config
		config = &Config{Rules: []*Rule{}}
	}

	// If no path specified, just return embedded rules
	if path == "" {
		return config, nil
	}

	// Try to load from file/directory
	fileConfig, err := LoadRules(path)
	if err != nil {
		// If file loading fails, just return embedded rules
		return config, nil
	}

	// Merge file rules with embedded (file rules override by name)
	config = mergeConfigs(config, fileConfig)

	return config, nil
}

// mergeConfigs merges two configs, with override rules taking precedence.
// Rules with matching names in override replace rules in base.
func mergeConfigs(base, override *Config) *Config {
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
		Description: override.Description,
		Rules:       make([]*Rule, 0, len(baseRuleMap)),
	}

	// First add all rules from override (maintains order)
	addedNames := make(map[string]bool)
	for _, rule := range override.Rules {
		merged.Rules = append(merged.Rules, rule)
		addedNames[rule.Name] = true
	}

	// Then add remaining base rules that weren't overridden
	for _, rule := range base.Rules {
		if !addedNames[rule.Name] {
			merged.Rules = append(merged.Rules, rule)
		}
	}

	return merged
}
