/*
 * NETCAP - Traffic Analysis Framework
 * Copyright (c) 2017-2020 Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
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
