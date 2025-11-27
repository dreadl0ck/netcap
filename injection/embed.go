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

