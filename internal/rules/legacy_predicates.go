package rules

import (
	"bytes"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"strings"

	"gopkg.in/yaml.v2"
)

var legacyPredicateDigests = map[string]bool{
	"ae66a4bed9279f87559ebe3205732c43b6d96fc9aa3f6f4dcc36466bbec0cbda": true,
	"da3368da9a47a526bf986f0355b4d2393857af6c1862824e1d76b1105e7778ee": true,
	"030a2f7890d2e66779ad55a65315fbc306e01db0e582535b8566ad9437034e31": true,
	"7ebc9c8ec654f5ce792c25dd114f46d5137ed1b02ac8a00508140603fe75a404": true,
	"e7e1c1018d79f3fce0690c3901afa2f7b3d9f1741830db766b2f76bccc12689b": true,
}

//go:embed legacy_defaults.yml
var legacyDefaultsYAML []byte

// legacyDefaults maps a rule name to the normalized YAML of its superseded
// embedded definitions.
var legacyDefaults = comparableDefaults(legacyDefaultsYAML, "legacy_defaults.yml")

// Defaults removed from the embedded set, as last shipped. A saved copy that
// still equals one is dropped instead of loading as an operator rule.
//
//go:embed retired_defaults.yml
var retiredDefaultsYAML []byte

var retiredDefaults = comparableDefaults(retiredDefaultsYAML, "retired_defaults.yml")

func comparableDefaults(data []byte, name string) map[string][][]byte {
	var config Config
	if err := yaml.Unmarshal(data, &config); err != nil {
		panic(name + ": " + err.Error())
	}
	out := map[string][][]byte{}
	for _, rule := range config.Rules {
		out[rule.Name] = append(out[rule.Name], legacyComparable(rule))
	}
	return out
}

func isRetiredDefault(rule *Rule) bool {
	saved := legacyComparable(rule)
	for _, retired := range retiredDefaults[rule.Name] {
		if saved != nil && bytes.Equal(saved, retired) {
			return true
		}
	}
	return false
}

// MigrateSavedDefaults applies the rules-folder migration to a configuration
// loaded on its own, such as capture -rules DIR: unchanged copies of
// superseded defaults load as the current default and retired ones drop out.
func MigrateSavedDefaults(config *Config) (*Config, error) {
	embedded, err := LoadEmbeddedRules()
	if err != nil {
		return nil, err
	}
	current := map[string]*Rule{}
	for _, rule := range embedded.Rules {
		current[rule.Name] = rule
	}
	migrated := *config
	migrated.Rules = make([]*Rule, 0, len(config.Rules))
	for _, rule := range config.Rules {
		if base := current[rule.Name]; base != nil {
			migrated.Rules = append(migrated.Rules, migrateLegacyPredicate(base, rule))
		} else if !isRetiredDefault(rule) {
			migrated.Rules = append(migrated.Rules, rule)
		}
	}
	return &migrated, nil
}

// legacyComparable renders the fields an unchanged saved default shares
// with the shipped definition; enabled is the operator's choice.
func legacyComparable(rule *Rule) []byte {
	copy := normalizedRuleCopy(rule)
	copy.Enabled = false
	data, err := yaml.Marshal(copy)
	if err != nil {
		return nil
	}
	return data
}

func normalizedRuleCopy(rule *Rule) Rule {
	copy := *rule
	copy.Tags = nil
	for _, tag := range rule.Tags {
		if tag != "embedded" && !strings.HasPrefix(tag, "ruleset:") {
			copy.Tags = append(copy.Tags, tag)
		}
	}
	return copy
}

// Only unchanged saved defaults qualify; customized predicates or metadata stay owned by the operator.
func migrateLegacyPredicate(base, override *Rule) *Rule {
	if base == nil || override == nil {
		return override
	}
	// A saved copy of a superseded default (WebUI saves write whole rule
	// sets) would otherwise shadow the fixed embedded rule forever.
	if saved := legacyComparable(override); saved != nil {
		for _, legacy := range legacyDefaults[override.Name] {
			if bytes.Equal(saved, legacy) {
				migrated := base.SavedCopy()
				migrated.Enabled = override.Enabled
				migrated.Tags = override.Tags
				return &migrated
			}
		}
	}
	digest := sha256.Sum256([]byte(override.Expression))
	if !legacyPredicateDigests[hex.EncodeToString(digest[:])] {
		return override
	}
	candidate := normalizedRuleCopy(override)
	candidate.Expression = base.Expression
	expected := normalizedRuleCopy(base)
	a, errA := yaml.Marshal(candidate)
	b, errB := yaml.Marshal(expected)
	if errA != nil || errB != nil || !bytes.Equal(a, b) {
		return override
	}
	copy := *override
	copy.Expression, copy.compiled = base.Expression, nil
	return &copy
}
