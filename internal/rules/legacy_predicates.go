package rules

import (
	"bytes"
	"crypto/sha256"
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
