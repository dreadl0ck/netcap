package rules

import "github.com/dreadl0ck/netcap/types"

func compiledRulePlan(config *Config) map[types.Type][]*Rule {
	plan := make(map[types.Type][]*Rule)
	for _, rule := range config.Rules {
		if !rule.Enabled {
			continue
		}
		plan[rule.compiledType] = append(plan[rule.compiledType], rule)
		if rule.Sequence != nil && rule.Sequence.AfterType != "" {
			antecedent, _ := parseRecordType(rule.Sequence.AfterType)
			if antecedent != rule.compiledType {
				plan[antecedent] = append(plan[antecedent], rule)
			}
		}
	}
	return plan
}

func (e *Engine) rulesFor(recordType types.Type) []*Rule {
	if e.plan != nil {
		return e.plan[recordType]
	}
	return e.config.Rules
}
