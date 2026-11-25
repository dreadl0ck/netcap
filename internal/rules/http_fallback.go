package rules

import (
	"slices"
	"strings"

	"github.com/dreadl0ck/netcap/internal/filter"
	"github.com/dreadl0ck/netcap/types"
)

const netSupportClientRule = "NetSupport Manager RAT User Agent Detected"

// Coalesce the shipped HTTP fallbacks only when the same record matches the
// active client rule. Pair-level deduplication still applies to that finding.
func coalescedNetSupportPoll(rule *Rule, record types.AuditRecord, plan []*Rule, env map[string]any) bool {
	switch rule.Name {
	case "HTTP POST to IP":
		if rule.Expression != `Method == "POST" && MatchesPattern(Host, "^[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+$")` {
			return false
		}
	case "Unknown HTTP Proxy Detection":
		if rule.Expression != `Method == "CONNECT" || MatchesPattern(URL, "^https?://")` {
			return false
		}
	default:
		return false
	}
	h, ok := record.(*types.HTTP)
	if !ok || h.Method == "CONNECT" || !strings.HasPrefix(strings.ToLower(h.UserAgent), "netsupport manager") ||
		rule.Sequence != nil || rule.Threshold > 1 || rule.DistinctField != "" || len(rule.Actions) != 0 {
		return false
	}
	for _, specific := range plan {
		if specific.Name != netSupportClientRule || !specific.Enabled || specific.compiledType != types.Type_NC_HTTP ||
			specific.EffectiveKind() != KindFinding || specific.Sequence != nil || specific.Threshold > 1 || specific.DistinctField != "" ||
			len(specific.DedupeBy) > 0 && !slices.Equal(specific.DedupeBy, []string{"SrcIP", "DstIP"}) {
			continue
		}
		matched, err := filter.EvaluateEnvironment(specific.compiled, env)
		if err == nil && matched {
			return true
		}
	}
	return false
}
