package webui

import (
	"fmt"
	"net/http"
	"slices"
	"strings"

	"github.com/dreadl0ck/netcap/internal/rules"
	"github.com/dreadl0ck/netcap/types"
)

// alertKind is "inventory" for alerts of inventory rules, else "finding".
// Rule alerts written before kinds existed carry no tag; their info severity
// decides, as it does for a rule without a kind.
func alertKind(alert *types.Alert) string {
	switch {
	case slices.Contains(alert.Tags, rules.InventoryTag):
		return rules.KindInventory
	case slices.Contains(alert.Tags, rules.FindingTag):
		return rules.KindFinding
	case alert.RecordType == "NetworkDetection" && alert.RuleName == "policy.cleartext-service" && strings.EqualFold(alert.Severity, "info"):
		return rules.KindInventory
	case alert.RuleExpression != "" && strings.EqualFold(alert.Severity, "info"):
		return rules.KindInventory
	}
	return rules.KindFinding
}

// alertKindFilter reads ?kind=finding|inventory|all. Alert views list
// findings by default: inventory rules record that a service exists, and on
// the evaluation corpus they outnumbered findings several times over.
func alertKindFilter(r *http.Request) (func(*types.Alert) bool, error) {
	switch kind := r.URL.Query().Get("kind"); kind {
	case "", rules.KindFinding:
		return func(a *types.Alert) bool { return alertKind(a) == rules.KindFinding }, nil
	case rules.KindInventory:
		return func(a *types.Alert) bool { return alertKind(a) == rules.KindInventory }, nil
	case "all":
		return func(*types.Alert) bool { return true }, nil
	default:
		return nil, fmt.Errorf("kind must be finding, inventory or all")
	}
}
