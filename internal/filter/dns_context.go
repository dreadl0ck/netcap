package filter

import "strings"

// DNSResolutionMatches evaluates only the immutable fields of the observation.
// Matching is exact after DNS case/trailing-dot normalization, never a regex.
func DNSResolutionMatches(state, name string, answeredAt, at int64, domain string, maxAgeNS int64) bool {
	if state != "resolved" || name == "" || domain == "" || at < answeredAt || maxAgeNS < 0 {
		return false
	}
	if uint64(at)-uint64(answeredAt) > uint64(maxAgeNS) {
		return false
	}
	return strings.EqualFold(strings.TrimSuffix(name, "."), strings.TrimSuffix(domain, "."))
}
