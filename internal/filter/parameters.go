package filter

import "slices"

// ParamMatches looks only at parsed parameter values. Limits are deterministic
// and shared by the live and audit replay evaluators.
func ParamMatches(parameters map[string]string, pattern string) bool {
	if len(parameters) == 0 || len(parameters) > 256 {
		return false
	}
	keys := make([]string, 0, len(parameters))
	for key := range parameters {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	remaining := 64 << 10
	for _, key := range keys {
		value := parameters[key]
		n := min(len(value), 8<<10, remaining)
		if MatchesPattern(value[:n], pattern) {
			return true
		}
		remaining -= n
		if remaining == 0 {
			break
		}
	}
	return false
}
