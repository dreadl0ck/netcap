package netio

import "strings"

func csvFields(fields []string, separator string) string {
	quoted := make([]string, len(fields))
	for i, s := range fields {
		if strings.ContainsAny(s, "\"\r\n") || separator != "" && strings.Contains(s, separator) {
			s = "\"" + strings.ReplaceAll(s, "\"", "\"\"") + "\""
		}
		quoted[i] = s
	}
	return strings.Join(quoted, separator)
}
