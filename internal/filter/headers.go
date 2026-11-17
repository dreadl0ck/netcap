package filter

import "strings"

func HeaderValue(headers map[string]string, name string) string {
	for key, value := range headers {
		if strings.EqualFold(key, name) {
			return value
		}
	}
	return ""
}

func HasHeaderPrefix(headers map[string]string, prefix string) bool {
	prefix = strings.ToLower(prefix)
	for key, value := range headers {
		if value != "" && strings.HasPrefix(strings.ToLower(key), prefix) {
			return true
		}
	}
	return false
}
