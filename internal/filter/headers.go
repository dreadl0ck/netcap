package filter

import "strings"

func HeaderValue(headers map[string]string, name string) string {
	if value, ok := headers[name]; ok {
		return value
	}
	selected := ""
	for key := range headers {
		if strings.EqualFold(key, name) && (selected == "" || key < selected) {
			selected = key
		}
	}
	if selected == "" {
		return ""
	}
	return headers[selected]
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
