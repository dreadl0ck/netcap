package webui

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

func projectRecordJSON(raw []byte, fields string) ([]byte, error) {
	if fields == "" {
		return raw, nil
	}
	paths := strings.Split(fields, ",")
	if len(paths) > 32 {
		return nil, fmt.Errorf("at most 32 field paths are allowed")
	}
	out := make(map[string]json.RawMessage, len(paths))
	for _, path := range paths {
		path = strings.TrimSpace(path)
		if path == "" {
			return nil, fmt.Errorf("empty field path")
		}
		parts := []string{path}
		if strings.HasPrefix(path, "/") {
			parts = strings.Split(path[1:], "/")
		}
		if len(parts) > 8 {
			return nil, fmt.Errorf("field path exceeds 8 levels")
		}
		value := json.RawMessage(raw)
		for _, part := range parts {
			part = strings.ReplaceAll(strings.ReplaceAll(part, "~1", "/"), "~0", "~")
			if len(value) > 0 && value[0] == '[' {
				var items []json.RawMessage
				if err := json.Unmarshal(value, &items); err != nil {
					return nil, err
				}
				index, err := strconv.Atoi(part)
				if err != nil || index < 0 || index >= len(items) {
					return nil, fmt.Errorf("array field path %q is out of range", path)
				}
				value = items[index]
			} else {
				var object map[string]json.RawMessage
				if err := json.Unmarshal(value, &object); err != nil {
					return nil, fmt.Errorf("field path %q does not select an object", path)
				}
				var ok bool
				value, ok = object[part]
				if !ok {
					return nil, fmt.Errorf("field path %q is absent; inspect get_audit_record_fields or omit fields", path)
				}
			}
		}
		out[path] = value
	}
	return json.Marshal(out)
}
