package webui

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

type projectionPath struct {
	name  string
	parts []string
}

func parseRecordProjection(fields string) ([]projectionPath, error) {
	if fields == "" {
		return nil, nil
	}
	paths := strings.Split(fields, ",")
	if len(paths) > 32 {
		return nil, fmt.Errorf("at most 32 field paths are allowed")
	}
	projection := make([]projectionPath, 0, len(paths))
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
		for i, part := range parts {
			parts[i] = strings.ReplaceAll(strings.ReplaceAll(part, "~1", "/"), "~0", "~")
		}
		projection = append(projection, projectionPath{path, parts})
	}
	return projection, nil
}

func projectRecordJSON(raw []byte, fields string) ([]byte, error) {
	projection, err := parseRecordProjection(fields)
	if err != nil {
		return nil, err
	}
	return applyRecordProjection(raw, projection)
}

func applyRecordProjection(raw []byte, projection []projectionPath) ([]byte, error) {
	if len(projection) == 0 {
		return raw, nil
	}
	root, err := decodeProjectionContainer(raw, projection[0].name)
	if err != nil {
		return nil, err
	}
	out := make(map[string]json.RawMessage, len(projection))
	for _, path := range projection {
		container := &root
		for i, part := range path.parts {
			value, err := container.selectPart(part, path.name)
			if err != nil {
				return nil, err
			}
			if i == len(path.parts)-1 {
				out[path.name] = value
				break
			}
			container, err = container.descend(part, value, path.name)
			if err != nil {
				return nil, err
			}
		}
	}
	return json.Marshal(out)
}

type projectionContainer struct {
	object   map[string]json.RawMessage
	items    []json.RawMessage
	children map[string]*projectionContainer
}

func (c *projectionContainer) descend(part string, raw json.RawMessage, path string) (*projectionContainer, error) {
	if child := c.children[part]; child != nil {
		return child, nil
	}
	child, err := decodeProjectionContainer(raw, path)
	if err != nil {
		return nil, err
	}
	if c.children == nil {
		c.children = make(map[string]*projectionContainer)
	}
	c.children[part] = &child
	return &child, nil
}

func decodeProjectionContainer(raw []byte, path string) (c projectionContainer, err error) {
	if len(raw) > 0 && raw[0] == '[' {
		err = json.Unmarshal(raw, &c.items)
	} else if json.Unmarshal(raw, &c.object) != nil {
		err = fmt.Errorf("field path %q does not select an object", path)
	}
	return c, err
}

func (c projectionContainer) selectPart(part, path string) (json.RawMessage, error) {
	if c.items != nil {
		index, err := strconv.Atoi(part)
		if err != nil || index < 0 || index >= len(c.items) {
			return nil, fmt.Errorf("array field path %q is out of range", path)
		}
		return c.items[index], nil
	}
	if value, ok := c.object[part]; ok {
		return value, nil
	}
	return nil, fmt.Errorf("field path %q is absent; inspect get_audit_record_fields or omit fields", path)
}
