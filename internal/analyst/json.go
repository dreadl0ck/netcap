package analyst

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

func DecodeStrict(data []byte, value any) error {
	if len(data) > 256<<10 {
		return fmt.Errorf("analyst request exceeds 256 KiB")
	}
	tokens := json.NewDecoder(bytes.NewReader(data))
	tokens.UseNumber()
	var walk func(int) error
	walk = func(depth int) error {
		if depth > 32 {
			return fmt.Errorf("JSON depth limit exceeded")
		}
		token, err := tokens.Token()
		if err != nil {
			return err
		}
		delim, ok := token.(json.Delim)
		if !ok {
			return nil
		}
		switch delim {
		case '{':
			keys := map[string]bool{}
			for tokens.More() {
				key, err := tokens.Token()
				if err != nil {
					return err
				}
				name, ok := key.(string)
				canonical := strings.ToLower(name)
				if !ok || keys[canonical] {
					return fmt.Errorf("duplicate JSON key")
				}
				keys[canonical] = true
				if canonical == "sessionid" || canonical == "inputfile" {
					value, e := tokens.Token()
					if e != nil {
						return e
					}
					text, ok := value.(string)
					if !ok || strings.TrimSpace(text) == "" {
						return fmt.Errorf("empty or invalid explicit selector")
					}
					continue
				}
				if err = walk(depth + 1); err != nil {
					return err
				}
			}
		case '[':
			for tokens.More() {
				if err = walk(depth + 1); err != nil {
					return err
				}
			}
		default:
			return fmt.Errorf("invalid JSON delimiter")
		}
		_, err = tokens.Token()
		return err
	}
	if err := walk(0); err != nil {
		return err
	}
	if _, err := tokens.Token(); err != io.EOF {
		return fmt.Errorf("trailing JSON")
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	return dec.Decode(value)
}
