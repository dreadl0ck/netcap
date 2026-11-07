// Package devicecatalog reads explicitly selected, offline device catalogues.
// Admission/signature verification belongs to the optional-catalogue installer.
package devicecatalog

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
)

const MaxBytes = 16 << 20

func Read(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, MaxBytes+1))
	if err == nil && len(b) > MaxBytes {
		err = errors.New("catalogue exceeds 16 MiB")
	}
	return b, err
}

func decode(b []byte, target any) error {
	if len(b) > MaxBytes {
		return errors.New("catalogue exceeds 16 MiB")
	}
	if err := uniqueFields(json.NewDecoder(bytes.NewReader(b)), 0); err != nil {
		return err
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if err := d.Decode(target); err != nil {
		return err
	}
	if err := d.Decode(new(any)); err != io.EOF {
		return fmt.Errorf("trailing catalogue data: %v", err)
	}
	return nil
}

func uniqueFields(d *json.Decoder, depth int) error {
	if depth > 64 {
		return errors.New("catalogue nesting exceeds limit")
	}
	token, err := d.Token()
	if err != nil {
		return err
	}
	if delim, ok := token.(json.Delim); ok {
		switch delim {
		case '{':
			seen := map[string]bool{}
			for d.More() {
				key, err := d.Token()
				if err != nil {
					return err
				}
				name, ok := key.(string)
				if !ok || seen[name] {
					return errors.New("duplicate JSON field")
				}
				seen[name] = true
				if err := uniqueFields(d, depth+1); err != nil {
					return err
				}
			}
		case '[':
			for d.More() {
				if err := uniqueFields(d, depth+1); err != nil {
					return err
				}
			}
		default:
			return errors.New("unexpected JSON delimiter")
		}
		_, err = d.Token()
	}
	return err
}
