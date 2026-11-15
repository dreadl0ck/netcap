package utils

import (
	"fmt"
	"strings"
	"unicode/utf8"
)

// PrintableBytes keeps valid UTF-8 and escapes invalid octets; raw evidence stays separate.
func PrintableBytes(data []byte) string {
	if utf8.Valid(data) {
		return string(data)
	}
	var text strings.Builder
	for len(data) > 0 {
		r, size := utf8.DecodeRune(data)
		if r == utf8.RuneError && size == 1 {
			fmt.Fprintf(&text, "\\x%02x", data[0])
		} else {
			text.Write(data[:size])
		}
		data = data[size:]
	}
	return text.String()
}
