package types

import (
	"encoding/hex"
	"unicode"
	"unicode/utf8"
)

// DHCPOptionPresentation keeps binary options out of protobuf string fields.
func DHCPOptionPresentation(raw []byte) (data, encoding string) {
	if utf8.Valid(raw) {
		printable := true
		for _, r := range string(raw) {
			if !unicode.IsPrint(r) {
				printable = false
				break
			}
		}
		if printable {
			return string(raw), "utf-8"
		}
	}
	return hex.EncodeToString(raw), "hex"
}
