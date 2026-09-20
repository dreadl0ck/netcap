//go:build ja4plus

package ja4plus

import (
	"crypto/sha256"
	"encoding/hex"
)

func truncatedSHA256(input string) string {
	if input == "" {
		return "000000000000"
	}
	hash := sha256.Sum256([]byte(input))
	return hex.EncodeToString(hash[:])[:12]
}
