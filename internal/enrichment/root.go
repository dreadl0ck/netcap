package enrichment

import (
	"crypto/ed25519"
	"encoding/hex"
)

// SigningRoot is the public community anchor, never a signing credential.
// Its equality with the core anchor is checked by the device integration test.
func SigningRoot() ed25519.PublicKey {
	b, _ := hex.DecodeString("8a6d1aaec22ae69f41430d4109b3293b10f98113df87a0989fa609ffb623d7db")
	return ed25519.PublicKey(b)
}
