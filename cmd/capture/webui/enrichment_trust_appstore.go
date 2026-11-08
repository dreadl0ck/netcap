//go:build appstore

package webui

import (
	"crypto/ed25519"
	"errors"
)

func catalogueSigningRoot() (ed25519.PublicKey, error) {
	return nil, errors.New("external enrichment catalogues are unavailable in the App Store edition")
}
