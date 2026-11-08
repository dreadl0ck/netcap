//go:build !appstore

package webui

import (
	"crypto/ed25519"

	"github.com/dreadl0ck/netcap/internal/dbs"
)

func catalogueSigningRoot() (ed25519.PublicKey, error) {
	return dbs.CommunitySigningRoot()
}
