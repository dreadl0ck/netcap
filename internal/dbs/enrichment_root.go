package dbs

import "crypto/ed25519"

// CommunitySigningRoot returns the existing public trust anchor for separately scoped optional channels.
func CommunitySigningRoot() (ed25519.PublicKey, error) { return communityRoot() }
