// Package testfixture creates synthetic signing material, never a production grant.
package testfixture

import (
	"crypto/ed25519"
	"encoding/json"
	"github.com/dreadl0ck/netcap/internal/enrichment"
	"github.com/dreadl0ck/netcap/internal/webtech/publication"
	"os"
	"path/filepath"
	"time"
)

type Fixture struct {
	Scope    string              `json:"scope"`
	Envelope enrichment.Envelope `json:"envelope"`
	Archive  []byte              `json:"archive"`
	Trust    ed25519.PublicKey   `json:"trust"`
	Now      int64               `json:"now"`
}

func Build() (Fixture, error) {
	var f Fixture
	members, err := publication.Members()
	if err != nil {
		return f, err
	}
	dir, err := os.MkdirTemp("", "netcap-synthetic-catalogues-")
	if err != nil {
		return f, err
	}
	defer os.RemoveAll(dir)
	for name, b := range members {
		if err = os.WriteFile(filepath.Join(dir, name), b, 0600); err != nil {
			return f, err
		}
	}
	archive, p, err := enrichment.Pack(dir)
	if err != nil {
		return f, err
	}
	root := ed25519.NewKeyFromSeed(make([]byte, 32))
	signer := ed25519.NewKeyFromSeed(append([]byte{1}, make([]byte, 31)...))
	now := time.Date(2026, time.November, 6, 22, 0, 0, 0, time.UTC)
	k := enrichment.Key{Format: "netcap-enrichment-signing-key/v1", PublicKey: signer.Public().(ed25519.PublicKey), Epoch: 1, NotBefore: now.Unix() - 60, NotAfter: now.Unix() + 86400, Channel: enrichment.Channel, Capabilities: []string{enrichment.Capability}, MinimumFormat: 1}
	kb, err := json.Marshal(k)
	if err != nil {
		return f, err
	}
	p.Sequence = 1
	p.IssuedAt = now.Unix()
	p.ExpiresAt = now.Unix() + 3600
	pb, err := json.Marshal(p)
	if err != nil {
		return f, err
	}
	f = Fixture{Scope: "synthetic signing keys and test clock only; not a production publication", Envelope: enrichment.Envelope{Certificate: enrichment.SignedBytes{Payload: kb, Signature: ed25519.Sign(root, kb)}, SignedBytes: enrichment.SignedBytes{Payload: pb, Signature: ed25519.Sign(signer, pb)}}, Archive: archive, Trust: root.Public().(ed25519.PublicKey), Now: now.Unix()}
	return f, nil
}
func (f Fixture) Install(root string) error {
	return enrichment.Install(root, f.Envelope, f.Archive, f.Trust, time.Unix(f.Now, 0))
}
