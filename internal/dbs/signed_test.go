package dbs

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"testing"
	"time"
)

func TestSignedReleaseAuthenticityAndExpiry(t *testing.T) {
	root, secret, _ := ed25519.GenerateKey(rand.Reader)
	pub, signer, _ := ed25519.GenerateKey(rand.Reader)
	now := time.Now().UTC()
	key := SigningKey{"netcap-db-signing-key/v1", pub, 1, now.Add(-time.Hour).Unix(), now.Add(24 * time.Hour).Unix()}
	kb, _ := json.Marshal(key)
	meta := DBMetadata{Version: digest([]byte("archive")), SHA256: digest([]byte("archive")), Layout: 3, VulnDBSchema: VulnDBSchema, Size: 7, ManifestSHA256: digest([]byte("manifest")), ApprovalRegistrySHA256: communityRegistrySHA256, NVDStartYear: 2002, NVDEndYear: now.Year()}
	meta.Tarball = meta.Version + ".tar.gz"
	p := ReleasePayload{"netcap-db-release/v1", signedChannel, 1, now.Unix(), now.Add(time.Hour).Unix(), digest([]byte("policy")), meta, []byte(communityRegistry), now.Add(48 * time.Hour).Unix()}
	pb, _ := json.Marshal(p)
	e := SignedRelease{SignedBytes{kb, ed25519.Sign(secret, kb)}, SignedBytes{pb, ed25519.Sign(signer, pb)}}
	if _, _, _, err := verifySignedRelease(e, root, now, true); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name   string
		change func(*SignedRelease)
	}{
		{"payload", func(e *SignedRelease) { e.Payload = append([]byte(nil), e.Payload...); e.Payload[10] ^= 1 }},
		{"signature", func(e *SignedRelease) { e.Signature = make([]byte, 64) }},
		{"certificate", func(e *SignedRelease) { e.Certificate.Signature = make([]byte, 64) }},
		{"channel", func(e *SignedRelease) {
			q := p
			q.Channel = "other"
			e.Payload, _ = json.Marshal(q)
			e.Signature = ed25519.Sign(signer, e.Payload)
		}},
		{"registry", func(e *SignedRelease) {
			q := p
			q.Registry = []byte("[]")
			e.Payload, _ = json.Marshal(q)
			e.Signature = ed25519.Sign(signer, e.Payload)
		}},
		{"future", func(e *SignedRelease) {
			q := p
			q.IssuedAt = now.Add(10 * time.Minute).Unix()
			e.Payload, _ = json.Marshal(q)
			e.Signature = ed25519.Sign(signer, e.Payload)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			bad := e
			tc.change(&bad)
			if _, _, _, err := verifySignedRelease(bad, root, now, true); err == nil {
				t.Fatal("accepted invalid signed release")
			}
		})
	}
	if _, _, _, err := verifySignedRelease(e, root, now.Add(2*time.Hour), true); err == nil {
		t.Fatal("expired update accepted")
	}
	if _, _, _, err := verifySignedRelease(e, root, now.Add(2*time.Hour), false); err != nil {
		t.Fatal("expiry broke already installed offline data", err)
	}
	wrong, _, _ := ed25519.GenerateKey(rand.Reader)
	if _, _, _, err := verifySignedRelease(e, wrong, now, true); err == nil {
		t.Fatal("untrusted root accepted")
	}
	newPub, newSecret, _ := ed25519.GenerateKey(rand.Reader)
	rotated := key
	rotated.PublicKey, rotated.Epoch = newPub, 2
	certBytes, _ := json.Marshal(rotated)
	newPayload := p
	newPayload.Sequence = 2
	newBytes, _ := json.Marshal(newPayload)
	rotation := SignedRelease{SignedBytes{certBytes, ed25519.Sign(secret, certBytes)}, SignedBytes{newBytes, ed25519.Sign(newSecret, newBytes)}}
	verified, _, newKey, err := verifySignedRelease(rotation, root, now, true)
	if err != nil {
		t.Fatal("root-authorized rotation rejected", err)
	}
	if err := compareReleaseOrder(verified, newKey, p, key); err != nil {
		t.Fatal(err)
	}
	if err := compareReleaseOrder(p, key, verified, newKey); err == nil {
		t.Fatal("key/sequence rollback accepted")
	}
	changed := p
	changed.PolicySHA256 = digest([]byte("changed policy"))
	if err := compareReleaseOrder(changed, key, p, key); err == nil {
		t.Fatal("sequence equivocation accepted")
	}
}
