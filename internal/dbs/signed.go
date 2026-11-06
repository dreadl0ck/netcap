package dbs

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

const signedChannel = "community-schema2"
const signedMarker = ".signed-release.json"

// Signatures cover opaque payload bytes; readers never reserialize signed JSON.
type SignedBytes struct {
	Payload   []byte `json:"payload"`
	Signature []byte `json:"signature"`
}

type SigningKey struct {
	Format    string `json:"format"`
	PublicKey []byte `json:"public_key"`
	Epoch     uint64 `json:"epoch"`
	NotBefore int64  `json:"not_before"`
	NotAfter  int64  `json:"not_after"`
}

type SignedRelease struct {
	Certificate SignedBytes `json:"certificate"`
	SignedBytes
}

type ReleasePayload struct {
	Format          string     `json:"format"`
	Channel         string     `json:"channel"`
	Sequence        uint64     `json:"sequence"`
	IssuedAt        int64      `json:"issued_at"`
	ExpiresAt       int64      `json:"expires_at"`
	PolicySHA256    string     `json:"policy_sha256"`
	Metadata        DBMetadata `json:"metadata"`
	Registry        []byte     `json:"registry"`
	PolicyExpiresAt int64      `json:"policy_expires_at"`
}

func verifySignedRelease(e SignedRelease, root ed25519.PublicKey, now time.Time, fresh bool) (ReleasePayload, approvalTrust, SigningKey, error) {
	var p ReleasePayload
	var key SigningKey
	var trust approvalTrust
	fail := func(reason string) (ReleasePayload, approvalTrust, SigningKey, error) {
		return p, trust, key, fmt.Errorf("signed release: %s", reason)
	}
	if len(root) != ed25519.PublicKeySize || len(e.Certificate.Payload) > 4096 || !ed25519.Verify(root, e.Certificate.Payload, e.Certificate.Signature) {
		return fail("invalid root-signed key certificate")
	}
	if err := decodeJSON(e.Certificate.Payload, &key); err != nil {
		return fail(err.Error())
	}
	if key.Format != "netcap-db-signing-key/v1" || len(key.PublicKey) != ed25519.PublicKeySize || key.Epoch == 0 || key.NotAfter <= key.NotBefore || key.NotAfter-key.NotBefore > int64((90*24*time.Hour)/time.Second) {
		return fail("invalid signing key scope or validity")
	}
	if len(e.Payload) > 8<<20 || !ed25519.Verify(key.PublicKey, e.Payload, e.Signature) {
		return fail("invalid release signature")
	}
	if err := decodeJSON(e.Payload, &p); err != nil {
		return fail(err.Error())
	}
	if p.Format != "netcap-db-release/v1" || p.Channel != signedChannel || p.Sequence == 0 || !validDigest(p.PolicySHA256) || p.IssuedAt < key.NotBefore || p.ExpiresAt > key.NotAfter || (p.PolicyExpiresAt != 0 && p.ExpiresAt > p.PolicyExpiresAt) || p.ExpiresAt <= p.IssuedAt || p.ExpiresAt-p.IssuedAt > 7*86400 || p.IssuedAt > now.Unix()+300 {
		return fail("invalid release scope or validity")
	}
	if fresh && (now.Unix() >= p.ExpiresAt || now.Unix() >= key.NotAfter || now.Unix() < key.NotBefore) {
		return fail("expired or not-yet-valid update")
	}
	if err := validateV3Metadata(&p.Metadata); err != nil {
		return fail(err.Error())
	}
	var err error
	trust, err = parseApprovalTrust(p.Registry, p.Metadata.ApprovalRegistrySHA256)
	if err != nil {
		return fail(err.Error())
	}
	return p, trust, key, nil
}

func communityRoot() (ed25519.PublicKey, error) {
	b, err := hex.DecodeString(communitySigningRoot)
	if err != nil || len(b) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("invalid compiled community root")
	}
	return ed25519.PublicKey(b), nil
}

func verifyCommunityRelease(e SignedRelease, fresh bool) (ReleasePayload, approvalTrust, SigningKey, error) {
	root, err := communityRoot()
	if err != nil {
		return ReleasePayload{}, approvalTrust{}, SigningKey{}, err
	}
	return verifySignedRelease(e, root, time.Now(), fresh)
}

func checkReleaseOrder(next ReleasePayload, nextKey SigningKey, previous SignedRelease) error {
	old, _, oldKey, err := verifyCommunityRelease(previous, false)
	if err != nil {
		return err
	}
	return compareReleaseOrder(next, nextKey, old, oldKey)
}

func compareReleaseOrder(next ReleasePayload, nextKey SigningKey, old ReleasePayload, oldKey SigningKey) error {
	if nextKey.Epoch < oldKey.Epoch || (nextKey.Epoch == oldKey.Epoch && (next.Sequence < old.Sequence || (next.Sequence == old.Sequence && (next.Metadata != old.Metadata || next.PolicySHA256 != old.PolicySHA256 || next.ExpiresAt != old.ExpiresAt)))) {
		return fmt.Errorf("signed release rollback or sequence equivocation")
	}
	return nil
}

// GenerateSigningKeys writes an offline root and a separately deployable signer.
// Existing keys are never overwritten. The serving container needs neither key.
func GenerateSigningKeys(dir string) error {
	if err := os.Mkdir(dir, 0o700); err != nil {
		return err
	}
	rootPub, root, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	pub, signer, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	key := SigningKey{"netcap-db-signing-key/v1", pub, 1, now.Add(-time.Minute).Unix(), now.Add(89 * 24 * time.Hour).Unix()}
	payload, err := json.Marshal(key)
	if err != nil {
		return err
	}
	cert, err := json.Marshal(SignedBytes{payload, ed25519.Sign(root, payload)})
	if err != nil {
		return err
	}
	for name, b := range map[string][]byte{"root.key": []byte(base64.StdEncoding.EncodeToString(root)), "signer.key": []byte(base64.StdEncoding.EncodeToString(signer)), "root.pub": []byte(hex.EncodeToString(rootPub)), "signer.json": cert} {
		if err := os.WriteFile(filepath.Join(dir, name), b, 0o600); err != nil {
			return err
		}
	}
	return nil
}

// RotateSigningKey requires the offline root; a replacement signer cannot certify itself.
func RotateSigningKey(rootPath, output string, epoch uint64) error {
	if epoch < 2 {
		return fmt.Errorf("rotation epoch must be at least 2")
	}
	encoded, err := readRegularBytes(rootPath, 1024)
	if err != nil {
		return err
	}
	root, err := base64.StdEncoding.DecodeString(string(bytes.TrimSpace(encoded)))
	if err != nil || len(root) != ed25519.PrivateKeySize {
		return fmt.Errorf("invalid offline root")
	}
	pub, signer, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	key := SigningKey{"netcap-db-signing-key/v1", pub, epoch, now.Add(-time.Minute).Unix(), now.Add(89 * 24 * time.Hour).Unix()}
	payload, err := json.Marshal(key)
	if err != nil {
		return err
	}
	if err := os.Mkdir(output, 0o700); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(output, "signer.key"), []byte(base64.StdEncoding.EncodeToString(signer)), 0o600); err != nil {
		return err
	}
	return atomicJSON(filepath.Join(output, "signer.json"), SignedBytes{payload, ed25519.Sign(root, payload)})
}

func SignPublication(meta DBMetadata, registryPath, policyPath, keyPath, certPath, output string, sequence uint64) error {
	registry, err := readRegularBytes(registryPath, 16<<20)
	if err != nil {
		return err
	}
	policy, err := readRegularBytes(policyPath, 16<<20)
	if err != nil {
		return err
	}
	encoded, err := readRegularBytes(keyPath, 1024)
	if err != nil {
		return err
	}
	key, err := base64.StdEncoding.DecodeString(string(bytes.TrimSpace(encoded)))
	if err != nil || len(key) != ed25519.PrivateKeySize {
		return fmt.Errorf("invalid signing private key")
	}
	var cert SignedBytes
	if err := readJSON(certPath, &cert); err != nil {
		return err
	}
	now := time.Now().UTC()
	var sourcePolicy SourcePolicy
	if err := decodeJSON(policy, &sourcePolicy); err != nil {
		return err
	}
	p := ReleasePayload{"netcap-db-release/v1", signedChannel, sequence, now.Unix(), now.Add(72 * time.Hour).Unix(), digest(policy), meta, registry, sourcePolicy.ExpiresAt}
	payload, err := json.Marshal(p)
	if err != nil {
		return err
	}
	e := SignedRelease{cert, SignedBytes{payload, ed25519.Sign(key, payload)}}
	_, trust, nextKey, err := verifyCommunityRelease(e, true)
	if err != nil {
		return err
	}
	if err := verifyV3ArchiveWithTrust(filepath.Join(output, meta.Tarball), &meta, trust); err != nil {
		return err
	}
	var previous SignedRelease
	if err := readJSON(filepath.Join(output, "signed-latest.json"), &previous); err == nil {
		if err := checkReleaseOrder(p, nextKey, previous); err != nil {
			return err
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	if err := immutableJSON(filepath.Join(output, fmt.Sprintf("signed-%d.json", sequence)), e); err != nil {
		return err
	}
	return atomicJSON(filepath.Join(output, "signed-latest.json"), e)
}
