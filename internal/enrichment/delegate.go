package enrichment

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"
)

// DelegateExistingSigner issues only a scoped certificate for an already root-certified
// public key. It creates no private keys and never alters the existing core certificate.
func DelegateExistingSigner(rootPath, existingCertPath, output string, trust ed25519.PublicKey, now time.Time) error {
	encoded, e := regular(rootPath, 1024)
	if e != nil {
		return e
	}
	root, e := base64.StdEncoding.DecodeString(string(bytes.TrimSpace(encoded)))
	if e != nil || len(root) != ed25519.PrivateKeySize {
		return fmt.Errorf("invalid existing offline root")
	}
	if !bytes.Equal(ed25519.PrivateKey(root).Public().(ed25519.PublicKey), trust) {
		return fmt.Errorf("offline root does not match existing community trust")
	}
	b, e := regular(existingCertPath, 8192)
	if e != nil {
		return e
	}
	var cert SignedBytes
	if e = decode(b, &cert); e != nil {
		return e
	}
	if len(cert.Payload) > 4096 || !ed25519.Verify(trust, cert.Payload, cert.Signature) {
		return fmt.Errorf("invalid existing root-certified signer")
	}
	var old struct {
		Format    string `json:"format"`
		PublicKey []byte `json:"public_key"`
		Epoch     uint64 `json:"epoch"`
		NotBefore int64  `json:"not_before"`
		NotAfter  int64  `json:"not_after"`
	}
	if e = decode(cert.Payload, &old); e != nil {
		return e
	}
	if old.Format != "netcap-db-signing-key/v1" || len(old.PublicKey) != 32 || old.Epoch == 0 || old.NotAfter <= old.NotBefore || uint64(old.NotAfter)-uint64(old.NotBefore) > 90*86400 || now.Unix() < old.NotBefore || now.Unix() >= old.NotAfter {
		return fmt.Errorf("invalid or expired existing signing key")
	}
	key := Key{"netcap-enrichment-signing-key/v1", old.PublicKey, old.Epoch, old.NotBefore, old.NotAfter, Channel, []string{Capability}, 1}
	payload, e := json.Marshal(key)
	if e != nil {
		return e
	}
	sig := ed25519.Sign(root, payload)
	if !ed25519.Verify(trust, payload, sig) {
		return fmt.Errorf("inconsistent existing offline root")
	}
	out, e := json.Marshal(SignedBytes{payload, sig})
	if e != nil {
		return e
	}
	return write(output, out)
}
