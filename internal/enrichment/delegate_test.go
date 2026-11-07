package enrichment

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestSyntheticExistingSignerDelegation(t *testing.T) {
	env, _, root, signer, now := fixture(t)
	rootKey := ed25519.NewKeyFromSeed(make([]byte, 32))
	var key Key
	json.Unmarshal(env.Certificate.Payload, &key)
	legacy := map[string]any{"format": "netcap-db-signing-key/v1", "public_key": key.PublicKey, "epoch": key.Epoch, "not_before": key.NotBefore, "not_after": key.NotAfter}
	payload, _ := json.Marshal(legacy)
	cert, _ := json.Marshal(SignedBytes{payload, ed25519.Sign(rootKey, payload)})
	dir := t.TempDir()
	rootPath, oldPath, out := filepath.Join(dir, "synthetic-root.key"), filepath.Join(dir, "synthetic-core-signer.json"), filepath.Join(dir, "synthetic-enrichment-signer.json")
	os.WriteFile(rootPath, []byte(base64.StdEncoding.EncodeToString(rootKey)), 0600)
	os.WriteFile(oldPath, cert, 0600)
	if e := DelegateExistingSigner(rootPath, oldPath, out, root, now); e != nil {
		t.Fatal(e)
	}
	b, e := os.ReadFile(out)
	if e != nil {
		t.Fatal(e)
	}
	var delegated SignedBytes
	json.Unmarshal(b, &delegated)
	env.Certificate = delegated
	if _, _, e = Verify(env, root, now, true); e != nil {
		t.Fatal(e)
	}
	if e = DelegateExistingSigner(rootPath, oldPath, out, root, now); e == nil {
		t.Fatal("delegation overwrote existing certificate")
	}
	before, e := os.ReadFile(oldPath)
	if e != nil || string(before) != string(cert) {
		t.Fatal("core certificate changed")
	}
	wrong := append([]byte(nil), rootKey...)
	wrong[0] ^= 1
	os.WriteFile(rootPath, []byte(base64.StdEncoding.EncodeToString(wrong)), 0600)
	if e = DelegateExistingSigner(rootPath, oldPath, filepath.Join(dir, "invalid.json"), root, now); e == nil {
		t.Fatal("inconsistent root accepted")
	}
	// The existing signer remains usable; no replacement private key was generated.
	if !ed25519.Verify(key.PublicKey, env.Payload, ed25519.Sign(signer, env.Payload)) {
		t.Fatal("existing signer mismatch")
	}
}
