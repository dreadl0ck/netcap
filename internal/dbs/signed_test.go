package dbs

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"github.com/dreadl0ck/netcap/internal/resolvers"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
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

func TestSignedMirrorCannotReplayAnOlderPublishedKey(t *testing.T) {
	oldPath := os.Getenv("NETCAP_TEST_SIGNED_REPLAY")
	if oldPath == "" {
		t.Skip("set NETCAP_TEST_SIGNED_REPLAY to an earlier public signed envelope")
	}
	latest, err := fetchSigned(defaultDBsURL + "/dbs/signed/v1/latest")
	if err != nil {
		t.Fatal(err)
	}
	var previous SignedRelease
	if err := readJSON(oldPath, &previous); err != nil {
		t.Fatal(err)
	}
	p, _, key, err := verifyCommunityRelease(previous, true)
	if err != nil {
		t.Fatal(err)
	}
	if err := checkReleaseOrder(p, key, latest); err == nil {
		t.Fatal("fixture is not an older key/sequence")
	}
	target := filepath.Join(t.TempDir(), "dbs")
	if err := os.Mkdir(target, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := atomicJSON(filepath.Join(target, signedMarker), latest); err != nil {
		t.Fatal(err)
	}
	oldDir := resolvers.DataBaseFolderPath
	resolvers.DataBaseFolderPath = target
	t.Cleanup(func() { resolvers.DataBaseFolderPath = oldDir })
	archiveRequests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/dbs/signed/v1/latest" {
			archiveRequests++
		}
		_ = jsonResponse(w, previous)
	}))
	defer server.Close()
	if err := downloadSigned(server.URL, true, nil); err == nil {
		t.Fatal("mirror replay accepted")
	}
	if archiveRequests != 0 {
		t.Fatal("replayed archive was requested")
	}
}

func TestSignedDownloadRefusesConcurrentInstallation(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, ".dbs-install.lock"), []byte("other process"), 0o600); err != nil {
		t.Fatal(err)
	}
	previous := resolvers.DataBaseFolderPath
	resolvers.DataBaseFolderPath = filepath.Join(root, "dbs")
	t.Cleanup(func() { resolvers.DataBaseFolderPath = previous })
	if err := downloadSigned("http://127.0.0.1:1", false, nil); err == nil || !strings.Contains(err.Error(), "update lock unavailable") {
		t.Fatalf("did not reject concurrent update: %v", err)
	}
	if b, err := os.ReadFile(filepath.Join(root, ".dbs-install.lock")); err != nil || string(b) != "other process" {
		t.Fatal("modified another process's lock")
	}
}
