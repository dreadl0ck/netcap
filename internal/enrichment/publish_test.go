package enrichment

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestSyntheticPublicationHTTPDownloadAndRollback(t *testing.T) {
	env, a, root, signer, _ := fixture(t)
	now := time.Now()
	rootKey := ed25519.NewKeyFromSeed(make([]byte, 32))
	var k Key
	json.Unmarshal(env.Certificate.Payload, &k)
	k.NotBefore = now.Unix() - 60
	k.NotAfter = now.Add(7 * 24 * time.Hour).Unix()
	kb, _ := json.Marshal(k)
	cert := SignedBytes{kb, ed25519.Sign(rootKey, kb)}
	cb, _ := json.Marshal(cert)
	var p Payload
	json.Unmarshal(env.Payload, &p)
	pb, _ := json.Marshal(p)
	dir := t.TempDir()
	keys := t.TempDir()
	for name, b := range map[string][]byte{p.ArchiveSHA256 + ".tar.gz": a, "unsigned-payload.json": pb} {
		if e := os.WriteFile(filepath.Join(dir, name), b, 0600); e != nil {
			t.Fatal(e)
		}
	}
	keyPath, certPath := filepath.Join(keys, "synthetic-signer.key"), filepath.Join(keys, "synthetic-signer.json")
	os.WriteFile(keyPath, []byte(base64.StdEncoding.EncodeToString(signer)), 0600)
	os.WriteFile(certPath, cb, 0600)
	if e := SignPublication(dir, keyPath, certPath, 4, root, now); e != nil {
		t.Fatal(e)
	}
	handler, e := Handler(dir, root)
	if e != nil {
		t.Fatal(e)
	}
	server := httptest.NewServer(handler)
	defer server.Close()
	target := filepath.Join(t.TempDir(), "optional")
	if e = Download(target, server.URL, root); e != nil {
		t.Fatal(e)
	}
	if _, e = Resolve(target, root, time.Now()); e != nil {
		t.Fatal(e)
	}
	for _, path := range []string{"/dbs/signed/v1/latest", "/enrichment/signed/v1/../../netcap.sqlite", "/enrichment/signed/v1/unsigned-payload.json"} {
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, httptest.NewRequest("GET", path, nil))
		if w.Code != 404 {
			t.Fatalf("%s: %d", path, w.Code)
		}
	}
	if e = SignPublication(dir, keyPath, certPath, 3, root, now); e == nil {
		t.Fatal("publisher rollback accepted")
	}
	if e = SignPublication(dir, keyPath, certPath, 4, root, now.Add(time.Second)); e == nil {
		t.Fatal("equal-version changed payload accepted")
	}
}
