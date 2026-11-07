package enrichment

import (
	"crypto/ed25519"
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestExpiredChannelColdStartRetainsSourceOffering(t *testing.T) {
	env, archive, trust, signer, _ := fixture(t)
	var original Payload
	json.Unmarshal(env.Payload, &original)
	members, e := unpack(archive, original)
	if e != nil {
		t.Fatal(e)
	}
	delete(members, ManifestName)
	past := time.Now().Add(-4 * 24 * time.Hour)
	var sources []Source
	json.Unmarshal(members[SourcesName], &sources)
	for i := range sources {
		sources[i].Evidence = `{"scope":"synthetic-test-only"}`
		sources[i].Review = &Review{"approved-for-publication", "synthetic automated test; not a production approval", "synthetic", past.UTC().Format(time.RFC3339), "synthetic test only", Digest([]byte(sources[i].Evidence))}
	}
	members[SourcesName], _ = json.Marshal(sources)
	stage := t.TempDir()
	for n, b := range members {
		os.WriteFile(filepath.Join(stage, n), b, 0600)
	}
	archive, p, e := Pack(stage)
	if e != nil {
		t.Fatal(e)
	}
	p.Sequence = 2
	p.IssuedAt = past.Unix()
	p.ExpiresAt = past.Add(time.Hour).Unix()
	var k Key
	json.Unmarshal(env.Certificate.Payload, &k)
	k.NotBefore = past.Add(-time.Minute).Unix()
	k.NotAfter = past.Add(24 * time.Hour).Unix()
	kb, _ := json.Marshal(k)
	root := ed25519.NewKeyFromSeed(make([]byte, 32))
	env.Certificate = SignedBytes{kb, ed25519.Sign(root, kb)}
	env.Payload, _ = json.Marshal(p)
	env.Signature = ed25519.Sign(signer, env.Payload)
	if _, _, e = Verify(env, trust, time.Now(), true); e == nil {
		t.Fatal("expired channel accepted for installation")
	}
	dir := t.TempDir()
	eb, _ := json.Marshal(env)
	os.WriteFile(filepath.Join(dir, "signed-latest.json"), eb, 0600)
	os.WriteFile(filepath.Join(dir, "signed-2.json"), eb, 0600)
	os.WriteFile(filepath.Join(dir, p.ArchiveSHA256+".tar.gz"), archive, 0600)
	handler, e := LiveHandler(dir, trust)
	if e != nil {
		t.Fatal(e)
	}
	for path, status := range map[string]int{"/enrichment/live": 200, "/enrichment/ready": 503, "/enrichment/signed/v1/latest": 503, "/enrichment/signed/v1/" + p.ArchiveSHA256 + ".tar.gz": 200, "/enrichment/signed/v1/" + p.ArchiveSHA256 + "/dhcp-fingerprints-odbl.json": 200} {
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, httptest.NewRequest("GET", path, nil))
		if w.Code != status {
			t.Fatalf("%s: %d != %d: %s", path, w.Code, status, w.Body.String())
		}
	}
}
