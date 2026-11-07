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

func TestLivePublicationAndHistoricalSourceOffering(t *testing.T) {
	env, archive, trust, signer, _ := fixture(t)
	var original Payload
	json.Unmarshal(env.Payload, &original)
	members, e := unpack(archive, original)
	if e != nil {
		t.Fatal(e)
	}
	delete(members, ManifestName)
	dir := t.TempDir()
	keys := t.TempDir()
	now := time.Now()
	var k Key
	json.Unmarshal(env.Certificate.Payload, &k)
	k.NotBefore = now.Unix() - 60
	k.NotAfter = now.Add(7 * 24 * time.Hour).Unix()
	kb, _ := json.Marshal(k)
	root := ed25519.NewKeyFromSeed(make([]byte, 32))
	cert, _ := json.Marshal(SignedBytes{kb, ed25519.Sign(root, kb)})
	keyPath, certPath := filepath.Join(keys, "synthetic-signer.key"), filepath.Join(keys, "synthetic-signer.json")
	os.WriteFile(keyPath, []byte(base64.StdEncoding.EncodeToString(signer)), 0600)
	os.WriteFile(certPath, cert, 0600)
	publish := func(sequence uint64, at time.Time) Payload {
		t.Helper()
		stage := t.TempDir()
		var sources []Source
		json.Unmarshal(members[SourcesName], &sources)
		for i := range sources {
			sources[i].Evidence = `{"scope":"synthetic-test-only"}`
			sources[i].Review = &Review{"approved-for-publication", "synthetic automated test; not a production approval", "synthetic", at.UTC().Format(time.RFC3339), "synthetic-test-only; no production authorization", Digest([]byte(sources[i].Evidence))}
		}
		sb, _ := json.Marshal(sources)
		for n, b := range members {
			if n == SourcesName {
				b = sb
			}
			if e := os.WriteFile(filepath.Join(stage, n), b, 0600); e != nil {
				t.Fatal(e)
			}
		}
		a, p, e := Pack(stage)
		if e != nil {
			t.Fatal(e)
		}
		os.WriteFile(filepath.Join(dir, p.ArchiveSHA256+".tar.gz"), a, 0600)
		pb, _ := json.Marshal(p)
		os.WriteFile(filepath.Join(dir, "unsigned-payload.json"), pb, 0600)
		if e = SignPublication(dir, keyPath, certPath, sequence, trust, at); e != nil {
			t.Fatal(e)
		}
		return p
	}
	first := publish(2, now)
	handler, e := LiveHandler(dir, trust)
	if e != nil {
		t.Fatal(e)
	}
	request := func(path string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, httptest.NewRequest("GET", path, nil))
		return w
	}
	if w := request("/enrichment/ready"); w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	publish(3, now.Add(time.Second))
	w := request("/enrichment/ready")
	var ready struct {
		Sequence uint64 `json:"sequence"`
	}
	json.Unmarshal(w.Body.Bytes(), &ready)
	if w.Code != 200 || ready.Sequence != 3 {
		t.Fatalf("live pointer did not advance: %s", w.Body.String())
	}
	w = request("/enrichment/signed/v1/" + first.ArchiveSHA256 + ".tar.gz")
	if w.Code != 200 || Digest(w.Body.Bytes()) != first.ArchiveSHA256 {
		t.Fatal("historical immutable source offering disappeared")
	}
	w = request("/enrichment/signed/v1/" + first.ArchiveSHA256 + "/dhcp-fingerprints-odbl.json")
	if w.Code != 200 || string(w.Body.Bytes()) != string(members["dhcp-fingerprints-odbl.json"]) {
		t.Fatal("historical derivative offering disappeared")
	}
	os.WriteFile(filepath.Join(dir, "refresh-status.json"), []byte(`{"format":"netcap-enrichment-refresh/v1","state":"failed","stage":"acquisition","observed_at":"2026-11-06T00:00:00Z"}`), 0600)
	if request("/enrichment/freshness").Code != 503 || request("/enrichment/ready").Code != 200 {
		t.Fatal("failed optional refresh changed ready data")
	}
}
