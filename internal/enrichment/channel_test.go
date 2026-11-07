package enrichment

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/ed25519"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestArchiveAdmission(t *testing.T) {
	env, a, _, _, _ := fixture(t)
	var p Payload
	json.Unmarshal(env.Payload, &p)
	members, e := unpack(a, p)
	if e != nil {
		t.Fatal(e)
	}
	for _, name := range []string{"traversal", "unknown-member", "duplicate", "symlink", "oversized", "gzip-checksum", "hidden-tail"} {
		t.Run(name, func(t *testing.T) {
			var out bytes.Buffer
			gz := gzip.NewWriter(&out)
			tw := tar.NewWriter(gz)
			for n, b := range members {
				tw.WriteHeader(&tar.Header{Name: n, Mode: 0600, Size: int64(len(b)), Typeflag: tar.TypeReg})
				tw.Write(b)
			}
			extra := &tar.Header{Name: "kev.json", Mode: 0600, Typeflag: tar.TypeReg, Size: 1}
			switch name {
			case "traversal":
				extra.Name = "../kev.json"
			case "unknown-member":
				extra.Name = "netcap.sqlite"
			case "symlink":
				extra.Name = "bad-link"
				extra.Typeflag = tar.TypeSymlink
				extra.Linkname = "kev.json"
				extra.Size = 0
			case "oversized":
				extra.Size = MaxMember + 1
			}
			if name != "gzip-checksum" && name != "hidden-tail" {
				tw.WriteHeader(extra)
				if extra.Size == 1 {
					tw.Write([]byte("x"))
				}
			}
			tw.Close()
			if name == "hidden-tail" {
				gz.Write([]byte("hidden non-tar content"))
			}
			gz.Close()
			b := out.Bytes()
			if name == "gzip-checksum" {
				b[len(b)-1] ^= 1
			}
			next := p
			next.ArchiveSHA256 = Digest(b)
			next.ArchiveSize = int64(len(b))
			if _, e := unpack(b, next); e == nil {
				t.Fatal("unsafe archive accepted")
			}
		})
	}
}

func TestDelegationScope(t *testing.T) {
	env, _, root, _, now := fixture(t)
	rootKey := ed25519.NewKeyFromSeed(make([]byte, 32))
	for _, name := range []string{"core-key", "wrong-channel", "unknown-capability", "future-key", "expired-key", "future-format"} {
		t.Run(name, func(t *testing.T) {
			next := env
			var k Key
			json.Unmarshal(env.Certificate.Payload, &k)
			switch name {
			case "core-key":
				k.Format = "netcap-db-signing-key/v1"
			case "wrong-channel":
				k.Channel = "community-schema2"
			case "unknown-capability":
				k.Capabilities = append(k.Capabilities, "unknown")
			case "future-key":
				k.NotBefore = now.Unix() + 1
			case "expired-key":
				k.NotAfter = now.Unix()
			case "future-format":
				k.MinimumFormat = 2
			}
			next.Certificate.Payload, _ = json.Marshal(k)
			next.Certificate.Signature = ed25519.Sign(rootKey, next.Certificate.Payload)
			if _, _, e := Verify(next, root, now, true); e == nil {
				t.Fatal("unscoped/invalid delegation accepted")
			}
		})
	}
}

// All signing material and source grants in these fixtures are synthetic, never production authorizations.
func fixture(t *testing.T) (Envelope, []byte, ed25519.PublicKey, ed25519.PrivateKey, time.Time) {
	t.Helper()
	root := ed25519.NewKeyFromSeed(make([]byte, 32))
	signer := ed25519.NewKeyFromSeed(append([]byte{1}, make([]byte, 31)...))
	now := time.Unix(1794000000, 0)
	c := KEVCatalog{KEVFormat, "synthetic", "2026-11-04T00:00:00Z", 1, []KEVStatus{{"CVE-2024-1234", "2026-11-04", "Unknown", "2026-11-18", "Synthetic action", []string{"https://example.org/advisory"}}}}
	b, _ := json.Marshal(c)
	grant := "SYNTHETIC TEST GRANT ONLY"
	members := map[string][]byte{"kev.json": b, "dhcp-fingerprints-odbl.json": []byte(`{"format":"netcap-dhcp-catalogue","schema":1,"version":"synthetic","license":"ODbL-1.0 AND DbCL-1.0","source_sha256":"0000000000000000000000000000000000000000000000000000000000000000","entries":[{"key":"1,3,6","candidates":[{"id":"synthetic","label":"Synthetic device"}]}]}`), "mac-organizations.json": []byte(`{"format":"netcap-mac-catalogue","schema":1,"version":"synthetic","license":"IEEE-secondary-nonassertion","entries":[{"prefix":"001122","bits":24,"organization":"Synthetic organization"}]}`)}
	for name, path := range map[string]string{"webtech-descriptors.json": "../webtech/webtech-descriptors.json", "service-signatures.json": "../servicesignatures/builtin.json"} {
		data, e := os.ReadFile(path)
		if e != nil {
			t.Fatal(e)
		}
		members[name] = data
	}
	var sources []Source
	for _, name := range []string{"kev.json", "dhcp-fingerprints-odbl.json", "mac-organizations.json", "webtech-descriptors.json", "service-signatures.json"} {
		data := members[name]
		sources = append(sources, Source{ID: SourceFor(name), Origin: "https://example.org", Revision: "synthetic", InputSHA256: Digest([]byte("input")), GrantOrigin: "https://example.org/license", GrantRevision: "synthetic", GrantText: grant, GrantSHA256: Digest([]byte(grant)), Transformation: "synthetic", Outputs: []File{{name, Digest(data), int64(len(data))}}})
	}
	sb, _ := json.Marshal(sources)
	members[SourcesName] = sb
	members[NoticesName] = []byte(grant)
	dir := t.TempDir()
	for n, v := range members {
		if e := os.WriteFile(filepath.Join(dir, n), v, 0600); e != nil {
			t.Fatal(e)
		}
	}
	a, p, e := Pack(dir)
	if e != nil {
		t.Fatal(e)
	}
	a2, _, e := Pack(dir)
	if e != nil || Digest(a) != Digest(a2) {
		t.Fatal("non-deterministic pack")
	}
	k := Key{"netcap-enrichment-signing-key/v1", signer.Public().(ed25519.PublicKey), 1, now.Unix() - 60, now.Unix() + 86400, Channel, []string{Capability}, 1}
	kb, _ := json.Marshal(k)
	p.Sequence = 2
	p.IssuedAt = now.Unix()
	p.ExpiresAt = now.Unix() + 3600
	pb, _ := json.Marshal(p)
	env := Envelope{SignedBytes{kb, ed25519.Sign(root, kb)}, SignedBytes{pb, ed25519.Sign(signer, pb)}}
	return env, a, root.Public().(ed25519.PublicKey), signer, now
}
func TestInstallAtomicAndOffline(t *testing.T) {
	env, a, root, _, now := fixture(t)
	dir := filepath.Join(t.TempDir(), "enrichment")
	if _, e := Open(dir, root, now); !os.IsNotExist(e) {
		t.Fatal(e)
	}
	if e := Install(dir, env, a, root, now); e != nil {
		t.Fatal(e)
	}
	before, _ := os.ReadFile(filepath.Join(dir, "active"))
	members, e := Open(dir, root, now)
	if e != nil {
		t.Fatal(e)
	}
	c, e := ParseKEV(members["kev.json"])
	if e != nil {
		t.Fatal(e)
	}
	if c.Lookup("CVE-2024-1234").Ransomware != "Unknown" || c.Lookup("CVE-2024-12345") != nil || c.Lookup("cve-2024-1234") != nil {
		t.Fatal("false KEV match/label")
	}
	a[0] ^= 1
	if e = Install(dir, env, a, root, now); e == nil {
		t.Fatal("corrupt archive accepted")
	}
	after, _ := os.ReadFile(filepath.Join(dir, "active"))
	if string(before) != string(after) {
		t.Fatal("failed update changed active")
	}
	if _, e = Open(dir, root, now.Add(2*time.Hour)); e == nil {
		t.Fatal("stale runtime data accepted")
	}
}

func TestInstallRefusesCoreRoot(t *testing.T) {
	env, a, trust, _, now := fixture(t)
	for _, name := range []string{"netcap.sqlite", ".release.json", ".signed-release.json"} {
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			marker := []byte("synthetic core marker; never a real database")
			os.WriteFile(filepath.Join(root, name), marker, 0600)
			if e := Install(root, env, a, trust, now); e == nil {
				t.Fatal("optional install wrote into a core root")
			}
			entries, e := os.ReadDir(root)
			if e != nil || len(entries) != 1 {
				t.Fatal("failed optional install changed the core directory")
			}
			b, _ := os.ReadFile(filepath.Join(root, name))
			if string(b) != string(marker) {
				t.Fatal("core marker changed")
			}
		})
	}
}
func TestSignedScopeAndOrder(t *testing.T) {
	env, _, root, signer, now := fixture(t)
	for _, name := range []string{"channel", "capability", "minimum-format", "expiry", "rollback", "equivocation", "root"} {
		t.Run(name, func(t *testing.T) {
			next := env
			next.Payload = append([]byte(nil), env.Payload...)
			var p Payload
			json.Unmarshal(next.Payload, &p)
			switch name {
			case "channel":
				p.Channel = "community-schema2"
			case "capability":
				p.Capabilities = []string{"unknown"}
			case "minimum-format":
				p.MinimumFormat = 2
			case "expiry":
				p.ExpiresAt = now.Unix()
			case "rollback":
				p.Sequence--
			case "equivocation":
				p.ExpiresAt++
			case "root":
				root = make([]byte, 32)
			}
			next.Payload, _ = json.Marshal(p)
			next.Signature = ed25519.Sign(signer, next.Payload)
			if CheckOrder(next, env, root, now) == nil {
				t.Fatal("invalid update accepted")
			}
		})
	}
}
func TestKEVValidation(t *testing.T) {
	env, a, _, _, _ := fixture(t)
	var p Payload
	json.Unmarshal(env.Payload, &p)
	m, e := unpack(a, p)
	if e != nil {
		t.Fatal(e)
	}
	var c KEVCatalog
	json.Unmarshal(m["kev.json"], &c)
	for _, name := range []string{"count", "duplicate", "url", "ransomware", "date"} {
		t.Run(name, func(t *testing.T) {
			n := c
			n.Entries = append([]KEVStatus(nil), c.Entries...)
			switch name {
			case "count":
				n.Count++
			case "duplicate":
				n.Entries = append(n.Entries, n.Entries[0])
				n.Count++
			case "url":
				n.Entries[0].URLs = []string{"javascript:alert(1)"}
			case "ransomware":
				n.Entries[0].Ransomware = "false"
			case "date":
				n.Entries[0].DateAdded = "2026-99-99"
			}
			b, _ := json.Marshal(n)
			if _, e := ParseKEV(b); e == nil {
				t.Fatal("invalid KEV accepted")
			}
		})
	}
}

func TestKEVLookupPreservesEmptyReferenceArray(t *testing.T) {
	catalog := &KEVCatalog{Entries: []KEVStatus{{CVE: "CVE-2024-1234", URLs: []string{}}}}
	status := catalog.Lookup("CVE-2024-1234")
	b, e := json.Marshal(status)
	if e != nil || !bytes.Contains(b, []byte(`"urls":[]`)) {
		t.Fatalf("shared API reference contract: %s, %v", b, e)
	}
}
func TestRealPinnedKEVCandidate(t *testing.T) {
	input := os.Getenv("NETCAP_TEST_KEV_INPUT")
	if input == "" {
		t.Skip("explicit acquired pinned input required")
	}
	b, e := os.ReadFile(input)
	if e != nil {
		t.Fatal(e)
	}
	grant, e := os.ReadFile(os.Getenv("NETCAP_TEST_KEV_LICENSE"))
	if e != nil {
		t.Fatal(e)
	}
	out, s, e := BuildKEV(b, grant)
	if e != nil {
		t.Fatal(e)
	}
	c, e := ParseKEV(out)
	if e != nil || len(c.Entries) != 1768 || c.Lookup("CVE-2024-27834") == nil {
		t.Fatal(e)
	}
	out2, _, e := BuildKEV(b, grant)
	if e != nil || Digest(out) != Digest(out2) {
		t.Fatal("non-deterministic KEV")
	}
	t.Logf("count=%d output_sha256=%s input=%s license=%s", c.Count, Digest(out), s.InputSHA256, s.GrantSHA256)
	labels := map[string]int{}
	for _, v := range c.Entries {
		labels[v.Ransomware]++
	}
	t.Logf("ransomware labels: %v", labels)
}

func TestRustBuiltSyntheticArchive(t *testing.T) {
	dir := os.Getenv("NETCAP_TEST_ENRICHMENT_RUST_FIXTURE")
	if dir == "" {
		t.Skip("explicit Rust synthetic fixture required")
	}
	env, e := readEnvelope(filepath.Join(dir, "signed.json"))
	if e != nil {
		t.Fatal(e)
	}
	a, e := os.ReadFile(filepath.Join(dir, "archive.tar.gz"))
	if e != nil {
		t.Fatal(e)
	}
	root, e := os.ReadFile(filepath.Join(dir, "root.pub"))
	if e != nil {
		t.Fatal(e)
	}
	dest := filepath.Join(t.TempDir(), "data")
	now := time.Unix(1794000000, 0)
	if e = Install(dest, env, a, root, now); e != nil {
		t.Fatal(e)
	}
	if _, e = Open(dest, root, now); e != nil {
		t.Fatal(e)
	}
}

func TestSourceInventoryBindings(t *testing.T) {
	env, a, _, _, _ := fixture(t)
	var p Payload
	json.Unmarshal(env.Payload, &p)
	original, e := unpack(a, p)
	if e != nil {
		t.Fatal(e)
	}
	for _, name := range []string{"unknown", "missing", "changed-size", "changed-grant", "unbound-output", "unknown-manifest-field"} {
		t.Run(name, func(t *testing.T) {
			m := map[string][]byte{}
			for n, b := range original {
				m[n] = append([]byte(nil), b...)
			}
			var manifest Manifest
			json.Unmarshal(m[ManifestName], &manifest)
			switch name {
			case "unknown":
				m["netcap.sqlite"] = []byte("never-core")
			case "missing":
				delete(m, NoticesName)
			case "changed-size":
				manifest.Files[0].Size++
			case "changed-grant":
				var s []Source
				json.Unmarshal(m[SourcesName], &s)
				s[0].GrantText += " changed"
				m[SourcesName], _ = json.Marshal(s)
			case "unbound-output":
				var s []Source
				json.Unmarshal(m[SourcesName], &s)
				s[0].Outputs[0].SHA256 = Digest([]byte("wrong"))
				m[SourcesName], _ = json.Marshal(s)
			case "unknown-manifest-field":
				m[ManifestName] = append(m[ManifestName][:len(m[ManifestName])-1], []byte(`,"unknown":1}`)...)
			}
			if name != "changed-size" {
				for i, f := range manifest.Files {
					if b, ok := m[f.Path]; ok {
						manifest.Files[i] = File{f.Path, Digest(b), int64(len(b))}
					}
				}
			}
			if name != "unknown-manifest-field" {
				m[ManifestName], _ = json.Marshal(manifest)
			}
			next := p
			next.ManifestSHA256 = Digest(m[ManifestName])
			if validateMembers(m, next) == nil {
				t.Fatal("invalid bound source/inventory accepted")
			}
		})
	}
}

func TestExportSyntheticCrossLanguageFixture(t *testing.T) {
	dir := os.Getenv("NETCAP_TEST_ENRICHMENT_FIXTURE")
	if dir == "" {
		t.Skip("explicit synthetic fixture output required")
	}
	env, a, root, _, _ := fixture(t)
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(env)
	for name, data := range map[string][]byte{"signed.json": b, "archive.tar.gz": a, "root.pub": root} {
		if err := os.WriteFile(filepath.Join(dir, name), data, 0600); err != nil {
			t.Fatal(err)
		}
	}
}
