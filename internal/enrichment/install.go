package enrichment

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"github.com/dreadl0ck/netcap/internal/devicecatalog"
	"github.com/dreadl0ck/netcap/internal/servicesignatures"
	"github.com/dreadl0ck/netcap/internal/webtech"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Root never points into the separately managed core database directory.
func Root(configRoot string) string {
	if p := os.Getenv("NC_ENRICHMENT_ROOT"); p != "" {
		return p
	}
	return filepath.Join(configRoot, "enrichment")
}
func regular(path string, limit int64) ([]byte, error) {
	s, e := os.Lstat(path)
	if e != nil {
		return nil, e
	}
	if !s.Mode().IsRegular() || s.Size() > limit {
		return nil, fmt.Errorf("invalid regular enrichment file: %s", path)
	}
	f, e := os.Open(path)
	if e != nil {
		return nil, e
	}
	defer f.Close()
	b, e := io.ReadAll(io.LimitReader(f, limit+1))
	if int64(len(b)) > limit {
		return nil, fmt.Errorf("oversized enrichment file")
	}
	return b, e
}
func write(path string, b []byte) error {
	f, e := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if e != nil {
		return e
	}
	if _, e = f.Write(b); e == nil {
		e = f.Sync()
	}
	c := f.Close()
	if e != nil {
		return e
	}
	return c
}
func readEnvelope(path string) (Envelope, error) {
	var e Envelope
	b, err := regular(path, 2<<20)
	if err == nil {
		err = decode(b, &e)
	}
	return e, err
}
func validateMembers(members map[string][]byte, p Payload) error {
	mb, ok := members[ManifestName]
	if !ok || Digest(mb) != p.ManifestSHA256 {
		return fmt.Errorf("enrichment manifest digest mismatch")
	}
	var m Manifest
	if e := decode(mb, &m); e != nil {
		return e
	}
	if m.Format != Capability || len(m.Files) < 3 || len(m.Files) > 7 || len(members) != len(m.Files)+1 {
		return fmt.Errorf("invalid enrichment inventory")
	}
	files := map[string]File{}
	last := ""
	for _, f := range m.Files {
		if f.Path <= last || (!validDigest(f.SHA256)) || f.Size <= 0 || f.Size > MaxMember || (SourceFor(f.Path) == "" && f.Path != NoticesName && f.Path != SourcesName) {
			return fmt.Errorf("invalid enrichment member %s", f.Path)
		}
		last = f.Path
		b, ok := members[f.Path]
		if !ok || int64(len(b)) != f.Size || Digest(b) != f.SHA256 {
			return fmt.Errorf("enrichment member hash/size mismatch: %s", f.Path)
		}
		files[f.Path] = f
	}
	if files[SourcesName].Path == "" || files[NoticesName].Path == "" {
		return fmt.Errorf("missing source evidence or notices")
	}
	var sources []Source
	if e := decode(members[SourcesName], &sources); e != nil {
		return e
	}
	covered := map[string]bool{}
	ids := map[string]bool{}
	for _, s := range sources {
		if e := validateReview(s); e != nil {
			return e
		}
		if s.ID == "" || ids[s.ID] || s.Origin == "" || s.Revision == "" || s.GrantOrigin == "" || s.GrantRevision == "" || s.Transformation == "" || !validDigest(s.InputSHA256) || s.GrantText == "" || Digest([]byte(s.GrantText)) != s.GrantSHA256 || !bytes.Contains(members[NoticesName], []byte(s.GrantText)) || len(s.Outputs) == 0 {
			return fmt.Errorf("incomplete or duplicate enrichment source/grant: %s", s.ID)
		}
		ids[s.ID] = true
		for _, f := range s.Outputs {
			if SourceFor(f.Path) == "" || SourceFor(f.Path) != s.ID || covered[f.Path] || files[f.Path] != f {
				return fmt.Errorf("unbound enrichment output: %s", f.Path)
			}
			covered[f.Path] = true
		}
	}
	for name := range files {
		if SourceFor(name) != "" && !covered[name] {
			return fmt.Errorf("missing enrichment source: %s", name)
		}
		if SourceFor(name) != "" {
			var object map[string]json.RawMessage
			if e := decode(members[name], &object); e != nil {
				return e
			}
		}
	}
	if b, ok := members["kev.json"]; ok {
		if _, e := ParseKEV(b); e != nil {
			return e
		}
	}
	if b, ok := members["dhcp-fingerprints-odbl.json"]; ok {
		if _, e := devicecatalog.ParseDHCP(b); e != nil {
			return e
		}
	}
	if b, ok := members["mac-organizations.json"]; ok {
		if _, e := devicecatalog.ParseMAC(b); e != nil {
			return e
		}
	}
	if b, ok := members["webtech-descriptors.json"]; ok {
		if _, e := webtech.Parse(b); e != nil {
			return e
		}
	}
	if b, ok := members["service-signatures.json"]; ok {
		if _, e := servicesignatures.Parse(bytes.NewReader(b)); e != nil {
			return e
		}
	}
	return nil
}
func unpack(archive []byte, p Payload) (map[string][]byte, error) {
	if int64(len(archive)) != p.ArchiveSize || Digest(archive) != p.ArchiveSHA256 {
		return nil, fmt.Errorf("enrichment archive hash/size mismatch")
	}
	gz, e := gzip.NewReader(bytes.NewReader(archive))
	if e != nil {
		return nil, e
	}
	defer gz.Close()
	raw, e := io.ReadAll(io.LimitReader(gz, MaxArchive+1))
	if e != nil {
		return nil, e
	}
	if len(raw) > MaxArchive {
		return nil, fmt.Errorf("oversized enrichment tar")
	}
	input := bytes.NewReader(raw)
	r := tar.NewReader(input)
	members := map[string][]byte{}
	var total int64
	for {
		h, e := r.Next()
		if e == io.EOF {
			break
		}
		if e != nil {
			return nil, e
		}
		if h.Typeflag != tar.TypeReg || h.Size <= 0 || h.Size > MaxMember || (SourceFor(h.Name) == "" && h.Name != ManifestName && h.Name != NoticesName && h.Name != SourcesName) || members[h.Name] != nil {
			return nil, fmt.Errorf("invalid enrichment archive member")
		}
		total += h.Size
		if total > MaxArchive {
			return nil, fmt.Errorf("oversized enrichment contents")
		}
		b, e := io.ReadAll(io.LimitReader(r, h.Size+1))
		if e != nil {
			return nil, e
		}
		if int64(len(b)) != h.Size {
			return nil, fmt.Errorf("truncated member")
		}
		members[h.Name] = b
	}
	for input.Len() > 0 {
		b, _ := input.ReadByte()
		if b != 0 {
			return nil, fmt.Errorf("nonzero trailing enrichment tar data")
		}
	}
	if e = validateMembers(members, p); e != nil {
		return nil, e
	}
	return members, nil
}

// Install activates a verified immutable version with a single pointer rename. A failed optional update leaves core and active untouched.
func Install(root string, envelope Envelope, archive []byte, trust ed25519.PublicKey, now time.Time) error {
	root = filepath.Clean(root)
	if root == "." || root == string(filepath.Separator) {
		return fmt.Errorf("invalid enrichment root")
	}
	for _, name := range []string{"netcap.sqlite", ".release.json", ".signed-release.json"} {
		if _, e := os.Lstat(filepath.Join(root, name)); e == nil {
			return fmt.Errorf("enrichment root overlaps a core database installation")
		} else if !os.IsNotExist(e) {
			return e
		}
	}
	if e := os.MkdirAll(root, 0700); e != nil {
		return e
	}
	lock, e := os.OpenFile(filepath.Join(root, ".install.lock"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if e != nil {
		return e
	}
	defer func() { lock.Close(); os.Remove(filepath.Join(root, ".install.lock")) }()
	p, _, e := Verify(envelope, trust, now, true)
	if e != nil {
		return e
	}
	if oldDir, e := activeDir(root); e == nil {
		old, e := readEnvelope(filepath.Join(oldDir, "signed-release.json"))
		if e != nil {
			return e
		}
		if e = CheckOrder(envelope, old, trust, now); e != nil {
			return e
		}
	} else if !os.IsNotExist(e) {
		return e
	}
	members, e := unpack(archive, p)
	if e != nil {
		return e
	}
	versions := filepath.Join(root, "versions")
	if e = os.MkdirAll(versions, 0700); e != nil {
		return e
	}
	stage, e := os.MkdirTemp(versions, ".stage-")
	if e != nil {
		return e
	}
	defer os.RemoveAll(stage)
	for name, b := range members {
		if e = write(filepath.Join(stage, name), b); e != nil {
			return e
		}
	}
	eb, e := json.Marshal(envelope)
	if e != nil {
		return e
	}
	if e = write(filepath.Join(stage, "signed-release.json"), eb); e != nil {
		return e
	}
	// Payload identity includes sequence and expiry; the same archive can receive a fresh signed lease.
	id := Digest(envelope.Payload)
	dest := filepath.Join(versions, id)
	if _, e = os.Lstat(dest); os.IsNotExist(e) {
		if e = os.Rename(stage, dest); e != nil {
			return e
		}
	} else if e != nil {
		return e
	} else {
		if _, e = OpenVersion(dest, trust, now, true); e != nil {
			return e
		}
	}
	temp, e := os.CreateTemp(root, ".active-")
	if e != nil {
		return e
	}
	name := temp.Name()
	temp.Close()
	os.Remove(name)
	defer os.Remove(name)
	if e = write(name, []byte(id+"\n")); e != nil {
		return e
	}
	return os.Rename(name, filepath.Join(root, "active"))
}
func activeDir(root string) (string, error) {
	b, e := regular(filepath.Join(root, "active"), 128)
	if e != nil {
		return "", e
	}
	id := strings.TrimSuffix(string(b), "\n")
	if !validDigest(id) {
		return "", fmt.Errorf("invalid enrichment active pointer")
	}
	return filepath.Join(root, "versions", id), nil
}

// OpenVersion verifies every signed member before returning immutable paths; no network is used.
func OpenVersion(dir string, trust ed25519.PublicKey, now time.Time, fresh bool) (map[string][]byte, error) {
	info, err := os.Lstat(dir)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("invalid enrichment version directory")
	}
	e, err := readEnvelope(filepath.Join(dir, "signed-release.json"))
	if err != nil {
		return nil, err
	}
	p, _, err := Verify(e, trust, now, fresh)
	if err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	m := map[string][]byte{}
	for _, entry := range entries {
		if entry.Name() == "signed-release.json" {
			continue
		}
		b, e := regular(filepath.Join(dir, entry.Name()), MaxMember)
		if e != nil {
			return nil, e
		}
		m[entry.Name()] = b
	}
	return m, validateMembers(m, p)
}
func Open(root string, trust ed25519.PublicKey, now time.Time) (map[string][]byte, error) {
	dir, e := activeDir(root)
	if e != nil {
		return nil, e
	}
	return OpenVersion(dir, trust, now, true)
}

// Download is an explicit utility action; capture/analysis never calls it.
func Download(root, server string, trust ed25519.PublicKey) error {
	client := &http.Client{Timeout: 10 * time.Minute}
	fetch := func(url string, limit int64) ([]byte, error) {
		r, e := client.Get(url)
		if e != nil {
			return nil, e
		}
		defer r.Body.Close()
		if r.StatusCode != 200 {
			return nil, fmt.Errorf("enrichment HTTP %d", r.StatusCode)
		}
		b, e := io.ReadAll(io.LimitReader(r.Body, limit+1))
		if int64(len(b)) > limit {
			return nil, fmt.Errorf("oversized enrichment response")
		}
		return b, e
	}
	server = strings.TrimRight(server, "/")
	b, e := fetch(server+"/enrichment/signed/v1/latest", 2<<20)
	if e != nil {
		return e
	}
	var env Envelope
	if e = decode(b, &env); e != nil {
		return e
	}
	p, _, e := Verify(env, trust, time.Now(), true)
	if e != nil {
		return e
	}
	archive, e := fetch(server+"/enrichment/signed/v1/"+p.ArchiveSHA256+".tar.gz", p.ArchiveSize)
	if e != nil {
		return e
	}
	return Install(root, env, archive, trust, time.Now())
}

// Pack deterministically builds an unsigned candidate. Signing and deployment remain separate operations.
func Pack(dir string) ([]byte, Payload, error) {
	var p Payload
	m := Manifest{Format: Capability}
	members := map[string][]byte{}
	entries, e := os.ReadDir(dir)
	if e != nil {
		return nil, p, e
	}
	for _, entry := range entries {
		name := entry.Name()
		if SourceFor(name) == "" && name != NoticesName && name != SourcesName {
			return nil, p, fmt.Errorf("unknown enrichment candidate member: %s", name)
		}
		b, e := regular(filepath.Join(dir, name), MaxMember)
		if e != nil {
			return nil, p, e
		}
		members[name] = b
		m.Files = append(m.Files, File{name, Digest(b), int64(len(b))})
	}
	sort.Slice(m.Files, func(i, j int) bool { return m.Files[i].Path < m.Files[j].Path })
	mb, e := json.Marshal(m)
	if e != nil {
		return nil, p, e
	}
	members[ManifestName] = mb
	p.ManifestSHA256 = Digest(mb)
	if e = validateMembers(members, p); e != nil {
		return nil, p, e
	}
	var out bytes.Buffer
	gz := gzip.NewWriter(&out)
	tw := tar.NewWriter(gz)
	names := make([]string, 0, len(members))
	for n := range members {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		b := members[n]
		if e = tw.WriteHeader(&tar.Header{Name: n, Mode: 0600, Size: int64(len(b)), Typeflag: tar.TypeReg}); e != nil {
			return nil, p, e
		}
		if _, e = tw.Write(b); e != nil {
			return nil, p, e
		}
	}
	if e = tw.Close(); e != nil {
		return nil, p, e
	}
	if e = gz.Close(); e != nil {
		return nil, p, e
	}
	p.ArchiveSHA256 = Digest(out.Bytes())
	p.ArchiveSize = int64(out.Len())
	p.Format = "netcap-enrichment-release/v1"
	p.Channel = Channel
	p.MinimumFormat = 1
	p.Capabilities = []string{Capability}
	return out.Bytes(), p, nil
}
