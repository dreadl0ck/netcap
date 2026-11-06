package dbs

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/dreadl0ck/netcap/internal/vulndb"
)

const maxReleaseBytes int64 = 4 << 30

var errImmutableCollision = errors.New("immutable object collision")

func releaseNotices(m ReleaseManifest) []byte {
	b := bytes.NewBufferString("NETCAP community datasets, layout 3\nUnapproved CMS, DHCP, MAC-address, Exploit-DB and Nmap corpora are excluded.\n\n")
	for _, s := range m.Sources {
		fmt.Fprintf(b, "%s\nOrigin: %s\nRevision: %s\nTransformation: %s\nGrant origin: %s\nGrant revision: %s\nGrant SHA-256: %s\n%s\n\n%s\n\n", s.ID, s.Origin, s.Revision, s.Transformation, s.GrantOrigin, s.GrantRevision, s.GrantSHA256, s.NoticeText, s.GrantText)
	}
	return b.Bytes()
}

func writeV3Tar(dir string, m ReleaseManifest, dst io.Writer) error {
	gz := gzip.NewWriter(dst)
	tw := tar.NewWriter(gz)
	write := func(name string, size int64, r io.Reader) error {
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: size, Typeflag: tar.TypeReg}); err != nil {
			return err
		}
		_, err := io.CopyN(tw, r, size)
		return err
	}
	for _, member := range m.Files {
		path := filepath.Join(dir, member.Path)
		before, err := os.Lstat(path)
		if err != nil {
			return err
		}
		if !before.Mode().IsRegular() {
			return fmt.Errorf("non-regular file %s", path)
		}
		f, err := os.Open(path)
		if err != nil {
			return err
		}
		after, err := f.Stat()
		if err != nil || !os.SameFile(before, after) || after.Size() != member.Size {
			f.Close()
			return fmt.Errorf("candidate changed: %s", path)
		}
		hash := sha256.New()
		err = write(member.Path, member.Size, io.TeeReader(f, hash))
		var extra [1]byte
		n, readErr := f.Read(extra[:])
		closeErr := f.Close()
		if err != nil {
			return err
		}
		if n != 0 || readErr != io.EOF || hex.EncodeToString(hash.Sum(nil)) != member.SHA256 {
			return fmt.Errorf("candidate changed while archiving: %s", member.Path)
		}
		if closeErr != nil {
			return closeErr
		}
	}
	manifest, err := json.Marshal(m)
	if err != nil {
		return err
	}
	for _, v := range []struct {
		name string
		data []byte
	}{{ManifestFile, manifest}, {"DATABASE_NOTICES.txt", releaseNotices(m)}} {
		if err := write(v.name, int64(len(v.data)), bytes.NewReader(v.data)); err != nil {
			return err
		}
	}
	if err := tw.Close(); err != nil {
		return err
	}
	return gz.Close()
}

// PackV3 publishes immutable objects, then commits latest.json as the sole
// mutable release pointer. It never changes the candidate or prunes history.
func PackV3(dir, out, approvalsPath string) (*DBMetadata, error) {
	return PackV3WithRegistry(dir, out, approvalsPath, os.Getenv(ApprovalRegistryPinEnv))
}

func PackV3WithRegistry(dir, out, approvalsPath, registrySHA256 string) (*DBMetadata, error) {
	absDir, err := canonicalPath(dir)
	if err != nil {
		return nil, err
	}
	absOut, err := canonicalPath(out)
	if err != nil {
		return nil, err
	}
	if rel, err := filepath.Rel(absDir, absOut); err != nil || rel == "." || (rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))) {
		return nil, fmt.Errorf("output must be outside candidate inputs")
	}
	trust, err := loadApprovalTrust(approvalsPath, registrySHA256, dir, out)
	if err != nil {
		return nil, err
	}
	m, err := verifyCandidateWithTrust(dir, trust)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(out, 0o755); err != nil {
		return nil, err
	}
	f, err := os.CreateTemp(out, ".archive-*")
	if err != nil {
		return nil, err
	}
	defer os.Remove(f.Name())
	if err := f.Chmod(0o644); err != nil {
		f.Close()
		return nil, err
	}
	err = writeV3Tar(dir, m, f)
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return nil, err
	}
	if closeErr != nil {
		return nil, closeErr
	}
	sum, size, err := hashFile(f.Name())
	if err != nil {
		return nil, err
	}
	meta := &DBMetadata{Version: sum, SHA256: sum, Size: size, Layout: V3Layout, VulnDBSchema: VulnDBSchema, Tarball: sum + ".tar.gz", CreatedAt: time.Now().UTC().Format(time.RFC3339)}
	db, err := vulndb.Open(filepath.Join(dir, "netcap.sqlite"))
	if err != nil {
		return nil, err
	}
	values, err := db.Meta()
	db.Close()
	if err != nil {
		return nil, err
	}
	meta.NVDStartYear, err = strconv.Atoi(values["nvd_start_year"])
	if err != nil {
		return nil, err
	}
	meta.NVDEndYear, err = strconv.Atoi(values["nvd_end_year"])
	if err != nil {
		return nil, err
	}
	meta.ApprovalRegistrySHA256 = trust.SHA256
	mb, _ := json.Marshal(m)
	meta.ManifestSHA256 = digest(mb)
	if err := verifyV3ArchiveWithTrust(f.Name(), meta, trust); err != nil {
		return nil, fmt.Errorf("archive verification: %w", err)
	}
	if err := installImmutable(f.Name(), filepath.Join(out, meta.Tarball)); err != nil {
		return nil, err
	}
	metaPath := filepath.Join(out, sum+".json")
	var existing DBMetadata
	if err := readJSON(metaPath, &existing); err == nil {
		check := existing
		check.CreatedAt = meta.CreatedAt
		if check != *meta {
			return nil, fmt.Errorf("immutable metadata collision")
		}
		meta = &existing
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	if err := immutableJSON(metaPath, meta); err != nil {
		if !errors.Is(err, errImmutableCollision) {
			return nil, err
		}
		var winner DBMetadata
		if readErr := readJSON(metaPath, &winner); readErr != nil {
			return nil, readErr
		}
		check := winner
		check.CreatedAt = meta.CreatedAt
		if check != *meta {
			return nil, err
		}
		meta = &winner
	}
	if err := atomicJSON(filepath.Join(out, "latest.json"), meta); err != nil {
		return nil, err
	}
	return meta, nil
}

func canonicalPath(path string) (string, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	real, err := filepath.EvalSymlinks(abs)
	if err == nil {
		return real, nil
	}
	if !os.IsNotExist(err) {
		return "", err
	}
	parent := filepath.Dir(abs)
	if parent == abs {
		return "", err
	}
	real, err = canonicalPath(parent)
	if err != nil {
		return "", err
	}
	return filepath.Join(real, filepath.Base(abs)), nil
}

func immutableJSON(path string, value any) error {
	b, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	b = append(b, '\n')
	f, err := os.CreateTemp(filepath.Dir(path), ".metadata-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if err := f.Chmod(0o644); err != nil {
		f.Close()
		return err
	}
	if _, err := f.Write(b); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return installImmutable(f.Name(), path)
}

func installImmutable(src, dst string) error {
	// Hard-link publication is create-only and atomic, unlike Rename which
	// replaces an existing digest object on Unix.
	if err := os.Link(src, dst); err != nil {
		if !os.IsExist(err) {
			return err
		}
		want, _, e := hashFile(src)
		if e != nil {
			return e
		}
		got, _, err := hashFile(dst)
		if err != nil {
			return err
		}
		if got != want {
			return errImmutableCollision
		}
		return nil
	}
	return nil
}

func validateV3Metadata(m *DBMetadata) error {
	if m.Layout != V3Layout || m.VulnDBSchema != VulnDBSchema || !validDigest(m.SHA256) || m.Version != m.SHA256 || m.Tarball != m.SHA256+".tar.gz" || !validDigest(m.ManifestSHA256) || !validDigest(m.ApprovalRegistrySHA256) || m.Size <= 0 || m.Size > maxReleaseBytes {
		return fmt.Errorf("invalid v3 metadata or digest identity")
	}
	if m.NVDStartYear < 2002 || m.NVDStartYear > m.NVDEndYear || m.NVDEndYear > time.Now().Year() {
		return fmt.Errorf("invalid v3 NVD coverage metadata")
	}
	return nil
}

// VerifyV3Archive checks the complete archive body, member inventory, reviewed
// rights records and database contents. No workstation data is consulted.
func VerifyV3Archive(path string, meta *DBMetadata) error {
	trust, err := configuredTrust(filepath.Dir(path))
	if err != nil {
		return err
	}
	return verifyV3ArchiveWithTrust(path, meta, trust)
}

func verifyV3ArchiveWithTrust(path string, meta *DBMetadata, trust approvalTrust) error {
	dir, err := os.MkdirTemp("", "netcap-v3-verify-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	return extractV3ArchiveWithTrust(path, dir, meta, trust)
}

func extractV3Archive(path, dir string, meta *DBMetadata) error {
	trust, err := configuredTrust(filepath.Dir(path), dir)
	if err != nil {
		return err
	}
	return extractV3ArchiveWithTrust(path, dir, meta, trust)
}

func extractV3ArchiveWithTrust(path, dir string, meta *DBMetadata, trust approvalTrust) error {
	if err := validateV3Metadata(meta); err != nil {
		return err
	}
	if meta.ApprovalRegistrySHA256 != trust.SHA256 {
		return fmt.Errorf("metadata approval registry is not the trusted operator pin")
	}
	f, err := openRegular(path)
	if err != nil {
		return err
	}
	defer f.Close()
	hash := sha256.New()
	size, err := io.Copy(hash, f)
	if err != nil {
		return err
	}
	if hex.EncodeToString(hash.Sum(nil)) != meta.SHA256 || size != meta.Size {
		return fmt.Errorf("archive digest/size mismatch")
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return err
	}
	// Hash the exact compressed bytes consumed by extraction as well. An
	// in-place mutation after the preflight hash must never install new bytes.
	consumed := sha256.New()
	gz, err := gzip.NewReader(io.TeeReader(f, consumed))
	if err != nil {
		return err
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	seen := map[string]ReleaseFile{}
	var total int64
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		if h.Typeflag != tar.TypeReg || filepath.Base(h.Name) != h.Name || h.Name == "." || h.Name == ".." || !isValidRelativePath(h.Name) {
			return fmt.Errorf("invalid v3 tar member %q", h.Name)
		}
		if _, ok := seen[h.Name]; ok {
			return fmt.Errorf("duplicate tar member %q", h.Name)
		}
		if CandidateFiles()[h.Name] == "" && h.Name != ManifestFile && h.Name != "DATABASE_NOTICES.txt" {
			return fmt.Errorf("unknown tar member %q", h.Name)
		}
		if h.Size < 0 || h.Size > maxReleaseBytes-total {
			return fmt.Errorf("release exceeds size limit")
		}
		total += h.Size
		if (h.Name == ManifestFile || h.Name == "DATABASE_NOTICES.txt") && h.Size > 16<<20 {
			return fmt.Errorf("oversized release evidence")
		}
		out, err := os.OpenFile(filepath.Join(dir, h.Name), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
		if err != nil {
			return err
		}
		_, err = io.CopyN(out, tr, h.Size)
		ce := out.Close()
		if err != nil {
			return err
		}
		if ce != nil {
			return ce
		}
		hash, n, err := hashFile(filepath.Join(dir, h.Name))
		if err != nil {
			return err
		}
		seen[h.Name] = ReleaseFile{h.Name, CandidateFiles()[h.Name], hash, n}
	}
	// Read through the gzip trailer; tar EOF alone does not check its CRC.
	if n, err := io.Copy(io.Discard, io.LimitReader(gz, 1)); err != nil || n != 0 {
		return fmt.Errorf("trailing or corrupt gzip body: %v", err)
	}
	if hex.EncodeToString(consumed.Sum(nil)) != meta.SHA256 {
		return fmt.Errorf("compressed archive changed during extraction")
	}
	var m ReleaseManifest
	if err := readJSON(filepath.Join(dir, ManifestFile), &m); err != nil {
		return err
	}
	mb, err := os.ReadFile(filepath.Join(dir, ManifestFile))
	if err != nil {
		return err
	}
	if digest(mb) != meta.ManifestSHA256 {
		return fmt.Errorf("release manifest digest mismatch")
	}
	if err := trust.authorize(m); err != nil {
		return err
	}
	if len(seen) != len(m.Files)+2 {
		return fmt.Errorf("release inventory mismatch")
	}
	for _, file := range m.Files {
		if seen[file.Path] != file {
			return fmt.Errorf("member digest mismatch: %s", file.Path)
		}
	}
	notices, err := os.ReadFile(filepath.Join(dir, "DATABASE_NOTICES.txt"))
	if err != nil {
		return err
	}
	if !bytes.Equal(notices, releaseNotices(m)) {
		return fmt.Errorf("missing full applicable notices")
	}
	if err := validateReleaseData(dir); err != nil {
		return err
	}
	if err := validateMetadataCoverage(dir, meta); err != nil {
		return err
	}
	return validateSourceBindings(dir, m)
}
