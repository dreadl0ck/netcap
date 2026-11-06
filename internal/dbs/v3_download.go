package dbs

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"

	"github.com/dreadl0ck/netcap/internal/env"
	"github.com/dreadl0ck/netcap/internal/resolvers"
)

var installMu sync.Mutex

// ManagedReleaseMetadata reads the authoritative marker inside the atomically
// switched data directory. A root-level legacy .db-version is not v3 evidence.
func ManagedReleaseMetadata(dir string) (*DBMetadata, error) {
	resolved, err := filepath.EvalSymlinks(dir)
	if err != nil {
		return nil, err
	}
	dir = resolved
	var m DBMetadata
	if err := readJSON(filepath.Join(dir, ".release.json"), &m); err != nil {
		return nil, err
	}
	if err := validateV3Metadata(&m); err != nil {
		return nil, err
	}
	if err := verifyInstalled(dir, &m); err != nil {
		return nil, err
	}
	return &m, nil
}

func makeTarball(source, _ string, dst io.Writer) error {
	m, err := VerifyCandidate(source, os.Getenv("NC_DBS_APPROVALS"))
	if err != nil {
		return err
	}
	return writeV3Tar(source, m, dst)
}

// DownloadDBsWithProgress installs only a completely verified managed release.
// Ambient data is retained as a backup, never merged into the active release.
func DownloadDBsWithProgress(serverURL string, force bool, progress ProgressFunc) error {
	return DownloadDBsWithRegistry(serverURL, force, progress, os.Getenv(ApprovalRegistryEnv), os.Getenv(ApprovalRegistryPinEnv))
}

func DownloadDBsWithRegistry(serverURL string, force bool, progress ProgressFunc, path, pin string) error {
	if path == "" && pin == "" {
		return downloadSigned(serverURL, force, progress)
	}
	installMu.Lock()
	defer installMu.Unlock()
	target := filepath.Clean(resolvers.DataBaseFolderPath)
	if target == "." || target == string(filepath.Separator) {
		return fmt.Errorf("invalid database installation path")
	}
	trust, err := loadClientTrust(path, pin, target)
	if err != nil {
		return err
	}
	report := func(p DownloadProgress) {
		if progress != nil {
			progress(p)
		}
	}
	if serverURL == "" {
		serverURL = os.Getenv(env.NetcapDBsURL)
	}
	if serverURL == "" {
		serverURL = defaultDBsURL
	}
	serverURL = strings.TrimRight(serverURL, "/")
	report(DownloadProgress{Stage: StageMetadata, Message: "Checking reviewed v3 release"})
	meta, err := fetchMetadata(serverURL)
	if err != nil {
		return err
	}
	if meta.ApprovalRegistrySHA256 != trust.SHA256 {
		return fmt.Errorf("download metadata is not bound to the trusted operator registry")
	}
	if !force {
		var installed DBMetadata
		if err := readJSON(filepath.Join(target, ".release.json"), &installed); err == nil && installed == *meta {
			// Do not trust the marker alone: revalidate every active member.
			if err := verifyInstalledWithTrust(target, meta, trust); err == nil {
				report(DownloadProgress{Stage: StageCompleted, Version: meta.Version, Percent: 100})
				return nil
			}
		}
	}
	parent := filepath.Dir(target)
	if err := os.MkdirAll(parent, 0o755); err != nil {
		return err
	}
	stage, err := os.MkdirTemp(parent, ".netcap-release-*")
	if err != nil {
		return err
	}
	// Stage is private and contains no user files. Keep failed candidates for
	// inspection rather than altering an existing installation.
	tarPath := filepath.Join(stage, "download.tar.gz")
	err = downloadFileWithLimit(serverURL+"/dbs/v3/"+meta.Tarball, tarPath, meta.Size, func(n, _ int64) {
		percent := float64(n) / float64(meta.Size) * 100
		if percent > 100 {
			percent = 100
		}
		report(DownloadProgress{Stage: StageDownload, Version: meta.Version, Downloaded: n, Total: meta.Size, Percent: percent, Message: downloadMessage(n, meta.Size)})
	})
	if err != nil {
		return err
	}
	dir := filepath.Join(stage, "dbs")
	if err := os.Mkdir(dir, 0o755); err != nil {
		return err
	}
	report(DownloadProgress{Stage: StageExtract, Version: meta.Version, Message: "Verifying complete release"})
	if err := extractV3ArchiveWithTrust(tarPath, dir, meta, trust); err != nil {
		return err
	}
	if err := atomicJSON(filepath.Join(dir, ".release.json"), meta); err != nil {
		return err
	}
	if err := os.Chmod(stage, 0o755); err != nil {
		return err
	}
	if err := activateManaged(target, dir); err != nil {
		return err
	}
	// Version metadata lives inside the switched directory, so it commits
	// atomically with the data. The old global .db-version is not authoritative.
	report(DownloadProgress{Stage: StageCompleted, Version: meta.Version, Percent: 100, Message: "Reviewed v3 databases installed"})
	return nil
}

func verifyInstalled(dir string, meta *DBMetadata) error {
	var signed SignedRelease
	if err := readJSON(filepath.Join(dir, signedMarker), &signed); err == nil {
		payload, trust, _, err := verifyCommunityRelease(signed, false)
		if err != nil {
			return err
		}
		if payload.Metadata != *meta {
			return fmt.Errorf("installed signed metadata mismatch")
		}
		return verifyInstalledWithTrust(dir, meta, trust)
	} else if !os.IsNotExist(err) {
		return err
	}
	trust, err := loadClientTrust(os.Getenv(ApprovalRegistryEnv), os.Getenv(ApprovalRegistryPinEnv), dir)
	if err != nil {
		return err
	}
	return verifyInstalledWithTrust(dir, meta, trust)
}

func verifyInstalledWithTrust(dir string, meta *DBMetadata, trust approvalTrust) error {
	resolved, err := filepath.EvalSymlinks(dir)
	if err != nil {
		return err
	}
	dir = resolved
	if err := validateV3Metadata(meta); err != nil {
		return err
	}
	if meta.ApprovalRegistrySHA256 != trust.SHA256 {
		return fmt.Errorf("installed metadata registry is not the trusted operator pin")
	}
	var m ReleaseManifest
	if err := readJSON(filepath.Join(dir, ManifestFile), &m); err != nil {
		return err
	}
	if err := trust.authorize(m); err != nil {
		return err
	}
	mb, err := readRegularBytes(filepath.Join(dir, ManifestFile), 16<<20)
	if err != nil {
		return err
	}
	if digest(mb) != meta.ManifestSHA256 {
		return fmt.Errorf("installed manifest changed")
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	extra := 0
	if _, err := os.Lstat(filepath.Join(dir, signedMarker)); err == nil {
		extra = 1
	}
	if len(entries) != len(m.Files)+3+extra {
		return fmt.Errorf("ambient installed members")
	}
	expected := map[string]bool{ManifestFile: true, "DATABASE_NOTICES.txt": true, ".release.json": true}
	if extra == 1 {
		expected[signedMarker] = true
	}
	for _, f := range m.Files {
		expected[f.Path] = true
	}
	for _, entry := range entries {
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if !expected[entry.Name()] || !info.Mode().IsRegular() {
			return fmt.Errorf("unknown or non-regular installed member %s", entry.Name())
		}
	}
	notices, err := os.ReadFile(filepath.Join(dir, "DATABASE_NOTICES.txt"))
	if err != nil {
		return err
	}
	if !bytes.Equal(notices, releaseNotices(m)) {
		return fmt.Errorf("installed notices changed")
	}
	for _, f := range m.Files {
		info, err := os.Lstat(filepath.Join(dir, f.Path))
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("non-regular installed member")
		}
		sum, size, err := hashFile(filepath.Join(dir, f.Path))
		if err != nil {
			return err
		}
		if sum != f.SHA256 || size != f.Size {
			return fmt.Errorf("installed member changed")
		}
	}
	if err := validateReleaseData(dir); err != nil {
		return err
	}
	if err := validateMetadataCoverage(dir, meta); err != nil {
		return err
	}
	return validateSourceBindings(dir, m)
}

func activateManaged(target, dir string) error {
	abs, err := filepath.Abs(dir)
	if err != nil {
		return err
	}
	parent := filepath.Dir(target)
	if runtime.GOOS == "windows" {
		backupDir, err := os.MkdirTemp(parent, ".netcap-previous-*")
		if err != nil {
			return err
		}
		backup := filepath.Join(backupDir, "dbs")
		hadPrevious := false
		if info, err := os.Lstat(target); err == nil {
			if !info.IsDir() {
				return fmt.Errorf("database target is not a directory")
			}
			if err := os.Rename(target, backup); err != nil {
				return err
			}
			hadPrevious = true
		} else if !os.IsNotExist(err) {
			return err
		}
		if err := os.Rename(abs, target); err != nil {
			if hadPrevious {
				if restore := os.Rename(backup, target); restore != nil {
					return fmt.Errorf("activate: %v; rollback: %w", err, restore)
				}
			}
			return err
		}
		return nil
	}
	linkDir, err := os.MkdirTemp(parent, ".netcap-switch-*")
	if err != nil {
		return err
	}
	link := filepath.Join(linkDir, "dbs")
	if err := os.Symlink(abs, link); err != nil {
		return err
	}
	info, err := os.Lstat(target)
	backup := ""
	if err == nil && info.Mode()&os.ModeSymlink == 0 {
		if !info.IsDir() {
			return fmt.Errorf("database target is not a directory")
		}
		// Preserve the complete previous installation, including user data.
		backup = filepath.Join(linkDir, "previous-dbs")
		if err := os.Rename(target, backup); err != nil {
			return err
		}
	} else if err != nil && !os.IsNotExist(err) {
		return err
	}
	if err := os.Rename(link, target); err != nil {
		if backup != "" {
			if rollback := os.Rename(backup, target); rollback != nil {
				return fmt.Errorf("activate: %v; rollback: %w", err, rollback)
			}
		}
		return err
	}
	return nil
}
