package dbs

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/dreadl0ck/netcap/internal/env"
	"github.com/dreadl0ck/netcap/internal/resolvers"
)

func fetchSigned(url string) (SignedRelease, error) {
	var envelope SignedRelease
	client := &http.Client{Timeout: httpTimeout}
	r, err := client.Get(url)
	if err != nil {
		return envelope, err
	}
	defer r.Body.Close()
	if r.StatusCode != http.StatusOK {
		return envelope, fmt.Errorf("signed metadata HTTP %d", r.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(r.Body, (16<<20)+1))
	if err != nil {
		return envelope, err
	}
	if len(b) > 16<<20 {
		return envelope, fmt.Errorf("oversized signed metadata")
	}
	err = decodeJSON(b, &envelope)
	return envelope, err
}

func downloadSigned(serverURL string, force bool, progress ProgressFunc) error {
	installMu.Lock()
	defer installMu.Unlock()
	target := filepath.Clean(resolvers.DataBaseFolderPath)
	if target == "." || target == string(filepath.Separator) {
		return fmt.Errorf("invalid database installation path")
	}
	parent := filepath.Dir(target)
	if err := os.MkdirAll(parent, 0o755); err != nil {
		return err
	}
	lockPath := filepath.Join(parent, ".dbs-install.lock")
	lock, err := os.OpenFile(lockPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("database update lock unavailable (%s): %w", lockPath, err)
	}
	defer func() { _ = lock.Close(); _ = os.Remove(lockPath) }()
	if serverURL == "" {
		serverURL = os.Getenv(env.NetcapDBsURL)
	}
	if serverURL == "" {
		serverURL = defaultDBsURL
	}
	serverURL = strings.TrimRight(serverURL, "/")
	report := func(p DownloadProgress) {
		if progress != nil {
			progress(p)
		}
	}
	report(DownloadProgress{Stage: StageMetadata, Message: "Verifying signed community update"})
	envelope, err := fetchSigned(serverURL + "/dbs/signed/v1/latest")
	if err != nil {
		return err
	}
	p, trust, key, err := verifyCommunityRelease(envelope, true)
	if err != nil {
		return err
	}
	meta := &p.Metadata
	var previous SignedRelease
	if err := readJSON(filepath.Join(target, signedMarker), &previous); err == nil {
		if err := checkReleaseOrder(p, key, previous); err != nil {
			return err
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	var installed DBMetadata
	if !force && readJSON(filepath.Join(target, ".release.json"), &installed) == nil && installed == *meta && verifyInstalledWithTrust(target, meta, trust) == nil {
		if err := atomicJSON(filepath.Join(target, signedMarker), envelope); err != nil {
			return err
		}
		report(DownloadProgress{Stage: StageCompleted, Version: meta.Version, Percent: 100})
		return nil
	}
	if err := os.MkdirAll(parent, 0o755); err != nil {
		return err
	}
	stage, err := os.MkdirTemp(parent, ".netcap-signed-*")
	if err != nil {
		return err
	}
	archive := filepath.Join(stage, "download.tar.gz")
	if err := downloadFileWithLimit(serverURL+"/dbs/signed/v1/"+meta.Tarball, archive, meta.Size, func(n, _ int64) {
		report(DownloadProgress{Stage: StageDownload, Version: meta.Version, Downloaded: n, Total: meta.Size, Percent: 100 * float64(n) / float64(meta.Size)})
	}); err != nil {
		return err
	}
	dir := filepath.Join(stage, "dbs")
	if err := os.Mkdir(dir, 0o755); err != nil {
		return err
	}
	report(DownloadProgress{Stage: StageExtract, Version: meta.Version, Message: "Verifying signed release contents"})
	if err := extractV3ArchiveWithTrust(archive, dir, meta, trust); err != nil {
		return err
	}
	if err := atomicJSON(filepath.Join(dir, ".release.json"), meta); err != nil {
		return err
	}
	if err := atomicJSON(filepath.Join(dir, signedMarker), envelope); err != nil {
		return err
	}
	if err := os.Chmod(stage, 0o755); err != nil {
		return err
	}
	if _, _, _, err := verifyCommunityRelease(envelope, true); err != nil {
		return err
	}
	if err := activateManaged(target, dir); err != nil {
		return err
	}
	report(DownloadProgress{Stage: StageCompleted, Version: meta.Version, Percent: 100, Message: "Signed community databases installed"})
	return nil
}
