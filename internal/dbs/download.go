/*
 * NETCAP - Traffic Analysis Framework
 * Copyright (c) Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
 * License: GNU General Public License v3.0
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

package dbs

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/dreadl0ck/netcap/internal/env"
	"github.com/dreadl0ck/netcap/internal/vulndb"
	"github.com/dustin/go-humanize"
)

const (
	defaultDBsURL = "https://dbs.netcap.io"
	httpTimeout   = 30 * time.Second
)

// DBMetadata represents metadata about a database version
type DBMetadata struct {
	Version                string `json:"version"`
	CreatedAt              string `json:"created_at"`
	Tarball                string `json:"tarball"`
	NVDStartYear           int    `json:"nvd_start_year"`
	Layout                 int    `json:"layout"`
	VulnDBSchema           int    `json:"vulndb_schema"`
	SHA256                 string `json:"sha256"`
	Size                   int64  `json:"size"`
	ManifestSHA256         string `json:"manifest_sha256,omitempty"`
	ApprovalRegistrySHA256 string `json:"approval_registry_sha256"`
	NVDEndYear             int    `json:"nvd_end_year"`
}

// installedVersion is what .db-version records, so a layout-1 revision of the
// same date is never mistaken for an installed layout-2 one.
func (m *DBMetadata) installedVersion() string {
	return fmt.Sprintf("%s/%s", layoutPrefix, m.Version)
}

// DownloadStage names the phase a download is in. The UI distinguishes these
// because extraction of a 91 MB tarball is slow enough that a bar frozen at
// 100% reads as a hang.
type DownloadStage string

// Download stages, in the order they occur.
const (
	StageMetadata  DownloadStage = "metadata"
	StageDownload  DownloadStage = "download"
	StageExtract   DownloadStage = "extract"
	StageCompleted DownloadStage = "completed"
)

// DownloadProgress is one observation of an in-flight database download.
type DownloadProgress struct {
	Stage      DownloadStage `json:"stage"`
	Version    string        `json:"version,omitempty"`
	Downloaded int64         `json:"downloaded"`
	Total      int64         `json:"total"`
	Percent    float64       `json:"percent"`
	Message    string        `json:"message,omitempty"`
}

// ProgressFunc receives download progress observations. It is called from the
// downloading goroutine and must not block.
type ProgressFunc func(DownloadProgress)

// DownloadDBs downloads the latest databases from the configured server.
func DownloadDBs(serverURL string, force bool) error {
	return DownloadDBsWithProgress(serverURL, force, nil)
}

func downloadMessage(downloaded, total int64) string {
	if total > 0 {
		return fmt.Sprintf("Downloading %s of %s",
			humanize.Bytes(uint64(downloaded)), humanize.Bytes(uint64(total)))
	}

	return "Downloading " + humanize.Bytes(uint64(downloaded))
}

// fetchMetadata retrieves metadata about the latest database version
func fetchMetadata(serverURL string) (*DBMetadata, error) {
	client := &http.Client{
		Timeout: httpTimeout,
	}

	url := fmt.Sprintf("%s/dbs/%s/latest", serverURL, layoutPrefix)
	log.Printf("Fetching metadata from: %s", url)

	resp, err := client.Get(url)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch metadata from %s: %w", url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("%s serves no layout %d databases; it predates netcap v0.10 (point NETCAP_DBS_URL at an upgraded server or use -generate-dbs)", serverURL, Layout)
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("server returned status %s for %s: %s", resp.Status, url, string(body))
	}

	var metadata DBMetadata
	body, err := io.ReadAll(io.LimitReader(resp.Body, (1<<20)+1))
	if err != nil {
		return nil, err
	}
	if len(body) > 1<<20 {
		return nil, fmt.Errorf("oversized release metadata")
	}
	if err := decodeJSON(body, &metadata); err != nil {
		return nil, fmt.Errorf("failed to decode metadata: %w", err)
	}
	if metadata.Layout != Layout {
		return nil, fmt.Errorf("%s announced layout %d, this netcap reads layout %d", url, metadata.Layout, Layout)
	}
	if metadata.VulnDBSchema != vulndb.SchemaVersion {
		return nil, fmt.Errorf("%s announced %s schema %d, this netcap reads schema %d", url, vulndb.FileName, metadata.VulnDBSchema, vulndb.SchemaVersion)
	}
	if err := validateV3Metadata(&metadata); err != nil {
		return nil, err
	}

	return &metadata, nil
}

// verifySHA256 checks path against the digest announced in the metadata.
func verifySHA256(path, want string) error {
	if want == "" {
		return errors.New("metadata carries no sha256; refusing an unverifiable tarball")
	}
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	h := sha256.New()
	if _, err = io.Copy(h, f); err != nil {
		return err
	}
	if got := hex.EncodeToString(h.Sum(nil)); got != want {
		return fmt.Errorf("database tarball sha256 %s does not match metadata %s", got, want)
	}
	return nil
}

// downloadFile downloads a file from a URL to a local path with progress reporting
func downloadFile(url, filepath string) error {
	return downloadFileWithProgress(url, filepath, nil)
}

func downloadFileWithProgress(url, filepath string, onProgress func(downloaded, total int64)) error {
	return downloadFileWithLimit(url, filepath, maxReleaseBytes, onProgress)
}

func downloadFileWithLimit(url, filepath string, limit int64, onProgress func(downloaded, total int64)) error {
	if limit <= 0 || limit > maxReleaseBytes {
		return fmt.Errorf("invalid download size limit")
	}
	// Create the file
	out, err := os.Create(filepath)
	if err != nil {
		return err
	}
	defer out.Close()

	// Create HTTP client with timeout
	// Note: We use a longer timeout for downloads since files can be large
	client := &http.Client{
		Timeout: 10 * time.Minute,
	}

	// Get the data
	log.Printf("Downloading from: %s", url)
	resp, err := client.Get(url)
	if err != nil {
		return fmt.Errorf("failed to download from %s: %w", url, err)
	}
	defer resp.Body.Close()

	// Check server response
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("bad status %s for %s: %s", resp.Status, url, string(body))
	}
	if resp.ContentLength > limit {
		return fmt.Errorf("download exceeds announced release size")
	}

	// Create a progress writer
	progressWriter := &progressWriter{
		total:      resp.ContentLength,
		downloaded: 0,
		lastReport: time.Now(),
		onProgress: onProgress,
	}

	// Writer that writes to file and tracks progress
	writer := io.MultiWriter(out, progressWriter)

	// Write the body to file
	n, err := io.Copy(writer, io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return fmt.Errorf("failed to write downloaded data: %w", err)
	}
	if n > limit {
		return fmt.Errorf("download exceeds release size limit")
	}
	if err := out.Sync(); err != nil {
		return err
	}

	// Final progress report. Emit one last observation so a consumer that
	// samples on the ticker cannot be left showing a stale figure below 100%
	// on a transfer that has already finished.
	progressWriter.reportNow()
	fmt.Println()

	return out.Close()
}

// progressWriter tracks download progress
type progressWriter struct {
	total      int64
	downloaded int64
	lastReport time.Time
	onProgress func(downloaded, total int64)
}

func (pw *progressWriter) Write(p []byte) (int, error) {
	n := len(p)
	pw.downloaded += int64(n)

	// Report progress every second
	if time.Since(pw.lastReport) > time.Second {
		pw.reportNow()
	}

	return n, nil
}

func (pw *progressWriter) reportNow() {
	if pw.total > 0 {
		percent := float64(pw.downloaded) / float64(pw.total) * 100
		fmt.Printf("\rProgress: %.1f%% (%s / %s)",
			percent,
			humanize.Bytes(uint64(pw.downloaded)),
			humanize.Bytes(uint64(pw.total)))
	} else {
		fmt.Printf("\rDownloaded: %s", humanize.Bytes(uint64(pw.downloaded)))
	}

	pw.lastReport = time.Now()

	if pw.onProgress != nil {
		pw.onProgress(pw.downloaded, pw.total)
	}
}

// ListAvailableVersions lists all available database versions from the server
func ListAvailableVersions(serverURL string) error {
	if serverURL == "" {
		serverURL = os.Getenv(env.NetcapDBsURL)
		if serverURL == "" {
			serverURL = defaultDBsURL
		}
	}

	client := &http.Client{
		Timeout: httpTimeout,
	}

	url := fmt.Sprintf("%s/dbs/%s/list", serverURL, layoutPrefix)
	log.Printf("Fetching version list from: %s", url)

	resp, err := client.Get(url)
	if err != nil {
		return fmt.Errorf("failed to fetch version list from %s: %w", url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("server returned status %s for %s: %s", resp.Status, url, string(body))
	}

	var result struct {
		Versions []string `json:"versions"`
		Latest   string   `json:"latest"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return fmt.Errorf("failed to decode version list: %w", err)
	}

	fmt.Println("Available database versions:")
	for _, version := range result.Versions {
		if version == result.Latest {
			fmt.Printf("  %s (latest)\n", version)
		} else {
			fmt.Printf("  %s\n", version)
		}
	}

	return nil
}
