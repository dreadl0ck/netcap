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
	"archive/tar"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/dreadl0ck/netcap/defaults"
	"github.com/dreadl0ck/netcap/internal/env"
	"github.com/dreadl0ck/netcap/resolvers"
	"github.com/dustin/go-humanize"
)

const (
	defaultDBsURL = "https://dbs.netcap.io"
	httpTimeout   = 30 * time.Second
)

// DBMetadata represents metadata about a database version
type DBMetadata struct {
	Version      string `json:"version"`
	CreatedAt    string `json:"created_at"`
	Tarball      string `json:"tarball"`
	NVDStartYear int    `json:"nvd_start_year"`
}

// DownloadDBs downloads the latest databases from the configured server
func DownloadDBs(serverURL string, force bool) error {
	// Get server URL from environment or use default
	if serverURL == "" {
		serverURL = os.Getenv(env.NetcapDBsURL)
		if serverURL == "" {
			serverURL = defaultDBsURL
		}
	}

	log.Printf("Downloading databases from %s", serverURL)

	// Fetch metadata about the latest version
	metadata, err := fetchMetadata(serverURL)
	if err != nil {
		return fmt.Errorf("failed to fetch database metadata: %w", err)
	}

	log.Printf("Latest database version: %s (created: %s)", metadata.Version, metadata.CreatedAt)

	// Check if we already have this version
	versionFile := filepath.Join(resolvers.ConfigRootPath, ".db-version")
	if !force {
		if data, err := os.ReadFile(versionFile); err == nil {
			currentVersion := string(data)
			if currentVersion == metadata.Version {
				log.Printf("Already have the latest version (%s), skipping download", metadata.Version)
				return nil
			}
		}
	}

	// Create directories
	if err := os.MkdirAll(resolvers.ConfigRootPath, defaults.DirectoryPermission); err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}
	if err := os.MkdirAll(resolvers.DataBaseFolderPath, defaults.DirectoryPermission); err != nil {
		return fmt.Errorf("failed to create database directory: %w", err)
	}

	// Download the tarball
	tarballURL := fmt.Sprintf("%s/dbs/%s", serverURL, metadata.Tarball)
	tempTarball := filepath.Join(resolvers.ConfigRootPath, "dbs-download.tar.gz")

	log.Printf("Downloading database tarball to: %s", tempTarball)
	start := time.Now()

	if err := downloadFile(tarballURL, tempTarball); err != nil {
		return fmt.Errorf("failed to download database tarball: %w", err)
	}

	// Get file size for reporting
	stat, _ := os.Stat(tempTarball)
	log.Printf("Downloaded %s in %v to: %s", humanize.Bytes(uint64(stat.Size())), time.Since(start), tempTarball)

	// Extract the tarball
	log.Printf("Extracting databases to: %s", resolvers.DataBaseFolderPath)
	if err := extractTarball(tempTarball, resolvers.DataBaseFolderPath); err != nil {
		return fmt.Errorf("failed to extract database tarball: %w", err)
	}

	// Clean up temporary tarball
	os.Remove(tempTarball)

	// Save version file
	if err := os.WriteFile(versionFile, []byte(metadata.Version), defaults.FilePermission); err != nil {
		log.Printf("Warning: failed to write version file: %v", err)
	}

	log.Printf("Successfully downloaded and installed databases to: %s (version: %s)", resolvers.DataBaseFolderPath, metadata.Version)
	return nil
}

// fetchMetadata retrieves metadata about the latest database version
func fetchMetadata(serverURL string) (*DBMetadata, error) {
	client := &http.Client{
		Timeout: httpTimeout,
	}

	url := fmt.Sprintf("%s/dbs/latest", serverURL)
	log.Printf("Fetching metadata from: %s", url)

	resp, err := client.Get(url)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch metadata from %s: %w", url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("server returned status %s for %s: %s", resp.Status, url, string(body))
	}

	var metadata DBMetadata
	if err := json.NewDecoder(resp.Body).Decode(&metadata); err != nil {
		return nil, fmt.Errorf("failed to decode metadata: %w", err)
	}

	return &metadata, nil
}

// downloadFile downloads a file from a URL to a local path with progress reporting
func downloadFile(url, filepath string) error {
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
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("bad status %s for %s: %s", resp.Status, url, string(body))
	}

	// Create a progress writer
	progressWriter := &progressWriter{
		total:      resp.ContentLength,
		downloaded: 0,
		lastReport: time.Now(),
	}

	// Writer that writes to file and tracks progress
	writer := io.MultiWriter(out, progressWriter)

	// Write the body to file
	_, err = io.Copy(writer, resp.Body)
	if err != nil {
		return fmt.Errorf("failed to write downloaded data: %w", err)
	}

	// Final progress report
	fmt.Println()

	return nil
}

// progressWriter tracks download progress
type progressWriter struct {
	total      int64
	downloaded int64
	lastReport time.Time
}

func (pw *progressWriter) Write(p []byte) (int, error) {
	n := len(p)
	pw.downloaded += int64(n)

	// Report progress every second
	if time.Since(pw.lastReport) > time.Second {
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
	}

	return n, nil
}

// extractTarball extracts a gzipped tarball to the target directory
func extractTarball(tarballPath, targetDir string) error {
	// Open the tarball
	file, err := os.Open(tarballPath)
	if err != nil {
		return err
	}
	defer file.Close()

	// Create gzip reader
	gzipReader, err := gzip.NewReader(file)
	if err != nil {
		return err
	}
	defer gzipReader.Close()

	// Create tar reader
	tarReader := tar.NewReader(gzipReader)

	// Extract files
	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}

		// Strip leading "dbs/" directory if present to avoid nesting
		// The tarball contains "dbs/file.json" but we're extracting to ".../dbs" already
		targetPath := header.Name
		if len(targetPath) > 4 && targetPath[:4] == "dbs/" {
			targetPath = targetPath[4:]
		}

		// Skip if we stripped everything (was just "dbs/" directory entry)
		if targetPath == "" {
			continue
		}

		// Construct target path
		target := filepath.Join(targetDir, targetPath)

		// Ensure parent directory exists
		if err := os.MkdirAll(filepath.Dir(target), defaults.DirectoryPermission); err != nil {
			return err
		}

		// Handle different file types
		switch header.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, os.FileMode(header.Mode)); err != nil {
				return err
			}
		case tar.TypeReg:
			outFile, err := os.OpenFile(target, os.O_CREATE|os.O_RDWR|os.O_TRUNC, os.FileMode(header.Mode))
			if err != nil {
				return err
			}
			if _, err := io.Copy(outFile, tarReader); err != nil {
				outFile.Close()
				return err
			}
			outFile.Close()
		default:
			log.Printf("Warning: unknown file type %v in tar for %s", header.Typeflag, header.Name)
		}
	}

	return nil
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

	url := fmt.Sprintf("%s/dbs/list", serverURL)
	log.Printf("Fetching version list from: %s", url)

	resp, err := client.Get(url)
	if err != nil {
		return fmt.Errorf("failed to fetch version list from %s: %w", url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
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
