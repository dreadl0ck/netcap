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
	"sync"
	"sync/atomic"
	"time"

	"github.com/dreadl0ck/netcap/defaults"
	"github.com/dreadl0ck/netcap/internal/env"
	"github.com/dreadl0ck/netcap/resolvers"
)

// DBServer represents the database server
type DBServer struct {
	addr         string
	buildDir     string
	dbsDir       string
	currentDate  string // protected by mu
	mu           sync.RWMutex
	verbose      bool // read-only after construction
	nvdStartYear int  // read-only after construction

	// ready is true once an initial database revision is available to serve.
	// /health returns HTTP 200 in both states; the JSON body distinguishes
	// "initializing" from "healthy" so orchestrators using a simple curl -f
	// healthcheck pass immediately while clients can still detect readiness.
	ready atomic.Bool

	// initFn runs the first-revision initialization (existing-cache discovery
	// or fresh rebuild). It is injectable for tests; defaults to
	// (*DBServer).initialize when nil.
	initFn func() error
}

// NewDBServer creates a new database server instance
func NewDBServer(addr string, nvdStartYear int, verbose bool) *DBServer {
	// Use NC_CONFIG_ROOT if set, otherwise use default
	configRoot := os.Getenv(env.ConfigRoot)
	if configRoot == "" {
		configRoot = "netcap-dbs-server"
	}

	return &DBServer{
		addr:         addr,
		buildDir:     configRoot,
		dbsDir:       filepath.Join(configRoot, "dbs"),
		currentDate:  time.Now().Format("2006-01-02"),
		verbose:      verbose,
		nvdStartYear: nvdStartYear,
	}
}

// Start starts the database server.
//
// HTTP listener readiness is decoupled from database readiness: handlers are
// registered and ListenAndServe is called synchronously, while the initial
// database population runs on a background goroutine. This lets orchestrator
// healthchecks (e.g. `curl -f /health`) succeed within seconds even on a cold
// start where the first rebuild may take several minutes (NVD downloads,
// exploitdb clone, indexing). The /health body distinguishes "initializing"
// from "healthy" so clients that care can wait for true readiness.
func (s *DBServer) Start() error {
	// Create directories
	if err := os.MkdirAll(filepath.Join(s.buildDir, "build"), defaults.DirectoryPermission); err != nil {
		return fmt.Errorf("failed to create build directory: %w", err)
	}
	if err := os.MkdirAll(s.dbsDir, defaults.DirectoryPermission); err != nil {
		return fmt.Errorf("failed to create dbs directory: %w", err)
	}

	// Pre-flight: verify both directories are writable by the current process.
	// Without this check, a permission misconfiguration on a bind-mounted host
	// directory would only surface at the next scheduled rebuild (midnight),
	// making the server appear healthy while silently failing.
	if err := checkWritable(filepath.Join(s.buildDir, "build")); err != nil {
		return fmt.Errorf("build directory not writable: %w", err)
	}
	if err := checkWritable(s.dbsDir); err != nil {
		return fmt.Errorf("dbs directory not writable: %w", err)
	}

	// Setup HTTP handlers BEFORE doing any expensive initialization, so the
	// healthcheck endpoint is reachable as soon as the listener binds.
	http.HandleFunc("/", s.handleRoot)
	http.HandleFunc("/dbs/", s.handleDownload)
	http.HandleFunc("/dbs/latest", s.handleLatest)
	http.HandleFunc("/dbs/list", s.handleList)
	http.HandleFunc("/health", s.handleHealth)

	// Background initialization: discover an existing revision on the volume
	// (fast path; sets ready immediately) or run the initial rebuild
	// (slow path; can take minutes). Either way the HTTP listener is up
	// and /health returns 200 with status="initializing" until done.
	initFn := s.initFn
	if initFn == nil {
		initFn = s.initialize
	}
	go func() {
		if err := initFn(); err != nil {
			log.Printf("Warning: initial database setup failed: %v", err)
		}
		// Start nightly rebuild scheduler only after the initial attempt
		// finishes (success or failure). Subsequent nightly rebuilds will
		// retry transient sources like ja4db.
		go s.scheduleDailyRebuild()
	}()

	log.Printf("Starting database server on %s", s.addr)
	return http.ListenAndServe(s.addr, nil)
}

// initialize runs the first-revision setup: prefer an existing cached
// revision on the volume; otherwise perform a cold rebuild. On success it
// sets ready=true so /health reports "healthy".
func (s *DBServer) initialize() error {
	// Check if we have pre-existing databases (e.g., from a mounted volume)
	if hasExisting, existingVersion := s.checkExistingDatabases(); hasExisting {
		log.Printf("Found existing databases (version: %s)", existingVersion)
		log.Println("Using existing databases as initial revision")

		// Protect write to currentDate with lock
		s.mu.Lock()
		s.currentDate = existingVersion
		s.mu.Unlock()

		// Ensure latest symlinks/copies exist
		if err := s.ensureLatestLinks(); err != nil {
			log.Printf("Warning: failed to create latest links: %v", err)
		}

		s.ready.Store(true)
		return nil
	}

	// Initial database generation (cold path)
	log.Println("No existing databases found. Generating initial databases...")
	if err := s.rebuildDatabases(); err != nil {
		// Rebuild failed; remain not-ready. The nightly scheduler will
		// retry. Caller logs the error.
		return err
	}
	s.ready.Store(true)
	return nil
}

// rebuildDatabases generates a new version of the databases
func (s *DBServer) rebuildDatabases() error {
	log.Println("Starting database rebuild...")
	start := time.Now()

	// Set the current date for versioning (in local variable, not shared state yet)
	newDate := time.Now().Format("2006-01-02")

	// Create versioned directory
	versionedDir := filepath.Join(s.buildDir, "dbs", newDate)
	if err := os.MkdirAll(versionedDir, defaults.DirectoryPermission); err != nil {
		return fmt.Errorf("failed to create versioned directory: %w", err)
	}

	// Temporarily change the global nvdStartYear if needed
	if s.nvdStartYear != 0 {
		nvdStartYear = s.nvdStartYear
	}

	// Generate databases into a temporary location
	tempBuildDir := filepath.Join(s.buildDir, "build")
	tempDBsDir := filepath.Join(s.buildDir, "temp-dbs")

	if err := os.RemoveAll(tempBuildDir); err != nil {
		log.Printf("Warning: failed to clean build directory: %v", err)
	}
	if err := os.RemoveAll(tempDBsDir); err != nil {
		log.Printf("Warning: failed to clean temp-dbs directory: %v", err)
	}

	if err := os.MkdirAll(tempBuildDir, defaults.DirectoryPermission); err != nil {
		return fmt.Errorf("failed to create temp build directory: %w", err)
	}
	if err := os.MkdirAll(tempDBsDir, defaults.DirectoryPermission); err != nil {
		return fmt.Errorf("failed to create temp dbs directory: %w", err)
	}

	// Process each source (exploitdb will be cloned fresh to get latest exploits).
	// activeSources honours NC_DBS_SKIP_SOURCES so operators can bypass
	// known-bad upstreams (e.g. ja4db.json) without rebuilding the image.
	var wg sync.WaitGroup
	for _, source := range activeSources() {
		wg.Add(1)
		go s.processSourceForServer(source, tempBuildDir, tempDBsDir, &wg)
	}
	wg.Wait()

	// Create tarball of the databases
	tarballPath := filepath.Join(s.buildDir, "dbs", newDate+".tar.gz")
	if err := s.createTarball(tempDBsDir, tarballPath); err != nil {
		return fmt.Errorf("failed to create tarball: %w", err)
	}

	// Create metadata file
	metadata := map[string]any{
		"version":        newDate,
		"created_at":     time.Now().UTC().Format(time.RFC3339),
		"tarball":        newDate + ".tar.gz",
		"nvd_start_year": s.nvdStartYear,
	}
	metadataPath := filepath.Join(s.buildDir, "dbs", newDate+".json")
	if err := s.writeMetadata(metadata, metadataPath); err != nil {
		return fmt.Errorf("failed to write metadata: %w", err)
	}

	// Update "latest" symlink
	latestTarball := filepath.Join(s.buildDir, "dbs", "latest.tar.gz")
	latestMetadata := filepath.Join(s.buildDir, "dbs", "latest.json")

	os.Remove(latestTarball)
	os.Remove(latestMetadata)

	if err := os.Symlink(newDate+".tar.gz", latestTarball); err != nil {
		log.Printf("Warning: failed to create latest tarball symlink: %v", err)
	}
	if err := os.Symlink(newDate+".json", latestMetadata); err != nil {
		log.Printf("Warning: failed to create latest metadata symlink: %v", err)
	}

	// Now update the shared state - this is the only part that needs to be locked
	s.mu.Lock()
	s.currentDate = newDate
	s.mu.Unlock()

	// Mark the server as ready once a revision has been published. Idempotent.
	s.ready.Store(true)

	// Clean up old database versions to save storage space
	// Note: This reads s.currentDate but we just updated it, so it's safe
	if err := s.cleanupOldVersions(); err != nil {
		log.Printf("Warning: failed to clean up old versions: %v", err)
	}

	log.Printf("Database rebuild completed in %v", time.Since(start))
	return nil
}

// cleanupOldVersions removes all database versions except the current one
func (s *DBServer) cleanupOldVersions() error {
	// Get current date with lock
	s.mu.RLock()
	currentDate := s.currentDate
	s.mu.RUnlock()

	dbsPath := filepath.Join(s.buildDir, "dbs")

	entries, err := os.ReadDir(dbsPath)
	if err != nil {
		return fmt.Errorf("failed to read dbs directory: %w", err)
	}

	var (
		removedCount int
		freedSpace   int64
	)

	for _, entry := range entries {
		name := entry.Name()

		// Skip the current version files
		if name == currentDate+".tar.gz" || name == currentDate+".json" {
			continue
		}

		// Skip the latest symlinks
		if name == "latest.tar.gz" || name == "latest.json" {
			continue
		}

		// Skip non-versioned files and directories
		if !entry.IsDir() && (filepath.Ext(name) == ".gz" || filepath.Ext(name) == ".json") {
			// Check if it's a versioned file (YYYY-MM-DD pattern)
			baseName := name
			if filepath.Ext(name) == ".gz" {
				baseName = name[:len(name)-len(".tar.gz")]
			} else if filepath.Ext(name) == ".json" {
				baseName = name[:len(name)-len(".json")]
			}

			// If it matches date pattern and is not current version, delete it
			if len(baseName) == 10 && baseName != currentDate {
				filePath := filepath.Join(dbsPath, name)

				// Get file size before deletion for reporting
				if info, err := os.Stat(filePath); err == nil {
					freedSpace += info.Size()
				}

				if err := os.Remove(filePath); err != nil {
					log.Printf("Warning: failed to remove old file %s: %v", name, err)
				} else {
					removedCount++
					if s.verbose {
						log.Printf("Removed old version file: %s", name)
					}
				}
			}
		}
	}

	if removedCount > 0 {
		log.Printf("Cleanup: removed %d old version files (freed ~%d MB)",
			removedCount, freedSpace/(1024*1024))
	}

	return nil
}

func (s *DBServer) processSourceForServer(source *datasource, buildDir, dbsDir string, wg *sync.WaitGroup) {
	defer wg.Done()

	outFilePath := filepath.Join(buildDir, source.name)

	// fetch via HTTP GET from single remote source if provided
	fetchResource(source, outFilePath)

	// run hook
	if source.hook != nil {
		// The hooks expect a base directory with "build" and "dbs" subdirectories
		// buildDir is already pointing to base/build, so parent is the base
		tempBase := filepath.Dir(buildDir)

		// Ensure the dbs directory that hooks will write to exists
		// and points to our temp-dbs directory
		hooksDbsDir := filepath.Join(tempBase, "dbs")

		// Remove any existing dbs directory/symlink
		os.RemoveAll(hooksDbsDir)

		// Create symlink from base/dbs to our actual temp-dbs directory
		relPath, err := filepath.Rel(tempBase, dbsDir)
		if err != nil {
			relPath = dbsDir
		}

		// Try to create symlink, fall back to using dbsDir directly if it fails
		if err := os.Symlink(relPath, hooksDbsDir); err != nil {
			// Symlink failed (maybe Windows?), just ensure dbsDir is what hooks will use
			// In this case, we need to rewrite the base to point to parent of dbsDir
			tempBase = filepath.Dir(dbsDir)
		}

		if err := source.hook(outFilePath, source, tempBase); err != nil {
			log.Printf("hook for %s failed with error %v", source.name, err)
		}
	}
}

// createTarball creates a gzipped tarball of the databases directory
func (s *DBServer) createTarball(sourceDir, targetPath string) error {
	file, err := os.Create(targetPath)
	if err != nil {
		return err
	}
	defer file.Close()

	gzipWriter := gzip.NewWriter(file)
	defer gzipWriter.Close()

	tarWriter := tar.NewWriter(gzipWriter)
	defer tarWriter.Close()

	var fileCount, dirCount int
	var exploitdbIncluded bool

	err = filepath.Walk(sourceDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// Update header name to be relative to source directory
		relPath, err := filepath.Rel(sourceDir, path)
		if err != nil {
			return err
		}

		// Skip the root directory entry
		if relPath == "." {
			return nil
		}

		// Track if exploitdb is included
		if info.IsDir() && info.Name() == "exploitdb" {
			exploitdbIncluded = true
			log.Printf("Including exploitdb folder in tarball: %s", relPath)
		}

		// Handle directories
		if info.IsDir() {
			dirCount++
			header, err := tar.FileInfoHeader(info, info.Name())
			if err != nil {
				return err
			}
			header.Name = relPath
			return tarWriter.WriteHeader(header)
		}

		// For regular files, open first and get fresh stat to avoid race conditions
		if !info.Mode().IsRegular() {
			return nil
		}

		f, err := os.Open(path)
		if err != nil {
			return err
		}
		defer f.Close()

		// Get fresh file info AFTER opening the file
		// This prevents "archive/tar: write too long" errors when files change
		// between the initial Walk stat and when we actually read the file
		freshInfo, err := f.Stat()
		if err != nil {
			return err
		}

		// Create header with the fresh size
		header, err := tar.FileInfoHeader(freshInfo, freshInfo.Name())
		if err != nil {
			return err
		}
		header.Name = relPath

		// Write header
		if err := tarWriter.WriteHeader(header); err != nil {
			return err
		}

		fileCount++

		// Copy exactly the number of bytes specified in the header
		// Using CopyN ensures we don't write more than expected even if
		// the file grows while we're reading it
		_, err = io.CopyN(tarWriter, f, freshInfo.Size())
		if err != nil && err != io.EOF {
			return err
		}

		return nil
	})

	if err != nil {
		return err
	}

	log.Printf("Tarball created: %d files, %d directories", fileCount, dirCount)
	if exploitdbIncluded {
		log.Println("✓ exploitdb folder with exploit code snippets included in archive")
	} else {
		log.Println("⚠ exploitdb folder was not found in source directory")
	}

	return nil
}

// writeMetadata writes metadata as JSON
func (s *DBServer) writeMetadata(metadata map[string]any, path string) error {
	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	return encoder.Encode(metadata)
}

// scheduleDailyRebuild schedules database rebuilds at midnight
func (s *DBServer) scheduleDailyRebuild() {
	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()

	for range ticker.C {
		now := time.Now()

		// Check if it's midnight (hour 0)
		if now.Hour() == 0 {
			// Check if we already built today
			s.mu.RLock()
			lastBuild := s.currentDate
			s.mu.RUnlock()

			today := now.Format("2006-01-02")
			if lastBuild != today {
				log.Println("Starting scheduled nightly database rebuild...")
				if err := s.rebuildDatabases(); err != nil {
					log.Printf("Scheduled rebuild failed: %v", err)
				}
			}
		}
	}
}

// checkExistingDatabases checks if there are pre-existing database files
// Returns true and the version string if databases exist, false otherwise
func (s *DBServer) checkExistingDatabases() (bool, string) {
	// Check if the dbs directory has any versioned database files
	entries, err := os.ReadDir(s.dbsDir)
	if err != nil {
		return false, ""
	}

	// Look for the most recent versioned database
	var latestVersion string
	var latestTime time.Time

	for _, entry := range entries {
		name := entry.Name()

		// Check for tarball files with date pattern (YYYY-MM-DD.tar.gz)
		if filepath.Ext(name) == ".gz" && len(name) >= len("2006-01-02.tar.gz") {
			dateStr := name[:len("2006-01-02")]
			if t, err := time.Parse("2006-01-02", dateStr); err == nil {
				// Also check if corresponding JSON metadata exists
				jsonPath := filepath.Join(s.dbsDir, dateStr+".json")
				if _, err := os.Stat(jsonPath); err == nil {
					if latestVersion == "" || t.After(latestTime) {
						latestVersion = dateStr
						latestTime = t
					}
				}
			}
		}
	}

	if latestVersion != "" {
		return true, latestVersion
	}

	// Also check in resolvers.DataBaseFolderPath if it's different
	if resolvers.DataBaseFolderPath != "" && resolvers.DataBaseFolderPath != s.dbsDir {
		// Check if databases exist in the standard location
		if _, err := os.Stat(filepath.Join(resolvers.DataBaseFolderPath, "service-names-port-numbers.csv")); err == nil {
			// We have raw databases, create a tarball from them
			log.Println("Found databases in standard location, creating initial tarball...")
			return s.createInitialTarballFromExisting()
		}
	}

	return false, ""
}

// createInitialTarballFromExisting creates a tarball from existing database files
func (s *DBServer) createInitialTarballFromExisting() (bool, string) {
	currentDate := time.Now().Format("2006-01-02")
	tarballPath := filepath.Join(s.dbsDir, currentDate+".tar.gz")

	// Create tarball from existing databases
	if err := s.createTarball(resolvers.DataBaseFolderPath, tarballPath); err != nil {
		log.Printf("Failed to create tarball from existing databases: %v", err)
		return false, ""
	}

	// Create metadata
	metadata := map[string]any{
		"version":        currentDate,
		"created_at":     time.Now().Format(time.RFC3339),
		"tarball":        currentDate + ".tar.gz",
		"source":         "imported from existing databases",
		"nvd_start_year": s.nvdStartYear,
	}

	metadataPath := filepath.Join(s.dbsDir, currentDate+".json")
	if err := s.writeMetadata(metadata, metadataPath); err != nil {
		log.Printf("Failed to write metadata: %v", err)
		return false, ""
	}

	return true, currentDate
}

// ensureLatestLinks ensures that 'latest' symlinks/copies exist
func (s *DBServer) ensureLatestLinks() error {
	s.mu.RLock()
	currentDate := s.currentDate
	s.mu.RUnlock()

	latestTarball := filepath.Join(s.dbsDir, "latest.tar.gz")
	latestMetadata := filepath.Join(s.dbsDir, "latest.json")

	sourceTarball := filepath.Join(s.dbsDir, currentDate+".tar.gz")
	sourceMetadata := filepath.Join(s.dbsDir, currentDate+".json")

	// Check if source files exist
	if _, err := os.Stat(sourceTarball); err != nil {
		return fmt.Errorf("source tarball not found: %w", err)
	}
	if _, err := os.Stat(sourceMetadata); err != nil {
		return fmt.Errorf("source metadata not found: %w", err)
	}

	// Remove existing latest links/files if they exist
	os.Remove(latestTarball)
	os.Remove(latestMetadata)

	// Try to create symlinks, fall back to copying if symlinks fail
	if err := os.Symlink(currentDate+".tar.gz", latestTarball); err != nil {
		// Symlink failed, try copying
		if err := copyFile(sourceTarball, latestTarball); err != nil {
			return fmt.Errorf("failed to create latest tarball link/copy: %w", err)
		}
	}

	if err := os.Symlink(currentDate+".json", latestMetadata); err != nil {
		// Symlink failed, try copying
		if err := copyFile(sourceMetadata, latestMetadata); err != nil {
			return fmt.Errorf("failed to create latest metadata link/copy: %w", err)
		}
	}

	return nil
}

// checkWritable verifies that the given directory is writable by the current
// process by creating and removing a temporary probe file. It returns a
// descriptive error including the running uid/gid and a hint about bind-mount
// permissions when the probe fails.
func checkWritable(dir string) error {
	f, err := os.CreateTemp(dir, ".write-probe-*")
	if err != nil {
		uid := os.Getuid()
		gid := os.Getgid()
		return fmt.Errorf(
			"cannot write to %s (running as uid=%d gid=%d): %w; "+
				"if this is a bind-mounted host directory, ensure it is owned by the container user "+
				"(e.g. `sudo chown -R 1000:1000 <hostdir>` for the default netcap user)",
			dir, uid, gid, err,
		)
	}
	name := f.Name()
	f.Close()
	if err := os.Remove(name); err != nil {
		// Non-fatal: we could create the file, removal failure is a warning.
		log.Printf("Warning: failed to remove write-probe file %s: %v", name, err)
	}
	return nil
}

// copyFile copies a file from src to dst
func copyFile(src, dst string) error {
	sourceFile, err := os.Open(src)
	if err != nil {
		return err
	}
	defer sourceFile.Close()

	destFile, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer destFile.Close()

	_, err = io.Copy(destFile, sourceFile)
	return err
}

// handleDownload serves database tarballs
func (s *DBServer) handleDownload(w http.ResponseWriter, r *http.Request) {
	// Extract version from path (e.g., /dbs/2024-01-15.tar.gz or /dbs/latest.tar.gz)
	filename := filepath.Base(r.URL.Path)
	filePath := filepath.Join(s.buildDir, "dbs", filename)

	// Check if file exists
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		http.Error(w, "Database version not found", http.StatusNotFound)
		return
	}

	// Serve the file
	w.Header().Set("Content-Type", "application/gzip")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%s", filename))
	http.ServeFile(w, r, filePath)

	log.Printf("Served database: %s to %s", filename, r.RemoteAddr)
}

// handleLatest returns metadata about the latest version
func (s *DBServer) handleLatest(w http.ResponseWriter, r *http.Request) {
	// Only lock to read currentDate, not during file I/O
	s.mu.RLock()
	currentDate := s.currentDate
	s.mu.RUnlock()

	metadataPath := filepath.Join(s.buildDir, "dbs", currentDate+".json")

	data, err := os.ReadFile(metadataPath)
	if err != nil {
		http.Error(w, "Metadata not found", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(data)
}

// handleList lists all available database versions (only latest due to storage optimization)
func (s *DBServer) handleList(w http.ResponseWriter, r *http.Request) {
	// Only lock to read currentDate, not during JSON encoding
	s.mu.RLock()
	currentDate := s.currentDate
	s.mu.RUnlock()

	// Since we only keep the latest version, return just that
	response := map[string]any{
		"versions": []string{currentDate},
		"latest":   currentDate,
		"note":     "Server is configured to keep only the latest version to optimize storage",
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// handleRoot serves a simple text-based health status page on the root path
func (s *DBServer) handleRoot(w http.ResponseWriter, r *http.Request) {
	// Only handle exact root path, let other paths fall through to their handlers
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}

	s.mu.RLock()
	currentVersion := s.currentDate
	s.mu.RUnlock()

	statusLabel := "INITIALIZING"
	if s.ready.Load() {
		statusLabel = "HEALTHY"
	}

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	fmt.Fprintf(w, "NETCAP Database Server\n")
	fmt.Fprintf(w, "======================\n\n")
	fmt.Fprintf(w, "Status: %s\n", statusLabel)
	fmt.Fprintf(w, "Latest Database Version: %s\n", currentVersion)
	fmt.Fprintf(w, "Timestamp: %s\n\n", time.Now().UTC().Format(time.RFC3339))
	fmt.Fprintf(w, "Available Endpoints:\n")
	fmt.Fprintf(w, "  GET /              - This status page\n")
	fmt.Fprintf(w, "  GET /health        - Health check (JSON)\n")
	fmt.Fprintf(w, "  GET /dbs/latest    - Latest version metadata (JSON)\n")
	fmt.Fprintf(w, "  GET /dbs/list      - List available versions (JSON)\n")
	fmt.Fprintf(w, "  GET /dbs/<file>    - Download database file\n")
}

// handleHealth provides a health check endpoint.
//
// Always responds with HTTP 200 so that a simple liveness probe (e.g. the
// container-level `curl -f /health`) succeeds as soon as the listener binds,
// even before the first database revision is available. The JSON status field
// distinguishes "initializing" (no revision published yet) from "healthy"
// (at least one revision available). Clients that need true readiness can
// poll for status == "healthy" or use /dbs/latest.
func (s *DBServer) handleHealth(w http.ResponseWriter, r *http.Request) {
	// Read current date with lock (lock is now only held briefly during rebuilds)
	s.mu.RLock()
	currentVersion := s.currentDate
	s.mu.RUnlock()

	status := "initializing"
	if s.ready.Load() {
		status = "healthy"
	}

	health := map[string]any{
		"status":          status,
		"current_version": currentVersion,
		"timestamp":       time.Now().UTC().Format(time.RFC3339),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(health)
}
