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
	"crypto/sha256"
	"encoding/hex"
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

	"github.com/dreadl0ck/netcap"
	"github.com/dreadl0ck/netcap/defaults"
	"github.com/dreadl0ck/netcap/internal/env"
	"github.com/dreadl0ck/netcap/internal/resolvers"
	"github.com/dreadl0ck/netcap/internal/vulndb"
)

// Layout is the version of the database tarball layout served under
// /dbs/v<Layout>/. Layout 1 (netcap < v0.10) carried bleve indexes and is
// served frozen from the legacy dbs/ directory; layout 2 carries
// netcap.sqlite.
const Layout = 2

// layoutPrefix is the URL and directory prefix of the current layout.
var layoutPrefix = fmt.Sprintf("v%d", Layout)

// DBServer represents the database server
type DBServer struct {
	addr         string
	buildDir     string // config root: build/, staging/, v2/ and legacy dbs/
	dbsDir       string // published revisions of the current layout
	legacyDir    string // frozen layout-1 revision for netcap < v0.10
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
		dbsDir:       filepath.Join(configRoot, layoutPrefix),
		legacyDir:    filepath.Join(configRoot, "dbs"),
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
	http.HandleFunc("/dbs/"+layoutPrefix+"/", s.handleDownload)
	http.HandleFunc("/dbs/"+layoutPrefix+"/latest", s.handleLatest)
	http.HandleFunc("/dbs/"+layoutPrefix+"/list", s.handleList)
	// Layout 1 routes keep netcap < v0.10 clients working on their last
	// bleve revision; nothing rebuilds them any more.
	http.HandleFunc("/dbs/", s.handleLegacy)
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
		// retry transient sources.
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

// rebuildDatabases generates a new revision and publishes it only when
// netcap.sqlite was built, so a failed upstream never replaces a good
// revision.
func (s *DBServer) rebuildDatabases() error {
	log.Println("Starting database rebuild...")
	start := time.Now()

	newDate := time.Now().Format("2006-01-02")

	if s.nvdStartYear != 0 {
		nvdStartYear = s.nvdStartYear
	}

	// Hooks expect a base directory with build/ and dbs/; staging is private
	// to the rebuild, so parallel hooks never touch a served directory.
	stagingBase := filepath.Join(s.buildDir, "staging")
	stagingBuild := filepath.Join(stagingBase, "build")
	stagingDBs := filepath.Join(stagingBase, "dbs")

	if err := os.RemoveAll(stagingBase); err != nil {
		return fmt.Errorf("failed to clean staging directory: %w", err)
	}
	for _, dir := range []string{stagingBuild, stagingDBs, s.dbsDir} {
		if err := os.MkdirAll(dir, defaults.DirectoryPermission); err != nil {
			return fmt.Errorf("failed to create %s: %w", dir, err)
		}
	}

	// activeSources honours NC_DBS_SKIP_SOURCES so operators can bypass
	// known-bad upstreams without rebuilding the image.
	var wg sync.WaitGroup
	for _, source := range activeSources() {
		wg.Add(1)
		go s.processSourceForServer(source, stagingBase, &wg)
	}
	wg.Wait()
	if err := includeDBIP(stagingBase, filepath.Join(s.buildDir, "geoip-cache")); err != nil {
		return fmt.Errorf("failed to include DB-IP, keeping previous revision: %w", err)
	}

	if err := BuildVulnDB(stagingBuild, stagingDBs, nvdStartYear, s.verbose); err != nil {
		return fmt.Errorf("failed to build %s, keeping previous revision: %w", vulndb.FileName, err)
	}

	tarballName := newDate + ".tar.gz"
	tarballPath := filepath.Join(s.dbsDir, tarballName)

	sum, size, err := s.createTarball(stagingDBs, tarballPath)
	if err != nil {
		return fmt.Errorf("failed to create tarball: %w", err)
	}

	metadata := map[string]any{
		"version":        newDate,
		"created_at":     time.Now().UTC().Format(time.RFC3339),
		"tarball":        tarballName,
		"nvd_start_year": nvdStartYear,
		"layout":         Layout,
		"vulndb_schema":  vulndb.SchemaVersion,
		"sha256":         sum,
		"size":           size,
		"netcap_version": netcap.Version,
	}
	if err := s.writeMetadata(metadata, filepath.Join(s.dbsDir, newDate+".json")); err != nil {
		return fmt.Errorf("failed to write metadata: %w", err)
	}

	s.mu.Lock()
	s.currentDate = newDate
	s.mu.Unlock()

	if err := s.ensureLatestLinks(); err != nil {
		log.Printf("Warning: failed to update latest links: %v", err)
	}

	s.ready.Store(true)

	if err := s.cleanupOldVersions(); err != nil {
		log.Printf("Warning: failed to clean up old versions: %v", err)
	}
	if err := os.RemoveAll(stagingBase); err != nil {
		log.Printf("Warning: failed to remove staging directory: %v", err)
	}

	log.Printf("Database rebuild completed in %v (%s, sha256 %s)", time.Since(start), tarballName, sum)
	return nil
}

// cleanupOldVersions removes all database versions except the current one
func (s *DBServer) cleanupOldVersions() error {
	// Get current date with lock
	s.mu.RLock()
	currentDate := s.currentDate
	s.mu.RUnlock()

	dbsPath := s.dbsDir

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

func (s *DBServer) processSourceForServer(source *datasource, base string, wg *sync.WaitGroup) {
	defer wg.Done()

	outFilePath := filepath.Join(base, "build", source.name)

	if err := fetchResource(source, outFilePath); err != nil {
		log.Printf("fetching %s failed: %v", source.name, err)
		return
	}

	if source.hook != nil {
		if err := source.hook(outFilePath, source, base); err != nil {
			log.Printf("hook for %s failed with error %v", source.name, err)
		}
	}
}

// createTarball writes a gzipped tarball of sourceDir to targetPath via a
// temporary file and returns its sha256 and size. sourceDir must not contain
// targetPath.
func (s *DBServer) createTarball(sourceDir, targetPath string) (string, int64, error) {
	if err := validateGeoIPBundle(sourceDir); err != nil {
		return "", 0, err
	}
	if err := writeDatabaseNotices(sourceDir); err != nil {
		return "", 0, fmt.Errorf("failed to include database notices: %w", err)
	}

	tmpPath := targetPath + ".tmp"

	file, err := os.Create(tmpPath)
	if err != nil {
		return "", 0, err
	}
	defer os.Remove(tmpPath)
	defer file.Close()

	hasher := sha256.New()
	gzipWriter := gzip.NewWriter(io.MultiWriter(file, hasher))
	tarWriter := tar.NewWriter(gzipWriter)

	var fileCount, dirCount int
	var exploitdbIncluded bool

	err = filepath.Walk(sourceDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if excludedFromDistribution(path) {
			if info.IsDir() {
				return filepath.SkipDir
			}
			return nil
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
		return "", 0, err
	}
	if err = tarWriter.Close(); err != nil {
		return "", 0, err
	}
	if err = gzipWriter.Close(); err != nil {
		return "", 0, err
	}
	if err = file.Sync(); err != nil {
		return "", 0, err
	}

	stat, err := file.Stat()
	if err != nil {
		return "", 0, err
	}
	if err = os.Rename(tmpPath, targetPath); err != nil {
		return "", 0, err
	}

	log.Printf("Tarball created: %d files, %d directories", fileCount, dirCount)
	if exploitdbIncluded {
		log.Println("✓ exploitdb folder with exploit code snippets included in archive")
	} else {
		log.Println("⚠ exploitdb folder was not found in source directory")
	}

	return hex.EncodeToString(hasher.Sum(nil)), stat.Size(), nil
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
		// Check if layout-2 databases exist in the standard location
		if _, err := os.Stat(filepath.Join(resolvers.DataBaseFolderPath, vulndb.FileName)); err == nil {
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

	if err := os.MkdirAll(s.dbsDir, defaults.DirectoryPermission); err != nil {
		log.Printf("Failed to create %s: %v", s.dbsDir, err)
		return false, ""
	}

	// Create tarball from existing databases
	sum, size, err := s.createTarball(resolvers.DataBaseFolderPath, tarballPath)
	if err != nil {
		log.Printf("Failed to create tarball from existing databases: %v", err)
		return false, ""
	}

	// Create metadata
	metadata := map[string]any{
		"version":        currentDate,
		"created_at":     time.Now().UTC().Format(time.RFC3339),
		"tarball":        currentDate + ".tar.gz",
		"source":         "imported from existing databases",
		"nvd_start_year": s.nvdStartYear,
		"layout":         Layout,
		"vulndb_schema":  vulndb.SchemaVersion,
		"sha256":         sum,
		"size":           size,
		"netcap_version": netcap.Version,
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

	if err := replaceWithLink(currentDate+".tar.gz", sourceTarball, latestTarball); err != nil {
		return fmt.Errorf("failed to create latest tarball link/copy: %w", err)
	}

	if err := replaceWithLink(currentDate+".json", sourceMetadata, latestMetadata); err != nil {
		return fmt.Errorf("failed to create latest metadata link/copy: %w", err)
	}

	return nil
}

// replaceWithLink points dst at target (relative) by renaming a fresh
// symlink over it, so readers never see dst missing. It copies source when
// symlinks are unavailable.
func replaceWithLink(target, source, dst string) error {
	tmp := dst + ".tmp"
	_ = os.Remove(tmp)
	if err := os.Symlink(target, tmp); err == nil {
		return os.Rename(tmp, dst)
	}
	if err := copyFile(source, tmp); err != nil {
		return err
	}
	return os.Rename(tmp, dst)
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

// handleDownload serves tarballs of the current layout
// (e.g. /dbs/v2/2026-10-04.tar.gz or /dbs/v2/latest.tar.gz).
func (s *DBServer) handleDownload(w http.ResponseWriter, r *http.Request) {
	serveTarball(w, r, s.dbsDir)
}

// handleLegacy serves the frozen layout-1 revision to netcap < v0.10 under
// the original /dbs/latest, /dbs/list and /dbs/<file> routes.
func (s *DBServer) handleLegacy(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Deprecation", "true")
	w.Header().Set("Link", fmt.Sprintf("</dbs/%s/latest>; rel=\"successor-version\"", layoutPrefix))

	switch r.URL.Path {
	case "/dbs/latest":
		data, err := os.ReadFile(filepath.Join(s.legacyDir, "latest.json"))
		if err != nil {
			http.Error(w, "no legacy database revision; upgrade netcap to v0.10 or later", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write(data)
	case "/dbs/list":
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"note": "frozen layout 1 (bleve) for netcap < v0.10; current revisions are listed at /dbs/" + layoutPrefix + "/list",
		})
	default:
		serveTarball(w, r, s.legacyDir)
	}
}

func serveTarball(w http.ResponseWriter, r *http.Request, dir string) {
	filename := filepath.Base(r.URL.Path)
	if filepath.Ext(filename) != ".gz" {
		http.Error(w, "Database version not found", http.StatusNotFound)
		return
	}
	filePath := filepath.Join(dir, filename)

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

	metadataPath := filepath.Join(s.dbsDir, currentDate+".json")

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
	fmt.Fprintf(w, "  GET /dbs/%s/latest - Latest version metadata (JSON)\n", layoutPrefix)
	fmt.Fprintf(w, "  GET /dbs/%s/list   - List available versions (JSON)\n", layoutPrefix)
	fmt.Fprintf(w, "  GET /dbs/%s/<file> - Download database tarball\n", layoutPrefix)
	fmt.Fprintf(w, "  GET /dbs/latest    - Frozen bleve revision for netcap < v0.10 (deprecated)\n")
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
		"layout":          Layout,
		"timestamp":       time.Now().UTC().Format(time.RFC3339),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(health)
}
