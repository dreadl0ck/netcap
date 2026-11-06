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

	"github.com/dreadl0ck/netcap/internal/env"
)

// Layout is the current reviewed database distribution format.
const Layout = V3Layout

// layoutPrefix is the URL and directory prefix of the current layout.
var layoutPrefix = fmt.Sprintf("v%d", Layout)

// DBServer represents the database server
type DBServer struct {
	addr               string
	buildDir           string                // config root; existing v1/v2 artifacts remain untouched
	dbsDir             string                // published revisions of the current layout
	legacyDir          string                // frozen layout-1 revision for netcap < v0.10
	currentDate        string                // protected by mu
	validated          map[string]DBMetadata // protected by mu; only completely verified objects
	lastBuildAttempt   string                // protected by mu
	lastBuildError     string                // protected by mu
	mu                 sync.RWMutex
	verbose            bool // read-only after construction
	nvdStartYear       int  // read-only after construction
	approvalPath       string
	approvalPin        string
	approvalConfigured bool

	// ready is true once an initial database revision is available to serve.
	// /health returns HTTP 200 in both states; the JSON body distinguishes
	// "initializing" from "healthy" so orchestrators using a simple curl -f
	// healthcheck pass immediately while clients can still detect readiness.
	ready atomic.Bool
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
		verbose:      verbose,
		nvdStartYear: nvdStartYear,
	}
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
			lastBuild := s.lastBuildAttempt
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
	if _, err := io.Copy(destFile, sourceFile); err != nil {
		destFile.Close()
		return err
	}
	if err := destFile.Sync(); err != nil {
		destFile.Close()
		return err
	}
	return destFile.Close()
}

// handleLegacy retires every legacy metadata/download body without altering
// artifacts on disk. Until v3 validates, report unavailability explicitly.
func (s *DBServer) handleLegacy(w http.ResponseWriter, r *http.Request) {
	if s.ready.Load() {
		http.Error(w, "legacy database distribution retired; use /dbs/v3/latest", http.StatusGone)
		return
	}
	http.Error(w, "validated v3 release unavailable", http.StatusServiceUnavailable)
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
	fmt.Fprintf(w, "  Legacy v1/v2 metadata and downloads return 410 once v3 is ready\n")
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
	lastAttempt, lastError := s.lastBuildAttempt, s.lastBuildError
	s.mu.RUnlock()

	status := "initializing"
	if s.ready.Load() {
		status = "healthy"
	}

	health := map[string]any{
		"status":             status,
		"current_version":    currentVersion,
		"layout":             Layout,
		"last_build_attempt": lastAttempt,
		"last_build_error":   lastError,
		"timestamp":          time.Now().UTC().Format(time.RFC3339),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(health)
}
