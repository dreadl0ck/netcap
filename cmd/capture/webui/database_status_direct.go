//go:build !appstore

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

package webui

import (
	"encoding/json"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/dreadl0ck/netcap/internal/dbs"
	"github.com/dreadl0ck/netcap/internal/resolvers"
)

// DownloadState is the lifecycle of the database download, as opposed to
// dbs.DownloadStage which is the phase within a running one.
type DownloadState string

// Database download lifecycle states.
const (
	DownloadIdle      DownloadState = "idle"
	DownloadRunning   DownloadState = "running"
	DownloadCompleted DownloadState = "completed"
	DownloadFailed    DownloadState = "failed"
)

// MissingDB is one absent database, reported to the UI.
type MissingDB struct {
	File    string `json:"file"`
	Feature string `json:"feature"`
}

// DatabaseDownloadStatus is the observable state of the database download.
type DatabaseDownloadStatus struct {
	State      DownloadState     `json:"state"`
	Stage      dbs.DownloadStage `json:"stage,omitempty"`
	Version    string            `json:"version,omitempty"`
	Downloaded int64             `json:"downloaded"`
	Total      int64             `json:"total"`
	Percent    float64           `json:"percent"`
	Message    string            `json:"message,omitempty"`
	Error      string            `json:"error,omitempty"`
	StartedAt  int64             `json:"startedAt,omitempty"`
	FinishedAt int64             `json:"finishedAt,omitempty"`
}

// DatabaseStatus answers "can this install analyse a capture at full fidelity,
// and if not, what is missing and is a fix already running".
type DatabaseStatus struct {
	// Satisfied is true when no required database is absent.
	Satisfied bool `json:"satisfied"`
	// Missing lists the absent required databases.
	Missing []MissingDB `json:"missing"`
	// DatabaseDir is the resolved location, so a support request can name a
	// real path instead of "~/.config/netcap/dbs" which is wrong on Windows.
	DatabaseDir string `json:"databaseDir"`
	// Download is the state of any download that has been started.
	Download DatabaseDownloadStatus `json:"download"`
}

// dbDownload is the process-wide database download tracker. One webui server
// runs per process, so a package singleton is the whole scope.
var dbDownload = struct {
	mu     sync.Mutex
	status DatabaseDownloadStatus
}{
	status: DatabaseDownloadStatus{State: DownloadIdle},
}

func databaseDownloadStatus() DatabaseDownloadStatus {
	dbDownload.mu.Lock()
	defer dbDownload.mu.Unlock()

	return dbDownload.status
}

// beginDatabaseDownload claims the tracker. It returns false when a download
// is already running, which is what makes POST /api/dbs/update idempotent: a
// double click, or a retry from a second window, must not start a second
// 91 MB transfer into the same destination.
func beginDatabaseDownload() bool {
	dbDownload.mu.Lock()
	defer dbDownload.mu.Unlock()

	if dbDownload.status.State == DownloadRunning {
		return false
	}

	dbDownload.status = DatabaseDownloadStatus{
		State:     DownloadRunning,
		Stage:     dbs.StageMetadata,
		Message:   "Starting database download",
		StartedAt: time.Now().Unix(),
	}

	return true
}

func updateDatabaseDownload(p dbs.DownloadProgress) {
	dbDownload.mu.Lock()
	defer dbDownload.mu.Unlock()

	if dbDownload.status.State != DownloadRunning {
		return
	}

	dbDownload.status.Stage = p.Stage
	dbDownload.status.Downloaded = p.Downloaded
	dbDownload.status.Total = p.Total
	dbDownload.status.Percent = p.Percent
	dbDownload.status.Message = p.Message

	if p.Version != "" {
		dbDownload.status.Version = p.Version
	}
}

func finishDatabaseDownload(err error) {
	dbDownload.mu.Lock()
	defer dbDownload.mu.Unlock()

	dbDownload.status.FinishedAt = time.Now().Unix()

	if err != nil {
		dbDownload.status.State = DownloadFailed
		dbDownload.status.Error = err.Error()
		dbDownload.status.Message = "Database download failed"

		return
	}

	dbDownload.status.State = DownloadCompleted
	dbDownload.status.Stage = dbs.StageCompleted
	dbDownload.status.Percent = 100
	dbDownload.status.Message = "Databases installed"
}

func currentDatabaseStatus() DatabaseStatus {
	missing := make([]MissingDB, 0)
	for _, db := range dbs.MissingRequiredDBs() {
		missing = append(missing, MissingDB{File: db.File, Feature: db.Feature})
	}

	return DatabaseStatus{
		Satisfied:   len(missing) == 0,
		Missing:     missing,
		DatabaseDir: resolvers.DataBaseFolderPath,
		Download:    databaseDownloadStatus(),
	}
}

// handleDatabaseStatus reports which required databases are missing and how
// any in-flight download is progressing.
func (s *Server) handleDatabaseStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)

		return
	}

	respondDatabaseJSON(w, currentDatabaseStatus())
}

// handleDatabaseDownloadProgress reports only the download half, for polling
// while a download runs.
func (s *Server) handleDatabaseDownloadProgress(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)

		return
	}

	respondDatabaseJSON(w, databaseDownloadStatus())
}

// startDatabaseDownload kicks off the download in the background and reports
// whether this call was the one that started it.
func startDatabaseDownload(force bool) bool {
	if !beginDatabaseDownload() {
		log.Printf("[WebUI] Database download already running, ignoring duplicate request")

		return false
	}

	go func() {
		log.Printf("[WebUI] Starting database download...")

		err := dbs.DownloadDBsWithProgress("", force, updateDatabaseDownload)
		finishDatabaseDownload(err)

		if err != nil {
			log.Printf("[WebUI] Database download failed: %v", err)

			return
		}

		log.Printf("[WebUI] Database download completed successfully")
	}()

	return true
}

func respondDatabaseJSON(w http.ResponseWriter, payload any) {
	w.Header().Set("Content-Type", "application/json")

	if err := json.NewEncoder(w).Encode(payload); err != nil {
		log.Printf("[WebUI] Failed to encode database response: %v", err)
		http.Error(w, "Failed to encode response", http.StatusInternalServerError)
	}
}
