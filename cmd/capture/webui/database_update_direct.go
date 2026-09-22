//go:build !appstore

package webui

import (
	"log"
	"net/http"
)

// handleUpdateDatabases starts a database download and reports the resulting
// state.
//
// It used to fire a goroutine and answer "Database update started
// successfully" unconditionally, so a download that failed — no network, a
// 404 from the database host — was indistinguishable from one that worked.
// The response now carries the tracker, and the caller polls
// /api/dbs/update/progress for the outcome.
func (s *Server) handleUpdateDatabases(w http.ResponseWriter, r *http.Request) {
	log.Printf("[WebUI] handleUpdateDatabases called: method=%s", r.Method)

	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)

		return
	}

	started := startDatabaseDownload(true)

	message := "Database download started"
	if !started {
		message = "A database download is already running"
	}

	respondDatabaseJSON(w, map[string]any{
		"success":  true,
		"started":  started,
		"message":  message,
		"download": databaseDownloadStatus(),
	})
}
