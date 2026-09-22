//go:build !appstore

package webui

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"

	"github.com/dreadl0ck/netcap/internal/dbs"
)

// handleUpdateDatabases handles database update requests.
func (s *Server) handleUpdateDatabases(w http.ResponseWriter, r *http.Request) {
	log.Printf("[WebUI] handleUpdateDatabases called: method=%s", r.Method)

	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	go func() {
		log.Printf("[WebUI] Starting database download...")
		if err := dbs.DownloadDBs("", true); err != nil {
			log.Printf("[WebUI] Database download failed: %v", err)
		} else {
			log.Printf("[WebUI] Database download completed successfully")
		}
	}()

	response := map[string]any{
		"success": true,
		"message": "Database update started in background. Check logs for progress.",
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(response); err != nil {
		log.Printf("[WebUI] handleUpdateDatabases: failed to encode response: %v", err)
		http.Error(w, fmt.Sprintf("Failed to encode response: %v", err), http.StatusInternalServerError)
		return
	}

	log.Printf("[WebUI] handleUpdateDatabases: response sent successfully")
}
