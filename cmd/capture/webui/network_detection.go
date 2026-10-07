package webui

import (
	"errors"
	"net/http"
	"os"
	"path/filepath"

	"github.com/dreadl0ck/netcap/internal/networkdetect"
)

const NetworkDetectionSnapshotName = networkdetect.StatsFilename

func ValidateNetworkDetectionSnapshot(path string) error {
	_, err := networkdetect.ReadStats(path)
	return err
}

func (s *Server) handleNetworkDetection(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	dir, ok := s.behaviorDirectory(w, r)
	if !ok {
		return
	}
	s.mu.RLock()
	provider, active := s.collector.(interface {
		NetworkDetectionForOutput(string) (networkdetect.Stats, bool)
	})
	s.mu.RUnlock()
	if active {
		if stats, ok := provider.NetworkDetectionForOutput(dir); ok {
			RespondJSON(w, http.StatusOK, struct {
				networkdetect.Stats
				Active bool `json:"active"`
			}{stats, true})
			return
		}
	}
	stats, err := networkdetect.ReadStats(filepath.Join(dir, networkdetect.StatsFilename))
	if err != nil {
		status := http.StatusInternalServerError
		if errors.Is(err, os.ErrNotExist) {
			status = http.StatusNotFound
		}
		http.Error(w, err.Error(), status)
		return
	}
	RespondJSON(w, http.StatusOK, struct {
		networkdetect.Stats
		Active bool `json:"active"`
	}{stats, false})
}
