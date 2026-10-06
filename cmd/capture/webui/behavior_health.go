package webui

import (
	"errors"
	"net/http"
	"os"
	"path/filepath"

	"github.com/dreadl0ck/netcap/internal/behavior"
)

func (s *Server) handleBehaviorHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	dir, ok := s.behaviorDirectory(w, r)
	if !ok {
		return
	}
	if engine := s.activeBehavior(dir); engine != nil {
		s.mu.RLock()
		provider, available := s.collector.(interface{ GetBehaviorHealth(string) behavior.Health })
		s.mu.RUnlock()
		if available {
			if health := provider.GetBehaviorHealth(dir); health.Schema == 1 && s.activeBehavior(dir) == engine {
				RespondJSON(w, http.StatusOK, health)
				return
			}
		}
		RespondJSON(w, http.StatusOK, engine.Health(dir, nil, nil))
		return
	}
	state, err := behavior.ReadSnapshot(filepath.Join(dir, "Behavior.json"))
	if err != nil {
		status := http.StatusInternalServerError
		if errors.Is(err, os.ErrNotExist) {
			status = http.StatusNotFound
		}
		http.Error(w, err.Error(), status)
		return
	}
	health := behavior.BuildHealth(state, filepath.Join(dir, "Behavior.json"), dir, false, nil, nil)
	if stored, err := behavior.ReadHealth(dir); err == nil {
		health.Capture, health.Delivery = stored.Capture, stored.Delivery
		health.SampledAt = stored.SampledAt
		if stored.StorageError != "" {
			health.StorageError = stored.StorageError
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		health.StorageError = err.Error()
	}
	RespondJSON(w, http.StatusOK, health)
}
