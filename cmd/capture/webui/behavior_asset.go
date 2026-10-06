package webui

import (
	"net/http"
	"path/filepath"

	"github.com/dreadl0ck/netcap/internal/behavior"
)

func (s *Server) handleBehaviorAsset(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	dir, ok := s.behaviorDirectory(w, r)
	if !ok {
		return
	}
	var state behavior.Snapshot
	if engine := s.activeBehavior(dir); engine != nil {
		state = engine.Snapshot()
	} else {
		var err error
		state, err = behavior.ReadSnapshot(filepath.Join(dir, "Behavior.json"))
		if err != nil {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
	}
	context, err := behavior.BuildAssetContext(state, r.URL.Query().Get("asset"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	RespondJSON(w, http.StatusOK, context)
}
