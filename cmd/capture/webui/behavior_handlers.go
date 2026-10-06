package webui

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"

	"github.com/dreadl0ck/netcap/internal/behavior"
	"github.com/dreadl0ck/netcap/internal/rules"
)

func (s *Server) activeBehavior(dir string) *behavior.Engine {
	s.mu.RLock()
	provider, ok := s.collector.(interface{ BehaviorForOutput(string) *behavior.Engine })
	s.mu.RUnlock()
	if !ok {
		return nil
	}
	return provider.BehaviorForOutput(dir)
}

func (s *Server) behaviorDirectory(w http.ResponseWriter, r *http.Request) (string, bool) {
	// Do not let an invalid explicit selector silently mutate the active session.
	if id := r.URL.Query().Get("sessionId"); id != "" {
		if !s.isServiceMode || s.sessionManager == nil {
			http.Error(w, "unknown session", http.StatusNotFound)
			return "", false
		}
		if _, ok := s.sessionManager.GetSession(id); !ok {
			http.Error(w, "unknown session", http.StatusNotFound)
			return "", false
		}
	}
	if input := r.URL.Query().Get("inputFile"); input != "" {
		s.mu.RLock()
		known := false
		for _, file := range s.inputFiles {
			if file == input {
				known = true
				break
			}
		}
		s.mu.RUnlock()
		if !known {
			http.Error(w, "unknown input file", http.StatusNotFound)
			return "", false
		}
	}
	dir, ok := s.resolveOutDirFromRequest(r)
	if !ok {
		http.Error(w, "no capture selected", http.StatusServiceUnavailable)
	}
	return dir, ok
}

func (s *Server) handleBehavior(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	dir, ok := s.behaviorDirectory(w, r)
	if !ok {
		return
	}
	if engine := s.activeBehavior(dir); engine != nil {
		RespondJSON(w, http.StatusOK, engine.Snapshot())
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
	RespondJSON(w, http.StatusOK, state)
}

func (s *Server) handleBehaviorChange(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	dir, ok := s.behaviorDirectory(w, r)
	if !ok {
		return
	}
	var request struct {
		Action    string                  `json:"action"`
		IDs       []string                `json:"ids"`
		Reason    string                  `json:"reason"`
		Version   *uint64                 `json:"version"`
		Inventory *behavior.InventoryEdit `json:"inventory,omitempty"`
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if request.Version == nil {
		http.Error(w, "baseline version is required", http.StatusBadRequest)
		return
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		http.Error(w, "expected one JSON object", http.StatusBadRequest)
		return
	}
	engine := s.activeBehavior(dir)
	finish := func() error { return nil }
	if engine == nil {
		path := filepath.Join(dir, "Behavior.json")
		state, err := behavior.ReadSnapshot(path)
		if err != nil {
			http.Error(w, err.Error(), http.StatusConflict)
			return
		}
		sink, err := rules.NewFileAlertWriter(dir)
		if err != nil {
			http.Error(w, err.Error(), http.StatusConflict)
			return
		}
		engine, err = behavior.Open(behavior.Config{Path: path, MaxFacts: state.MaxFacts}, sink)
		if err != nil {
			http.Error(w, errors.Join(err, sink.Close()).Error(), http.StatusConflict)
			return
		}
		finish = func() error { return errors.Join(engine.Close(), sink.Close()) }
		defer finish()
	}
	var changeErr error
	if request.Action == "inventory" && request.Inventory != nil {
		request.Inventory.Version, request.Inventory.Reason = *request.Version, request.Reason
		changeErr = engine.EditInventory(*request.Inventory)
	} else {
		changeErr = engine.ChangeAtVersion(request.Action, request.IDs, request.Reason, *request.Version)
	}
	if err := changeErr; err != nil {
		http.Error(w, errors.Join(err, finish()).Error(), http.StatusConflict)
		return
	}
	state := engine.Snapshot()
	if err := finish(); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	RespondJSON(w, http.StatusOK, state)
}
