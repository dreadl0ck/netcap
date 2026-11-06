package webui

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"sync"

	"github.com/dreadl0ck/netcap/internal/rules"
)

// Shared by evaluation, reanalysis and alert clearing before any output mutation.
var offlineOutputLeases sync.Map

func leaseOfflineOutput(directory string) (func(), bool) {
	key, err := filepath.Abs(directory)
	if err != nil {
		return nil, false
	}
	if _, loaded := offlineOutputLeases.LoadOrStore(key, struct{}{}); loaded {
		return nil, false
	}
	return func() { offlineOutputLeases.Delete(key) }, true
}

func leaseOfflineMutation(directory string) (func(), bool) {
	release, ok := leaseOfflineOutput(directory)
	if !ok {
		return nil, false
	}
	lease, err := rules.AcquireOfflineLease(directory)
	if err != nil {
		if os.IsNotExist(err) {
			return release, true
		}
		release()
		return nil, false
	}
	return func() { _ = lease.Close(); release() }, true
}

type offlinePackRequest struct {
	YAML      string `json:"yaml"`
	InputFile string `json:"inputFile,omitempty"`
	SessionID string `json:"sessionId,omitempty"`
}

func decodeOfflineRequest(w http.ResponseWriter, r *http.Request) (*offlinePackRequest, bool) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return nil, false
	}
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20))
	decoder.DisallowUnknownFields()
	var request offlinePackRequest
	err := decoder.Decode(&request)
	if err == nil {
		var extra any
		if decoder.Decode(&extra) != io.EOF {
			err = fmt.Errorf("expected one JSON object")
		}
	}
	if err != nil {
		RespondJSON(w, http.StatusBadRequest, map[string]any{"valid": false, "errors": []any{map[string]string{"field": "request", "message": err.Error()}}})
		return nil, false
	}
	return &request, true
}

func parseOfflineRequest(w http.ResponseWriter, request *offlinePackRequest) (*rules.OfflinePack, bool) {
	pack, err := rules.ParseOfflinePack([]byte(request.YAML))
	if err != nil {
		RespondJSON(w, http.StatusBadRequest, map[string]any{"valid": false, "errors": []any{map[string]string{"field": "yaml", "message": err.Error()}}})
		return nil, false
	}
	return pack, true
}

func (s *Server) handleOfflineValidate(w http.ResponseWriter, r *http.Request) {
	request, ok := decodeOfflineRequest(w, r)
	if !ok {
		return
	}
	pack, ok := parseOfflineRequest(w, request)
	if !ok {
		return
	}
	RespondJSON(w, http.StatusOK, map[string]any{"valid": true, "errors": []any{}, "pack": pack})
}

// Explicit unknown selectors never fall back to the globally selected capture.
func (s *Server) offlineDirectory(r *http.Request, input, sessionID string) (string, int, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.isServiceMode {
		if input != "" {
			return "", http.StatusBadRequest, fmt.Errorf("Use a sessionId selector in service mode")
		}
		if sessionID == "" {
			sessionID = s.currentSession
		}
		if s.sessionManager == nil {
			return "", 503, fmt.Errorf("No session selected")
		}
		session, ok := s.sessionManager.GetSession(sessionID)
		if !ok {
			return "", 404, fmt.Errorf("Session not found")
		}
		if !session.IsPreloaded && session.IP != s.getUserIP(r) {
			return "", 403, fmt.Errorf("Access denied")
		}
		if session.Status != StatusCompleted {
			return "", 409, fmt.Errorf("Capture must be completed before offline evaluation")
		}
		return session.OutputDir, 0, nil
	}
	if sessionID != "" {
		return "", 404, fmt.Errorf("Session not found")
	}
	if input == "" {
		input = s.activeInputFile
	}
	if input == "" && len(s.inputFiles) == 1 {
		input = s.inputFiles[0]
	}
	if input != "" && !slices.Contains(s.inputFiles, input) {
		return "", 404, fmt.Errorf("Input file not found in list")
	}
	if s.isLiveMode || (input != "" && !s.completedFiles[input]) || (input == "" && s.isProcessing) {
		return "", 409, fmt.Errorf("Capture must be completed before offline evaluation")
	}
	dir := s.outDir
	if input != "" {
		if selected := s.fileOutputDirs[input]; selected != "" {
			dir = selected
		} else if len(s.inputFiles) == 1 {
			dir = s.baseOutDir
		} else {
			return "", 409, fmt.Errorf("Capture output is unavailable")
		}
	}
	if dir == "" {
		return "", 503, fmt.Errorf("No output directory selected")
	}
	return dir, 0, nil
}

func (s *Server) handleOfflineExecute(w http.ResponseWriter, r *http.Request) {
	request, ok := decodeOfflineRequest(w, r)
	if !ok {
		return
	}
	pack, ok := parseOfflineRequest(w, request)
	if !ok {
		return
	}
	s.mu.RLock()
	if request.SessionID == "" && s.isServiceMode {
		request.SessionID = s.currentSession
	}
	if request.InputFile == "" && !s.isServiceMode {
		request.InputFile = s.activeInputFile
		if request.InputFile == "" && len(s.inputFiles) == 1 {
			request.InputFile = s.inputFiles[0]
		}
	}
	s.mu.RUnlock()
	dir, status, err := s.offlineDirectory(r, request.InputFile, request.SessionID)
	if err != nil {
		RespondJSON(w, status, map[string]any{"error": err.Error()})
		return
	}
	release, ok := leaseOfflineOutput(dir)
	if !ok {
		RespondJSON(w, 409, map[string]any{"error": "Capture output is busy"})
		return
	}
	defer release()
	// Recheck completion after acquiring the lease: reanalysis may have queued work.
	confirmedDir, status, err := s.offlineDirectory(r, request.InputFile, request.SessionID)
	if err != nil {
		RespondJSON(w, status, map[string]any{"error": err.Error()})
		return
	}
	if confirmedDir != dir {
		RespondJSON(w, http.StatusConflict, map[string]any{"error": "Capture selection changed before evaluation"})
		return
	}
	report, err := rules.EvaluateOffline(r.Context(), rules.OfflineRequest{Directory: dir, Pack: pack, Limits: rules.OfflineLimits{}})
	if err != nil {
		status := http.StatusUnprocessableEntity
		if errors.Is(err, os.ErrExist) {
			status = http.StatusConflict
		}
		RespondJSON(w, status, map[string]any{"error": err.Error(), "report": report})
		return
	}
	RespondJSON(w, http.StatusOK, map[string]any{"report": report})
}

func (s *Server) handleOfflineEvaluations(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", 405)
		return
	}
	dir, status, err := s.offlineDirectory(r, r.URL.Query().Get("inputFile"), r.URL.Query().Get("sessionId"))
	if err != nil {
		RespondJSON(w, status, map[string]any{"error": err.Error()})
		return
	}
	reports, err := rules.ListOfflineEvaluations(dir)
	if err != nil {
		RespondJSON(w, 500, map[string]any{"error": err.Error()})
		return
	}
	if reports == nil {
		reports = []rules.OfflineReport{}
	}
	RespondJSON(w, 200, map[string]any{"evaluations": reports})
}

func (s *Server) handleOfflinePacks(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", 405)
		return
	}
	RespondJSON(w, 200, map[string]any{"format": "netcap-offline-rules/v1", "packs": []any{map[string]string{"name": "Disabled TCP example", "yaml": offlineExampleYAML}}, "upload": true, "limits": rules.DefaultOfflineLimits()})
}

const offlineExampleYAML = `format: netcap-offline-rules/v1
rules:
  - id: example.tcp.https
    name: Repeated HTTPS connections
    type: TCP
    expression: DstPort == 443
    enabled: false
    severity: low
    threshold:
      count: 10
      window: 60s
      group_by: [SrcIP]
`
