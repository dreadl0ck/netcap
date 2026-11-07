package webui

import (
	"context"
	"crypto/subtle"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/dreadl0ck/netcap/internal/evidence"
)

type captureSelection struct {
	AnalysisID string
	SessionID  string
	InputFile  string
	OutputDir  string
	RunID      string
}

type captureSelectionKey struct{}

type captureSelectionError struct {
	Status int
	Reason string
}

func (e *captureSelectionError) Error() string { return e.Reason }

func selectionError(status int, reason string) error {
	return &captureSelectionError{Status: status, Reason: reason}
}

// Resolve once per HTTP request so concurrent active-capture changes cannot mix sources.
func (s *Server) captureSelectionMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/") {
			selection, err := s.resolveCaptureSelection(r)
			q := r.URL.Query()
			explicit := q.Has("sessionId") || q.Has("inputFile") || q.Has("runId")
			if err != nil && explicit {
				writeSelectionError(w, err)
				return
			}
			if err == nil {
				r = r.WithContext(context.WithValue(r.Context(), captureSelectionKey{}, selection))
			}
		}
		next.ServeHTTP(w, r)
	})
}

func writeSelectionError(w http.ResponseWriter, err error) {
	if typed, ok := err.(*captureSelectionError); ok {
		http.Error(w, typed.Reason, typed.Status)
		return
	}
	http.Error(w, "Capture selection failed", http.StatusInternalServerError)
}

func (s *Server) resolveCaptureSelection(r *http.Request) (captureSelection, error) {
	if selected, ok := r.Context().Value(captureSelectionKey{}).(captureSelection); ok {
		return selected, nil
	}
	q := r.URL.Query()
	for _, field := range []string{"sessionId", "inputFile", "runId"} {
		if values, present := q[field]; present && (len(values) != 1 || strings.TrimSpace(values[0]) == "") {
			return captureSelection{}, selectionError(400, "Invalid or duplicate "+field)
		}
	}
	sid, input := q.Get("sessionId"), q.Get("inputFile")
	if scope := q.Get("scope"); scope != "" && scope != "current" && (sid != "" || input != "" || q.Has("runId")) {
		return captureSelection{}, selectionError(409, "Scope conflicts with explicit capture selection")
	}
	s.mu.RLock()
	service, manager := s.isServiceMode, s.sessionManager
	activeSession, activeInput, activeOutput := s.currentSession, s.activeInputFile, s.outDir
	s.mu.RUnlock()
	var selected captureSelection
	if service {
		if sid == "" {
			if input != "" {
				return selected, selectionError(400, "Service capture selection requires sessionId")
			}
			sid = activeSession
		}
		if manager == nil || sid == "" {
			return selected, selectionError(503, "No analysis selected")
		}
		manager.mu.RLock()
		session, exists := manager.sessions[sid]
		if exists {
			selected = captureSelection{AnalysisID: sid, SessionID: sid, InputFile: session.InputFile, OutputDir: session.OutputDir}
			if !session.IsPreloaded && session.IP != s.getUserIP(r) && !captureAdminAuthorized(r) {
				manager.mu.RUnlock()
				return captureSelection{}, selectionError(403, "Access denied")
			}
		}
		manager.mu.RUnlock()
		if !exists {
			return selected, selectionError(404, "Unknown capture session")
		}
		if input != "" && input != selected.InputFile {
			return captureSelection{}, selectionError(409, "Input file conflicts with session")
		}
	} else {
		s.mu.RLock()
		defer s.mu.RUnlock()
		if sid != "" {
			path, exists := s.fileIDToPath[sid]
			if !exists {
				return selected, selectionError(404, "Unknown analysis ID")
			}
			if input != "" && input != path {
				return selected, selectionError(409, "Input file conflicts with analysis ID")
			}
			input = path
			selected.AnalysisID = sid
		}
		if input != "" {
			if !slices.Contains(s.inputFiles, input) {
				if _, exists := s.fileOutputDirs[input]; !exists {
					return selected, selectionError(404, "Unknown capture input")
				}
			}
			selected.InputFile = input
			selected.OutputDir = s.outDirForKnownInputLocked(input)
			if child, exists := s.childAnalyses[input]; exists {
				selected.AnalysisID = child.AnalysisID
			}
		} else {
			selected.InputFile, selected.OutputDir = activeInput, activeOutput
		}
	}
	if selected.OutputDir == "" && selected.InputFile == "" {
		return selected, selectionError(503, "No analysis selected")
	}
	if expected := q.Get("runId"); expected != "" {
		var manifest evidence.CaptureManifest
		if err := readEvidenceJSON(filepath.Join(selected.OutputDir, "capture-manifest.json"), &manifest); err != nil || manifest.RunID == "" || manifest.RunID != expected {
			return captureSelection{}, selectionError(409, "Capture generation is unavailable or stale")
		}
		selected.RunID = manifest.RunID
	}
	return selected, nil
}

func captureAdminAuthorized(r *http.Request) bool {
	token := os.Getenv(EnvMCPAdminToken)
	return token != "" && subtle.ConstantTimeCompare([]byte(r.Header.Get("Authorization")), []byte("Bearer "+token)) == 1
}

func (s *Server) outDirForKnownInputLocked(input string) string {
	if dir := s.fileOutputDirs[input]; dir != "" {
		return dir
	}
	if len(s.inputFiles) == 1 {
		return s.baseOutDir
	}
	base := filepath.Base(input)
	for _, ext := range []string{".pcap", ".pcapng", ".cap", ".dmp"} {
		if before, ok := strings.CutSuffix(base, ext); ok {
			base = before
			break
		}
	}
	if s.baseOutDir == "" {
		return ""
	}
	return filepath.Join(s.baseOutDir, base)
}

func (s *Server) resolveOutDirFromRequest(r *http.Request) (string, bool) {
	selected, err := s.resolveCaptureSelection(r)
	if err != nil {
		return "", false
	}
	return selected.OutputDir, err == nil && selected.OutputDir != ""
}

func (s *Server) resolveInputFileFromRequest(r *http.Request) (string, bool) {
	selected, err := s.resolveCaptureSelection(r)
	if err != nil {
		return "", false
	}
	return selected.InputFile, err == nil && selected.InputFile != ""
}

func (s *Server) selectedCapture(w http.ResponseWriter, r *http.Request) (captureSelection, bool) {
	selected, err := s.resolveCaptureSelection(r)
	if err != nil {
		writeSelectionError(w, err)
		return captureSelection{}, false
	}
	if selected.OutputDir == "" {
		writeSelectionError(w, selectionError(503, "No output directory selected"))
		return captureSelection{}, false
	}
	return selected, true
}

func (s *Server) resolveBodyCapture(r *http.Request, input, session, run string) (captureSelection, error) {
	cloned := r.Clone(context.WithValue(r.Context(), captureSelectionKey{}, nil))
	q := cloned.URL.Query()
	for field, value := range map[string]string{"inputFile": input, "sessionId": session, "runId": run} {
		if value == "" {
			continue
		}
		if q.Has(field) && (len(q[field]) != 1 || q.Get(field) != value) {
			return captureSelection{}, selectionError(409, "Request body conflicts with query "+field)
		}
		q.Set(field, value)
	}
	cloned.URL.RawQuery = q.Encode()
	return s.resolveCaptureSelection(cloned)
}
