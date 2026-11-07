package webui

import (
	"errors"
	"github.com/dreadl0ck/netcap/internal/artifactio"
	"net/http"
	"os"
	"path/filepath"
	"slices"
)

func (s *Server) artifactDirectory(w http.ResponseWriter, r *http.Request) (string, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	q := r.URL.Query()
	dir := s.outDir
	if s.isServiceMode {
		sid := q.Get("sessionId")
		if sid == "" {
			sid = s.currentSession
		}
		if s.sessionManager == nil {
			http.Error(w, "No session selected", 503)
			return "", false
		}
		session, ok := s.sessionManager.GetSession(sid)
		if !ok || q.Get("inputFile") != "" {
			http.Error(w, "Unknown capture", 404)
			return "", false
		}
		if !session.IsPreloaded && session.IP != s.getUserIP(r) {
			http.Error(w, "Access denied", 403)
			return "", false
		}
		dir = session.OutputDir
	} else {
		if q.Get("sessionId") != "" {
			http.Error(w, "Unknown session", 404)
			return "", false
		}
		if input := q.Get("inputFile"); input != "" {
			if !slices.Contains(s.inputFiles, input) {
				http.Error(w, "Unknown capture", 404)
				return "", false
			}
			dir = s.fileOutputDirs[input]
			if dir == "" && len(s.inputFiles) == 1 {
				dir = s.baseOutDir
			}
		}
	}
	if dir == "" {
		http.Error(w, "No output directory selected", 503)
		return "", false
	}
	return filepath.Join(dir, "files"), true
}
func artifactAccessError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, os.ErrNotExist):
		http.Error(w, "Artifact not found", 404)
	case errors.Is(err, artifactio.ErrPath), errors.Is(err, os.ErrPermission):
		http.Error(w, "Invalid artifact path", 403)
	default:
		http.Error(w, "Artifact access failed", 500)
	}
}
