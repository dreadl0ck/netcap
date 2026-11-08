package webui

import (
	"errors"
	"github.com/dreadl0ck/netcap/internal/artifactio"
	"net/http"
	"os"
	"path/filepath"
)

func (s *Server) artifactDirectory(w http.ResponseWriter, r *http.Request) (string, bool) {
	selected, ok := s.selectedCapture(w, r)
	if !ok {
		return "", false
	}
	return filepath.Join(selected.OutputDir, "files"), true
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
