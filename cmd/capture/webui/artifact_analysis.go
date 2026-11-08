package webui

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"

	"github.com/dreadl0ck/netcap/internal/artifactio"
	"github.com/dreadl0ck/netcap/internal/decoder/stream/file"
)

func (s *Server) handleArtifactAnalysis(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", 405)
		return
	}
	dir, ok := s.artifactDirectory(w, r)
	if !ok {
		return
	}
	b, err := artifactio.Read(r.Context(), filepath.Dir(dir), file.AnalysisReportFile, 16<<20)
	if os.IsNotExist(err) {
		RespondJSON(w, 404, map[string]any{"state": "unavailable", "error": "No artifact analysis report; legacy or active capture"})
		return
	}
	if err != nil {
		RespondJSON(w, 500, map[string]any{"state": "failed", "error": "Cannot read artifact analysis report"})
		return
	}
	var report file.AnalysisReport
	if err := json.Unmarshal(b, &report); err != nil || report.Version != 1 || report.RunID == "" {
		RespondJSON(w, 500, map[string]any{"state": "failed", "error": "Invalid artifact analysis report"})
		return
	}
	RespondJSON(w, 200, report)
}
