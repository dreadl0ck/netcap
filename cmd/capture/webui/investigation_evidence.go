package webui

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	streamutils "github.com/dreadl0ck/netcap/internal/decoder/stream/utils"
	"github.com/dreadl0ck/netcap/internal/evidence"
)

func readEvidenceJSON(path string, target any) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, (16<<20)+1))
	if err != nil {
		return err
	}
	if len(data) > 16<<20 {
		return fmt.Errorf("evidence manifest exceeds 16 MiB")
	}
	return json.Unmarshal(data, target)
}

func (s *Server) resolveEvidenceOutput(r *http.Request) (string, bool) {
	q := r.URL.Query()
	if len(q["sessionId"]) > 1 || len(q["inputFile"]) > 1 {
		return "", false
	}
	if id := q.Get("sessionId"); id != "" {
		if s.sessionManager == nil {
			return "", false
		}
		session, ok := s.sessionManager.GetSession(id)
		if !ok {
			return "", false
		}
		return session.OutputDir, session.OutputDir != ""
	}
	if input := q.Get("inputFile"); input != "" {
		s.mu.RLock()
		known := false
		for _, path := range s.inputFiles {
			if path == input {
				known = true
				break
			}
		}
		if _, ok := s.fileOutputDirs[input]; ok {
			known = true
		}
		s.mu.RUnlock()
		if !known {
			return "", false
		}
	}
	return s.resolveOutDirFromRequest(r)
}

func (s *Server) handleCaptureEvidence(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	out, _ := s.resolveEvidenceOutput(r)
	if out == "" {
		http.Error(w, "No analysis selected", http.StatusServiceUnavailable)
		return
	}
	var manifest evidence.CaptureManifest
	if err := readEvidenceJSON(filepath.Join(out, "capture-manifest.json"), &manifest); err != nil {
		http.Error(w, "Capture provenance unavailable: "+err.Error(), http.StatusUnprocessableEntity)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(manifest)
}

func (s *Server) handleInvestigationHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	filename := ""
	switch r.URL.Query().Get("kind") {
	case "ftp":
		filename = "FTPDataHealth.json"
	case "reassembly":
		filename = "TCPReassemblyHealth.json"
	default:
		http.Error(w, "kind must be ftp or reassembly", http.StatusBadRequest)
		return
	}
	out, _ := s.resolveEvidenceOutput(r)
	if out == "" {
		http.Error(w, "No selected analysis", http.StatusServiceUnavailable)
		return
	}
	var value any
	if err := readEvidenceJSON(filepath.Join(out, filename), &value); err != nil {
		http.Error(w, "Investigation health unavailable: "+err.Error(), http.StatusUnprocessableEntity)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(value)
}

func (s *Server) handleStreamEvidence(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	out, _ := s.resolveEvidenceOutput(r)
	if out == "" {
		http.Error(w, "No analysis selected", http.StatusServiceUnavailable)
		return
	}
	root := filepath.Join(out, "stream-evidence")
	id := r.URL.Query().Get("id")
	if id == "" {
		directory, err := os.Open(root)
		if err != nil {
			http.Error(w, "Stream evidence unavailable", http.StatusNotFound)
			return
		}
		defer directory.Close()
		entries, err := directory.ReadDir(1001)
		if err != nil && err != io.EOF {
			http.Error(w, "Failed to read stream evidence", http.StatusInternalServerError)
			return
		}
		if len(entries) > 1000 {
			http.Error(w, "Stream evidence listing exceeds 1000 entries", http.StatusUnprocessableEntity)
			return
		}
		type row struct {
			ID           string                             `json:"id"`
			Manifest     streamutils.StreamEvidenceManifest `json:"manifest"`
			SpanCount    int                                `json:"spanCount"`
			SpansOmitted bool                               `json:"spansOmitted"`
		}
		rows := []row{}
		for _, entry := range entries {
			if !entry.IsDir() || !strings.HasPrefix(entry.Name(), "stream-") {
				continue
			}
			var manifest streamutils.StreamEvidenceManifest
			if err := readEvidenceJSON(filepath.Join(root, entry.Name(), "manifest.json"), &manifest); err != nil {
				http.Error(w, "Incomplete stream evidence: "+err.Error(), http.StatusUnprocessableEntity)
				return
			}
			count := len(manifest.Spans)
			manifest.Spans = nil
			rows = append(rows, row{entry.Name(), manifest, count, true})
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(rows)
		return
	}
	if !strings.HasPrefix(id, "stream-") || filepath.Base(id) != id || strings.ContainsAny(id, "/\\\x00") {
		http.Error(w, "Invalid stream identity", http.StatusBadRequest)
		return
	}
	direction := r.URL.Query().Get("direction")
	if direction != "client" && direction != "server" && direction != "manifest" {
		http.Error(w, "direction must be client, server or manifest", http.StatusBadRequest)
		return
	}
	filename := direction + ".bin"
	if direction == "manifest" {
		filename = "manifest.json"
	}
	path := filepath.Join(root, id, filename)
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		http.Error(w, "Stream bytes unavailable", http.StatusNotFound)
		return
	}
	resolvedRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		http.Error(w, "Stream evidence unavailable", http.StatusNotFound)
		return
	}
	relative, err := filepath.Rel(resolvedRoot, resolved)
	if err != nil || !filepath.IsLocal(relative) {
		http.Error(w, "Invalid stream path", http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s-%s"`, id, filename))
	w.Header().Set("Cache-Control", "no-store")
	http.ServeFile(w, r, resolved)
}
