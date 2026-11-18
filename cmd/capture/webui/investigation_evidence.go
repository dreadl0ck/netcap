package webui

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/dreadl0ck/netcap/internal/artifactio"
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
	if fields := r.URL.Query().Get("fields"); fields != "" {
		raw, _ := json.Marshal(manifest)
		projected, err := projectRecordJSON(raw, fields)
		if err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		w.Write(projected)
		return
	}
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

var streamInventorySlots = make(chan struct{}, 2)

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
		select {
		case streamInventorySlots <- struct{}{}:
			defer func() { <-streamInventorySlots }()
		default:
			http.Error(w, "stream inventory is busy", http.StatusTooManyRequests)
			return
		}
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
		const manifestLimit = 16 << 20
		remaining := int64(32 << 20)
		for _, entry := range entries {
			if !entry.IsDir() || !strings.HasPrefix(entry.Name(), "stream-") {
				continue
			}
			var summary struct {
				streamutils.StreamEvidenceManifest
				Spans []struct{} `json:"spans"`
			}
			data, err := artifactio.Read(r.Context(), out, filepath.Join("stream-evidence", entry.Name(), "manifest.json"), min(manifestLimit, remaining))
			if err == nil {
				remaining -= int64(len(data))
				err = json.Unmarshal(data, &summary)
			}
			if err != nil {
				http.Error(w, "Incomplete stream evidence: "+err.Error()+"; request an individual stream by ID", http.StatusUnprocessableEntity)
				return
			}
			rows = append(rows, row{entry.Name(), summary.StreamEvidenceManifest, len(summary.Spans), true})
		}
		sort.Slice(rows, func(i, j int) bool {
			a, b := rows[i].Manifest, rows[j].Manifest
			ta, ea := strconv.ParseInt(a.FirstPacketNs, 10, 64)
			tb, eb := strconv.ParseInt(b.FirstPacketNs, 10, 64)
			if ea == nil && eb == nil && ta != tb {
				return ta < tb
			}
			if (ea == nil) != (eb == nil) {
				return ea == nil
			}
			ka := strings.Join([]string{a.FirstPacketNs, a.Protocol, a.ConnectionKey, a.CommunityID, a.Client.SHA256, a.Server.SHA256}, "\x00")
			kb := strings.Join([]string{b.FirstPacketNs, b.Protocol, b.ConnectionKey, b.CommunityID, b.Client.SHA256, b.Server.SHA256}, "\x00")
			if ka != kb {
				return ka < kb
			}
			return rows[i].ID < rows[j].ID
		})
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
	f, info, err := artifactio.Open(out, filepath.Join("stream-evidence", id, filename))
	if errors.Is(err, artifactio.ErrPath) {
		http.Error(w, "Invalid stream path", http.StatusBadRequest)
		return
	}
	if err != nil {
		http.Error(w, "Stream bytes unavailable", http.StatusNotFound)
		return
	}
	defer f.Close()
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s-%s"`, id, filename))
	w.Header().Set("Cache-Control", "no-store")
	http.ServeContent(w, r, filename, info.ModTime(), f)
}
