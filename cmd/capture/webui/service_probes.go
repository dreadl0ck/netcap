//go:build !appstore

package webui

import (
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"

	"github.com/dreadl0ck/netcap/internal/resolvers"
	"github.com/dreadl0ck/netcap/internal/servicesignatures"
)

func retiredServiceProbes(w http.ResponseWriter, _ *http.Request) {
	http.Error(w, "Legacy service probes are retired; use GET /api/service-signatures", http.StatusGone)
}

func (s *Server) handleServiceProbes(w http.ResponseWriter, r *http.Request) {
	retiredServiceProbes(w, r)
}
func (s *Server) handleServiceProbeRouter(w http.ResponseWriter, r *http.Request) {
	retiredServiceProbes(w, r)
}
func (s *Server) handleTestServiceProbe(w http.ResponseWriter, r *http.Request) {
	retiredServiceProbes(w, r)
}
func (s *Server) handleExportServiceProbes(w http.ResponseWriter, r *http.Request) {
	retiredServiceProbes(w, r)
}
func (s *Server) handleImportServiceProbes(w http.ResponseWriter, r *http.Request) {
	retiredServiceProbes(w, r)
}

func (s *Server) handleServiceSignatures(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Read-only catalogue", http.StatusMethodNotAllowed)
		return
	}
	e, err := servicesignatures.Load(filepath.Join(resolvers.DataBaseFolderPath, servicesignatures.FileName))
	w.Header().Set("Content-Type", "application/json")
	response := map[string]any{"catalogue": e.Catalogue(), "inventory": e.Inventory("catalogue-on-disk", err), "source": "external", "degraded": err != nil}
	if err != nil {
		response["warning"] = err.Error()
		response["source"] = "builtin"
	}
	_ = json.NewEncoder(w).Encode(response)
}

func (s *Server) handleServiceSignatureStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Read-only capture diagnostics", http.StatusMethodNotAllowed)
		return
	}
	dir, ok := s.behaviorDirectory(w, r)
	if !ok {
		return
	}
	i, err := servicesignatures.ReadInventory(filepath.Join(dir, servicesignatures.InventoryFileName))
	if errors.Is(err, os.ErrNotExist) {
		RespondJSON(w, http.StatusOK, servicesignatures.UnavailableInventory("not-recorded", "This capture has no recorded service signature inventory; its source and coverage are unknown"))
		return
	}
	if err != nil {
		http.Error(w, "Invalid recorded service signature inventory: "+err.Error(), http.StatusInternalServerError)
		return
	}
	RespondJSON(w, http.StatusOK, i)
}
