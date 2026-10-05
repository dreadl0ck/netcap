//go:build !appstore

package webui

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/dreadl0ck/netcap/internal/resolvers"
)

func (s *Server) geoProviderSelection() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.geoProvidersOverride != "" {
		return s.geoProvidersOverride
	}
	raw := ""
	if s.runtimeConfig != nil {
		raw = s.runtimeConfig.GeoProviders
	}
	order, err := resolvers.GeoProviderOrder(raw)
	if err != nil {
		return raw
	}
	return strings.Join(order, ",")
}

func (s *Server) handleGeoProviders(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		var settings struct {
			Providers string `json:"providers"`
		}
		r.Body = http.MaxBytesReader(w, r.Body, 1024)
		if err := json.NewDecoder(r.Body).Decode(&settings); err != nil {
			http.Error(w, "Invalid provider settings", http.StatusBadRequest)
			return
		}
		order, err := resolvers.ParseGeoProviders(settings.Providers)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		raw := strings.Join(order, ",")
		s.mu.Lock()
		err = resolvers.SaveGeoProviderOrder(raw)
		if err == nil {
			s.geoProvidersOverride = raw
		}
		s.mu.Unlock()
		if err != nil {
			http.Error(w, "Failed to save provider settings", http.StatusInternalServerError)
			return
		}
	} else if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	respondDatabaseJSON(w, currentDatabaseStatus(s.geoProviderSelection()))
}
