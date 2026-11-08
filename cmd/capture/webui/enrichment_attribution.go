package webui

import (
	"crypto/ed25519"
	"encoding/json"
	"net/http"
	"os"
	"time"

	"github.com/dreadl0ck/netcap/internal/enrichment"
	"github.com/dreadl0ck/netcap/internal/resolvers"
	"github.com/dreadl0ck/netcap/internal/servicesignatures"
	"github.com/dreadl0ck/netcap/internal/webtech"
)

type catalogueAttribution struct {
	State            string              `json:"state"`
	Webtech          webtech.Attribution `json:"webtech"`
	Services         json.RawMessage     `json:"services"`
	InstalledNotices string              `json:"installed_notices,omitempty"`
	InstalledSources json.RawMessage     `json:"installed_sources,omitempty"`
}

func readCatalogueAttribution(root string, trust ed25519.PublicKey, now time.Time) catalogueAttribution {
	result := catalogueAttribution{State: "unavailable", Webtech: webtech.ResourceAttribution(), Services: servicesignatures.ResourceAttribution()}
	members, err := enrichment.Open(root, trust, now)
	if err != nil {
		if !os.IsNotExist(err) {
			result.State = "invalid-or-stale"
		}
		return result
	}
	result.State = "verified-installed"
	result.InstalledNotices = string(members[enrichment.NoticesName])
	result.InstalledSources = append([]byte{}, members[enrichment.SourcesName]...)
	return result
}

func (s *Server) handleEnrichmentAttribution(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	trust, err := catalogueSigningRoot()
	result := catalogueAttribution{State: "unavailable", Webtech: webtech.ResourceAttribution(), Services: servicesignatures.ResourceAttribution()}
	if err == nil {
		result = readCatalogueAttribution(enrichment.Root(resolvers.ConfigRootPath), trust, time.Now())
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(result)
}
