package webui

import (
	"encoding/json"
	"net/http"
	"sort"
	"sync"
)

// Feature scopes: "query" toggles apply to the next API request, "capture"
// toggles apply to the next analysis started from the WebUI.
const (
	featureScopeQuery   = "query"
	featureScopeCapture = "capture"
)

// Feature names. Each one has a capture flag of the same name.
const (
	featureNetworkDetection = "network-detection"
	featureEvidenceLinks    = "evidence-links"
)

// FeatureState is one optional capability as shown in Settings.
type FeatureState struct {
	Name        string `json:"name"`
	Title       string `json:"title"`
	Description string `json:"description"`
	Scope       string `json:"scope"`
	Flag        string `json:"flag"`
	Env         string `json:"env"`
	Enabled     bool   `json:"enabled"`
}

var featureCatalog = []FeatureState{
	{Name: featureNetworkDetection, Title: "Network detections", Scope: featureScopeCapture, Flag: "-network-detection", Env: "NC_NETWORK_DETECTION",
		Description: "Capture-time detections such as DNS tunneling, scans and periodic connections (c2.beacon)."},
	{Name: featureEvidenceLinks, Title: "Evidence linking", Scope: featureScopeQuery, Flag: "-evidence-links", Env: "NC_EVIDENCE_LINKS",
		Description: "Related evidence for a record: the records of the same connection, the DNS answer that resolved it, connections to resolved addresses and alerts."},
}

type featureSet struct {
	mu      sync.RWMutex
	enabled map[string]bool
}

func newFeatureSet(initial map[string]bool) *featureSet {
	f := &featureSet{enabled: map[string]bool{}}
	for _, feature := range featureCatalog {
		enabled, ok := initial[feature.Name]
		f.enabled[feature.Name] = !ok || enabled
	}
	return f
}

func (f *featureSet) Enabled(name string) bool {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.enabled[name]
}

func (f *featureSet) Set(name string, enabled bool) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.enabled[name]; !ok {
		return false
	}
	f.enabled[name] = enabled
	return true
}

func (f *featureSet) List() []FeatureState {
	f.mu.RLock()
	defer f.mu.RUnlock()
	out := make([]FeatureState, 0, len(featureCatalog))
	for _, feature := range featureCatalog {
		feature.Enabled = f.enabled[feature.Name]
		out = append(out, feature)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

func (s *Server) featureEnabled(name string) bool {
	if s.features == nil {
		return true
	}
	return s.features.Enabled(name)
}

// handleFeatures lists optional features (GET) or toggles one (POST
// {"name","enabled"}). Toggles last until the process exits; startup state
// comes from the capture flags.
func (s *Server) handleFeatures(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	switch r.Method {
	case http.MethodGet:
		RespondJSON(w, http.StatusOK, map[string]any{"features": s.features.List()})
	case http.MethodPost:
		var request struct {
			Name    string `json:"name"`
			Enabled *bool  `json:"enabled"`
		}
		decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&request); err != nil || request.Enabled == nil {
			RespondJSON(w, http.StatusBadRequest, map[string]string{"error": "expected {\"name\": string, \"enabled\": bool}"})
			return
		}
		if !s.features.Set(request.Name, *request.Enabled) {
			RespondJSON(w, http.StatusNotFound, map[string]string{"error": "unknown feature"})
			return
		}
		RespondJSON(w, http.StatusOK, map[string]any{"features": s.features.List()})
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}
