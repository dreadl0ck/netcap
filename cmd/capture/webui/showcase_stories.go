package webui

import (
	_ "embed"
	"encoding/json"
	"net/http"
	"path/filepath"

	"github.com/dreadl0ck/netcap/internal/artifactio"
	"github.com/dreadl0ck/netcap/internal/networkdetect"
	"github.com/dreadl0ck/netcap/types"
)

//go:embed showcase_stories.json
var showcaseData []byte

type showcaseStory struct {
	Title string `json:"title"`
	Summary string `json:"summary"`
	Rules []string `json:"rules"`
	Record string `json:"record,omitempty"`
}

var showcaseStories = func() map[string]showcaseStory {
	var stories map[string]showcaseStory
	if err := json.Unmarshal(showcaseData, &stories); err != nil {
		panic(err)
	}
	return stories
}()

func (s *Server) handleShowcaseStory(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.preloadedSelection(r) {
		RespondJSON(w, http.StatusOK, nil)
		return
	}
	dir, _ := s.resolveOutDirFromRequest(r)
	var manifest struct { InputSHA256 string `json:"inputSHA256"` }
	data, err := artifactio.Read(r.Context(), dir, "capture-manifest.json", 16<<20)
	if err != nil || json.Unmarshal(data, &manifest) != nil {
		RespondJSON(w, http.StatusOK, nil)
		return
	}
	story, ok := showcaseStories[manifest.InputSHA256]
	if !ok {
		RespondJSON(w, http.StatusOK, nil)
		return
	}
	type finding struct { Rule string `json:"rule"`; Name string `json:"name"`; Count int `json:"count"` }
	counts := make(map[string]int, len(story.Rules))
	for _, id := range story.Rules { counts[id] = 0 }
	var findings []finding
	partial := false
	if len(counts) > 0 {
		err := s.walkAlertAudit(r.Context(), filepath.Join(dir, "Alert.ncap.gz"), 0, alertStatsScanRows, alertStatsFrameBytes,
			func(alert *types.Alert, _ *ResolvedAlertsStore) error {
				if _, wanted := counts[alert.RuleName]; wanted { counts[alert.RuleName]++ }
				return nil
			})
		partial = err != nil
		for _, id := range story.Rules {
			if counts[id] > 0 { findings = append(findings, finding{id, networkdetect.DisplayName(id), counts[id]}) }
		}
	}
	RespondJSON(w, http.StatusOK, map[string]any{"title": story.Title, "summary": story.Summary, "findings": findings, "record": story.Record, "partial": partial})
}
