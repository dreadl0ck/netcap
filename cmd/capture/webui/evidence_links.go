package webui

import (
	"errors"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/dreadl0ck/netcap/internal/evidencelink"
)

const evidenceLinkCacheSize = 8

type evidenceLinkEntry struct {
	signature string
	index     *evidencelink.Index
	used      time.Time
}

var evidenceLinkCache = struct {
	sync.Mutex
	dirs  map[string]*evidenceLinkEntry
	build chan struct{}
}{dirs: map[string]*evidenceLinkEntry{}, build: make(chan struct{}, 1)}

// evidenceSignature changes whenever an audit file in dir changes, so a live
// capture rebuilds the index on the next query.
func evidenceSignature(dir string) (string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return "", err
	}
	var b strings.Builder
	for _, entry := range entries {
		if entry.IsDir() || !strings.Contains(entry.Name(), ".ncap") {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			continue
		}
		b.WriteString(entry.Name())
		b.WriteByte(':')
		b.WriteString(strconv.FormatInt(info.Size(), 10))
		b.WriteByte(':')
		b.WriteString(strconv.FormatInt(info.ModTime().UnixNano(), 10))
		b.WriteByte(';')
	}
	return b.String(), nil
}

func evidenceIndexFor(r *http.Request, dir string, config evidencelink.Config) (*evidencelink.Index, error) {
	signature, err := evidenceSignature(dir)
	if err != nil {
		return nil, err
	}
	key := dir + "\x00" + strconv.FormatInt(config.WindowNS, 10) + "/" + strconv.FormatInt(config.MaxRecords, 10) + "/" + strconv.Itoa(config.MaxLinks)
	evidenceLinkCache.Lock()
	if entry := evidenceLinkCache.dirs[key]; entry != nil && entry.signature == signature {
		entry.used = time.Now()
		evidenceLinkCache.Unlock()
		return entry.index, nil
	}
	evidenceLinkCache.Unlock()
	select {
	case evidenceLinkCache.build <- struct{}{}:
		defer func() { <-evidenceLinkCache.build }()
	case <-r.Context().Done():
		return nil, r.Context().Err()
	}
	index, err := evidencelink.Build(dir, config)
	if err != nil {
		return nil, err
	}
	evidenceLinkCache.Lock()
	defer evidenceLinkCache.Unlock()
	evidenceLinkCache.dirs[key] = &evidenceLinkEntry{signature: signature, index: index, used: time.Now()}
	for len(evidenceLinkCache.dirs) > evidenceLinkCacheSize {
		var oldestKey string
		var oldest time.Time
		for k, entry := range evidenceLinkCache.dirs {
			if oldestKey == "" || entry.used.Before(oldest) {
				oldestKey, oldest = k, entry.used
			}
		}
		delete(evidenceLinkCache.dirs, oldestKey)
	}
	return index, nil
}

func (s *Server) evidenceLinkConfig() evidencelink.Config {
	config := evidencelink.DefaultConfig()
	s.mu.RLock()
	if s.runtimeConfig != nil && s.runtimeConfig.EvidenceLinks != nil {
		config = *s.runtimeConfig.EvidenceLinks
	}
	s.mu.RUnlock()
	config.Enabled = s.featureEnabled(featureEvidenceLinks)
	return config
}

// handleEvidenceRelated serves GET /api/evidence/related?type=T&ordinal=N.
func (s *Server) handleEvidenceRelated(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	config := s.evidenceLinkConfig()
	if !config.Enabled {
		RespondJSON(w, http.StatusConflict, map[string]any{"enabled": false, "error": "evidence linking is disabled"})
		return
	}
	q := r.URL.Query()
	selector := evidencelink.Selector{ID: q.Get("id"), Type: q.Get("type"), ObservationID: q.Get("observationId"), CommunityID: q.Get("communityId")}
	if id := r.PathValue("id"); id != "" {
		selector.ID = id
	}
	if selector.Type != "" && (strings.ContainsAny(selector.Type, `/\.`) || len(selector.Type) > 64) {
		RespondJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid record type"})
		return
	}
	if raw := q.Get("ordinal"); raw != "" {
		ordinal, err := strconv.ParseInt(raw, 10, 64)
		if err != nil || ordinal < 0 {
			RespondJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid ordinal"})
			return
		}
		selector.Ordinal, selector.HasOrdinal = ordinal, true
	}
	if raw := q.Get("time"); raw != "" {
		at, err := strconv.ParseInt(raw, 10, 64)
		if err != nil {
			RespondJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid time"})
			return
		}
		selector.Time, selector.HasTime = at, true
	}
	dir, ok := s.resolveOutDirFromRequest(r)
	if !ok {
		RespondJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "no output directory"})
		return
	}
	index, err := evidenceIndexFor(r, dir, config)
	if err != nil {
		RespondJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	recordType, ordinal, err := index.Resolve(selector)
	if err != nil && !errors.Is(err, evidencelink.ErrNotFound) {
		RespondJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	var result *evidencelink.Result
	if err == nil {
		result, err = index.Related(recordType, ordinal)
	}
	if errors.Is(err, evidencelink.ErrNotFound) {
		RespondJSON(w, http.StatusNotFound, map[string]string{"error": err.Error()})
		return
	}
	if err != nil {
		RespondJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	RespondJSON(w, http.StatusOK, result)
}
