package webui

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/dreadl0ck/netcap/internal/flow"
)

type flowQueryResponse = flow.FileResult

func (s *Server) handleFlowQuery(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	query, err := flow.ParseQuery(r.URL.Query())
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	outDir, _ := s.resolveEvidenceOutput(r)
	if outDir == "" {
		http.Error(w, "No selected analysis dataset", http.StatusServiceUnavailable)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	result, err := readFlowQuery(ctx, filepath.Join(outDir, "Connection.ncap.gz"), query)
	if err != nil {
		status := http.StatusUnprocessableEntity
		if errors.Is(err, os.ErrNotExist) {
			status = http.StatusNotFound
		}
		if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
			status = http.StatusRequestTimeout
		}
		http.Error(w, fmt.Sprintf("Flow query unavailable: %v", err), status)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	if err := json.NewEncoder(w).Encode(result); err != nil {
		return
	}
}

func readFlowQuery(ctx context.Context, path string, query flow.Query) (flowQueryResponse, error) {
	return flow.ReadFile(ctx, path, query)
}

var peerRotationSlots = make(chan struct{}, 2)

func (s *Server) handlePeerRotation(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	selected, ok := s.selectedCapture(w, r)
	if !ok {
		return
	}
	if _, err := parseCollectionPage(r); err != nil {
		RespondJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	select {
	case peerRotationSlots <- struct{}{}:
		defer func() { <-peerRotationSlots }()
	default:
		RespondJSON(w, http.StatusTooManyRequests, map[string]string{"error": "Peer rotation query is busy"})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 25*time.Second)
	defer cancel()
	result, err := flow.ReadPeerRotation(ctx, selected.OutputDir)
	if err != nil {
		status := http.StatusUnprocessableEntity
		if ctx.Err() != nil {
			status = http.StatusRequestTimeout
		}
		RespondJSON(w, status, map[string]string{"error": "Peer rotation requires finalized Connection and TCP evidence within scan limits"})
		return
	}
	q := r.URL.Query()
	q.Set("mcpPage", "true")
	r = r.Clone(ctx)
	r.URL.RawQuery = q.Encode()
	w.Header().Set("Cache-Control", "no-store")
	respondCollectionPage(w, r, result.Candidates, "candidates", map[string]any{"auditGeneration": result.AuditGeneration})
}
