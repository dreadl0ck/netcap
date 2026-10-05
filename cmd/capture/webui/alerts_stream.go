package webui

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/dreadl0ck/netcap/internal/rules"
	"github.com/dreadl0ck/netcap/types"
)

func alertResponse(alert *types.Alert) AlertResponse {
	response := AlertResponse{Timestamp: alert.Timestamp / 1000000, Name: alert.Name, Description: alert.Description, RuleName: alert.RuleName,
		RecordType: alert.RecordType, Severity: alert.Severity, Tags: alert.Tags, MITRE: alert.MITRE, SrcIP: alert.SrcIP, DstIP: alert.DstIP,
		MatchedRecord: alert.MatchedRecord, RuleExpression: alert.RuleExpression, Threshold: alert.Threshold, ThresholdWindow: alert.ThresholdWindow}
	response.AlertID = generateAlertID(response)
	return response
}

func writeAlertSSE(w http.ResponseWriter, event, cursor string, value any) error {
	data, err := json.Marshal(value)
	if err != nil {
		return err
	}
	controller := http.NewResponseController(w)
	if err := controller.SetWriteDeadline(time.Now().Add(10 * time.Second)); err != nil && !errors.Is(err, http.ErrNotSupported) {
		return err
	}
	if cursor != "" {
		if _, err := fmt.Fprintf(w, "id: %s\n", cursor); err != nil {
			return err
		}
	}
	if _, err := fmt.Fprintf(w, "event: %s\ndata: %s\n\n", event, data); err != nil {
		return err
	}
	return controller.Flush()
}

func (s *Server) handleAlertsStream(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	dir, ok := s.behaviorDirectory(w, r)
	if !ok {
		return
	}
	if _, ok := w.(http.Flusher); !ok {
		http.Error(w, "streaming unavailable", http.StatusInternalServerError)
		return
	}
	s.mu.Lock()
	if s.alertStreams >= 8 {
		s.mu.Unlock()
		http.Error(w, "alert stream limit reached", http.StatusTooManyRequests)
		return
	}
	s.alertStreams++
	shutdown := s.shutdownChan
	s.mu.Unlock()
	defer func() { s.mu.Lock(); s.alertStreams--; s.mu.Unlock() }()
	cursor := r.Header.Get("Last-Event-ID")
	if cursor == "" {
		cursor = r.URL.Query().Get("cursor")
	}
	if len(cursor) > 160 {
		http.Error(w, "invalid alert cursor", http.StatusBadRequest)
		return
	}
	path := filepath.Join(dir, "Alert.ncap.gz")
	tail, err := rules.OpenAlertTail(path, cursor)
	if err != nil && !errors.Is(err, os.ErrNotExist) && !errors.Is(err, rules.ErrAlertNotReady) {
		status := http.StatusInternalServerError
		if errors.Is(err, rules.ErrAlertCursor) {
			status = http.StatusConflict
		}
		http.Error(w, err.Error(), status)
		return
	}
	if errors.Is(err, os.ErrNotExist) && cursor != "" {
		http.Error(w, "alert history is unavailable", http.StatusConflict)
		return
	}
	defer func() {
		if tail != nil {
			_ = tail.Close()
		}
	}()
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache, no-store")
	w.Header().Set("X-Accel-Buffering", "no")
	if err := writeAlertSSE(w, "connected", "", map[string]any{"pollMilliseconds": 50}); err != nil {
		return
	}
	poll := time.NewTicker(50 * time.Millisecond)
	defer poll.Stop()
	heartbeat := time.NewTicker(15 * time.Second)
	defer heartbeat.Stop()
	for {
		if tail == nil {
			tail, err = rules.OpenAlertTail(path, cursor)
			if err != nil && !errors.Is(err, os.ErrNotExist) && !errors.Is(err, rules.ErrAlertNotReady) {
				_ = writeAlertSSE(w, "gap", "", map[string]string{"error": err.Error()})
				return
			}
		}
		if tail != nil {
			for range 128 {
				select {
				case <-r.Context().Done():
					return
				case <-shutdown:
					return
				default:
				}
				event, err := tail.Next()
				if errors.Is(err, rules.ErrAlertNotReady) {
					break
				}
				if err != nil {
					_ = writeAlertSSE(w, "gap", "", map[string]string{"error": err.Error()})
					return
				}
				if err := writeAlertSSE(w, "alert", event.Cursor, alertResponse(event.Alert)); err != nil {
					return
				}
			}
		}
		select {
		case <-r.Context().Done():
			return
		case <-shutdown:
			return
		case <-poll.C:
		case <-heartbeat.C:
			if err := writeAlertSSE(w, "heartbeat", "", map[string]any{"at": time.Now().UnixMilli()}); err != nil {
				return
			}
		}
	}
}
