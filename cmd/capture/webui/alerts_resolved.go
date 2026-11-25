package webui

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/dreadl0ck/netcap/internal/artifactio"
	"github.com/dreadl0ck/netcap/types"
)

// resolvedAlertsVersion 2 records a group resolution once instead of one
// entry per alert, so resolving a large group neither reads every alert
// into memory nor grows the file past the page reader's limit.
const resolvedAlertsVersion = 2

// ResolvedAlert represents a resolved alert entry
type ResolvedAlert struct {
	AlertID    string `json:"alertId"`
	ResolvedAt int64  `json:"resolvedAt"`
}

// ResolvedGroup resolves every alert of a group detected at or before
// Through (Unix ns), except the listed alert IDs. Alerts without a
// detection time predate Through by construction of the append-only audit.
type ResolvedGroup struct {
	ResolvedAt   int64    `json:"resolvedAt"`
	Through      int64    `json:"through"`
	Except       []string `json:"except,omitempty"`
	ExceptGroups []string `json:"exceptGroups,omitempty"`
}

// ResolvedAlertsStore manages the resolved alerts
type ResolvedAlertsStore struct {
	Version int                      `json:"version,omitempty"`
	Alerts  map[string]ResolvedAlert `json:"alerts"` // Map of alertId -> ResolvedAlert
	Groups  map[string]ResolvedGroup `json:"groups,omitempty"`
}

// ResolveAlertRequest represents a request to resolve an alert
type ResolveAlertRequest struct {
	AlertID string `json:"alertId"`
	GroupID string `json:"groupId"` // Optional: resolve entire group
}

// ResolveAlertResponse represents the response to a resolve request
type ResolveAlertResponse struct {
	Success     bool      `json:"success"`
	Message     string    `json:"message"`
	MessageI18n UIMessage `json:"messageI18n"`
	ResolvedAt  int64     `json:"resolvedAt"`
	ResolvedIDs []string  `json:"resolvedIds,omitempty"` // IDs that were resolved
	GroupID     string    `json:"groupId,omitempty"`
}

const maxPageResolvedAlertBytes = 4 << 20

// Serializes read-modify-write of resolved_alerts.json.
var resolvedAlertsMu sync.Mutex

func (s *Server) getResolvedAlertsPath(outDir string) string {
	return filepath.Join(outDir, "resolved_alerts.json")
}

func (s *Server) loadResolvedAlerts(outDir string) (*ResolvedAlertsStore, error) {
	return s.loadPageResolvedAlerts(context.Background(), outDir)
}

func (s *Server) loadPageResolvedAlerts(ctx context.Context, outDir string) (*ResolvedAlertsStore, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	file, info, err := artifactio.Open(outDir, filepath.Base(s.getResolvedAlertsPath(outDir)))
	if errors.Is(err, os.ErrNotExist) {
		return &ResolvedAlertsStore{Alerts: map[string]ResolvedAlert{}}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to open resolved alerts: %w", err)
	}
	defer file.Close()
	limitErr := func() error {
		return fmt.Errorf("%w: resolved alerts exceed %d bytes", errAlertPageSourceLimit, maxPageResolvedAlertBytes)
	}
	if info.Size() > maxPageResolvedAlertBytes {
		return nil, limitErr()
	}
	data, err := io.ReadAll(io.LimitReader(auditContextReader{ctx: ctx, input: file}, maxPageResolvedAlertBytes+1))
	if err != nil {
		return nil, fmt.Errorf("failed to read resolved alerts: %w", err)
	}
	if len(data) > maxPageResolvedAlertBytes {
		return nil, limitErr()
	}
	return decodeResolvedAlerts(data)
}

func decodeResolvedAlerts(data []byte) (*ResolvedAlertsStore, error) {
	var store ResolvedAlertsStore
	if err := json.Unmarshal(data, &store); err != nil {
		return nil, fmt.Errorf("failed to parse resolved alerts: %w", err)
	}
	if store.Alerts == nil {
		store.Alerts = make(map[string]ResolvedAlert)
	}
	return &store, nil
}

// saveResolvedAlerts writes compact JSON atomically; a torn write would
// otherwise fail every alert view of the session.
func (s *Server) saveResolvedAlerts(outDir string, store *ResolvedAlertsStore) error {
	store.Version = resolvedAlertsVersion
	data, err := json.Marshal(store)
	if err != nil {
		return fmt.Errorf("failed to marshal resolved alerts: %w", err)
	}
	if len(data) > maxPageResolvedAlertBytes {
		return fmt.Errorf("resolved alerts would exceed %d bytes; resolve by group instead", maxPageResolvedAlertBytes)
	}
	tmp, err := os.CreateTemp(outDir, ".resolved_alerts-*.json")
	if err != nil {
		return fmt.Errorf("failed to write resolved alerts: %w", err)
	}
	defer os.Remove(tmp.Name())
	if _, err = tmp.Write(data); err == nil {
		err = tmp.Chmod(0644)
	}
	if closeErr := tmp.Close(); err == nil {
		err = closeErr
	}
	if err == nil {
		err = os.Rename(tmp.Name(), s.getResolvedAlertsPath(outDir))
	}
	if err != nil {
		return fmt.Errorf("failed to write resolved alerts: %w", err)
	}
	return nil
}

// isAlertResolved reports whether an alert is resolved, individually or
// through its group.
func isAlertResolved(alert *types.Alert, alertID string, store *ResolvedAlertsStore) (bool, int64) {
	if store == nil {
		return false, 0
	}
	if resolved, ok := store.Alerts[alertID]; ok {
		return true, resolved.ResolvedAt
	}
	if alert == nil {
		return false, 0
	}
	k := recordAlertGroup(alert)
	for _, id := range [2]string{k.id(), k.legacyID()} {
		group, ok := store.Groups[id]
		if ok && alert.DetectedAt <= group.Through && !slices.Contains(group.Except, alertID) && !slices.Contains(group.ExceptGroups, k.id()) {
			return true, group.ResolvedAt
		}
	}
	return false, 0
}

// alertGroupOf streams the audit to find the group of one alert ID.
func (s *Server) alertGroupOf(ctx context.Context, outDir, alertID string) (*types.Alert, error) {
	var found *types.Alert
	errFound := errors.New("found")
	err := s.walkAlertAudit(ctx, filepath.Join(outDir, "Alert.ncap.gz"), 0, alertStatsScanRows, alertStatsFrameBytes, func(alert *types.Alert, _ *ResolvedAlertsStore) error {
		if alertResponse(alert).AlertID == alertID {
			found = alert
			return errFound
		}
		return nil
	})
	if err != nil && !errors.Is(err, errFound) {
		return nil, err
	}
	return found, nil
}

// countAlertGroup streams the audit and counts alerts of a group detected
// at or before through, collecting matching legacy per-alert entries.
func (s *Server) countAlertGroup(ctx context.Context, outDir, groupID string, through int64, store *ResolvedAlertsStore) (int, []string, string, error) {
	count := 0
	var ids []string
	var parentID string
	err := s.walkAlertAudit(ctx, filepath.Join(outDir, "Alert.ncap.gz"), 0, alertStatsScanRows, alertStatsFrameBytes, func(alert *types.Alert, _ *ResolvedAlertsStore) error {
		if !inAlertGroup(alert, groupID) || alert.DetectedAt > through {
			return nil
		}
		count++
		if count == 1 {
			parentID = recordAlertGroup(alert).legacyID()
		}
		if id := alertResponse(alert).AlertID; store.Alerts[id].AlertID != "" {
			ids = append(ids, id)
		}
		return nil
	})
	return count, ids, parentID, err
}

func (s *Server) resolutionOutDir(w http.ResponseWriter, r *http.Request) (string, *ResolveAlertRequest, bool) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return "", nil, false
	}
	var req ResolveAlertRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 64<<10)).Decode(&req); err != nil {
		RespondJSON(w, http.StatusBadRequest, map[string]any{"error": "Invalid request body"})
		return "", nil, false
	}
	if req.GroupID == "" && req.AlertID == "" {
		RespondJSON(w, http.StatusBadRequest, map[string]any{"error": "Either alertId or groupId must be provided"})
		return "", nil, false
	}
	selected, ok := s.writableCapture(w, r)
	if !ok {
		return "", nil, false
	}
	return selected.OutputDir, &req, true
}

func (s *Server) respondResolutionError(w http.ResponseWriter, r *http.Request, action string, err error) {
	if errors.Is(err, errAlertPageSourceLimit) || errors.Is(err, errAlertAuditChanged) || r.Context().Err() != nil {
		s.respondAlertReadError(w, r.Context(), err)
		return
	}
	log.Printf("[WebUI] Failed to %s alerts: %v", action, err)
	RespondJSON(w, http.StatusInternalServerError, map[string]any{"error": "Failed to " + action + " alerts"})
}

// handleResolveAlert handles POST requests to resolve an alert
func (s *Server) handleResolveAlert(w http.ResponseWriter, r *http.Request) {
	outDir, req, ok := s.resolutionOutDir(w, r)
	if !ok {
		return
	}
	resolvedAlertsMu.Lock()
	defer resolvedAlertsMu.Unlock()
	store, err := s.loadResolvedAlerts(outDir)
	if err != nil {
		s.respondResolutionError(w, r, "resolve", err)
		return
	}
	if store.Groups == nil {
		store.Groups = map[string]ResolvedGroup{}
	}
	resolvedAt := time.Now().UnixMilli()
	response := ResolveAlertResponse{Success: true, ResolvedAt: resolvedAt}
	count := 1
	if req.GroupID != "" {
		through := time.Now().UnixNano()
		var legacy []string
		count, legacy, _, err = s.countAlertGroup(r.Context(), outDir, req.GroupID, through, store)
		if err != nil {
			s.respondResolutionError(w, r, "resolve", err)
			return
		}
		for _, id := range legacy {
			delete(store.Alerts, id)
		}
		store.Groups[req.GroupID] = ResolvedGroup{ResolvedAt: resolvedAt, Through: through}
		response.GroupID = req.GroupID
	} else {
		store.Alerts[req.AlertID] = ResolvedAlert{AlertID: req.AlertID, ResolvedAt: resolvedAt}
		if err := s.dropGroupException(r.Context(), outDir, req.AlertID, store); err != nil {
			s.respondResolutionError(w, r, "resolve", err)
			return
		}
		response.ResolvedIDs = []string{req.AlertID}
	}
	if err := s.saveResolvedAlerts(outDir, store); err != nil {
		s.respondResolutionError(w, r, "resolve", err)
		return
	}
	response.Message = fmt.Sprintf("Resolved %d alert(s)", count)
	response.MessageI18n = requestUIMessage(r, "alerts.resolved", "Resolved {count} alert(s)", map[string]any{"count": count})
	RespondJSON(w, http.StatusOK, response)
}

func (s *Server) dropGroupException(ctx context.Context, outDir, alertID string, store *ResolvedAlertsStore) error {
	if len(store.Groups) == 0 {
		return nil
	}
	alert, err := s.alertGroupOf(ctx, outDir, alertID)
	if err != nil || alert == nil {
		return err
	}
	k := recordAlertGroup(alert)
	for _, id := range [2]string{k.id(), k.legacyID()} {
		if group, ok := store.Groups[id]; ok {
			group.Except = slices.DeleteFunc(group.Except, func(id string) bool { return id == alertID })
			store.Groups[id] = group
		}
	}
	return nil
}

// handleUnresolveAlert handles POST requests to unresolve an alert
func (s *Server) handleUnresolveAlert(w http.ResponseWriter, r *http.Request) {
	outDir, req, ok := s.resolutionOutDir(w, r)
	if !ok {
		return
	}
	resolvedAlertsMu.Lock()
	defer resolvedAlertsMu.Unlock()
	store, err := s.loadResolvedAlerts(outDir)
	if err != nil {
		s.respondResolutionError(w, r, "unresolve", err)
		return
	}
	var unresolved []string
	count := 1
	if req.GroupID != "" {
		var legacy []string
		var parentID string
		count, legacy, parentID, err = s.countAlertGroup(r.Context(), outDir, req.GroupID, int64(^uint64(0)>>1), store)
		if err != nil {
			s.respondResolutionError(w, r, "unresolve", err)
			return
		}
		for _, id := range legacy {
			delete(store.Alerts, id)
		}
		delete(store.Groups, req.GroupID)
		if parent, ok := store.Groups[parentID]; ok && !slices.Contains(parent.ExceptGroups, req.GroupID) {
			parent.ExceptGroups = append(parent.ExceptGroups, req.GroupID)
			store.Groups[parentID] = parent
		}
	} else {
		delete(store.Alerts, req.AlertID)
		unresolved = []string{req.AlertID}
		if len(store.Groups) > 0 {
			alert, err := s.alertGroupOf(r.Context(), outDir, req.AlertID)
			if err != nil {
				s.respondResolutionError(w, r, "unresolve", err)
				return
			}
			if alert != nil {
				k := recordAlertGroup(alert)
				for _, groupID := range [2]string{k.id(), k.legacyID()} {
					if group, ok := store.Groups[groupID]; ok && alert.DetectedAt <= group.Through && !slices.Contains(group.Except, req.AlertID) {
						group.Except = append(group.Except, req.AlertID)
						store.Groups[groupID] = group
					}
				}
			}
		}
	}
	if err := s.saveResolvedAlerts(outDir, store); err != nil {
		s.respondResolutionError(w, r, "unresolve", err)
		return
	}
	RespondJSON(w, http.StatusOK, map[string]any{
		"success":       true,
		"message":       fmt.Sprintf("Unresolved %d alert(s)", count),
		"messageI18n":   requestUIMessage(r, "alerts.unresolved", "Unresolved {count} alert(s)", map[string]any{"count": count}),
		"unresolvedIds": unresolved,
		"groupId":       strings.TrimSpace(req.GroupID),
	})
}
