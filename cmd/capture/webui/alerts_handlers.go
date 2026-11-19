/*
 * NETCAP - Traffic Analysis Framework
 * Copyright (c) Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
 * License: GNU General Public License v3.0
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

package webui

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/dreadl0ck/netcap/internal/artifactio"
	"github.com/dreadl0ck/netcap/internal/delimited"
	"github.com/dreadl0ck/netcap/internal/rules"
	"github.com/dreadl0ck/netcap/types"
)

// AlertResponse represents an alert for the API
type AlertResponse struct {
	SrcPort             string   `json:"srcPort,omitempty"`
	DstPort             string   `json:"dstPort,omitempty"`
	Domain              string   `json:"domain,omitempty"`
	Timestamp           int64    `json:"timestamp"`
	Name                string   `json:"name"`
	Description         string   `json:"description"`
	RuleName            string   `json:"ruleName"`
	RecordType          string   `json:"recordType"`
	Severity            string   `json:"severity"`
	Tags                []string `json:"tags"`
	MITRE               string   `json:"mitre"`
	SrcIP               string   `json:"srcIP"`
	DstIP               string   `json:"dstIP"`
	MatchedRecord       string   `json:"matchedRecord"`
	RuleExpression      string   `json:"ruleExpression"`
	Threshold           int32    `json:"threshold"`
	ThresholdWindow     int32    `json:"thresholdWindow"`
	Resolved            bool     `json:"resolved"`
	ResolvedAt          int64    `json:"resolvedAt,omitempty"`
	AlertID             string   `json:"alertId"` // Unique identifier for the alert
	TimestampNs         string   `json:"timestampNs,omitempty"`
	DetectedAtNs        string   `json:"detectedAtNs,omitempty"`
	TimestampBasis      string   `json:"timestampBasis,omitempty"`
	RuleDigest          string   `json:"ruleDigest,omitempty"`
	MatchedRecordSHA256 string   `json:"matchedRecordSHA256,omitempty"`

	GroupedEvaluation *rules.OfflineAlertMetadata `json:"groupedEvaluation,omitempty"`
}

// GroupedAlert represents a deduplicated/grouped alert
type GroupedAlert struct {
	RuleName        string          `json:"ruleName"`
	Description     string          `json:"description"`
	Severity        string          `json:"severity"`
	RecordType      string          `json:"recordType"`
	Tags            []string        `json:"tags"`
	MITRE           string          `json:"mitre"`
	RuleExpression  string          `json:"ruleExpression"`
	Threshold       int32           `json:"threshold"`
	ThresholdWindow int32           `json:"thresholdWindow"`
	Count           int             `json:"count"`
	FirstSeen       int64           `json:"firstSeen"`
	LastSeen        int64           `json:"lastSeen"`
	UniqueSrcIPs    []string        `json:"uniqueSrcIPs"`
	UniqueDstIPs    []string        `json:"uniqueDstIPs"`
	UniqueSrcPorts  []string        `json:"uniqueSrcPorts"`
	UniqueDstPorts  []string        `json:"uniqueDstPorts"`
	SampleAlerts    []AlertResponse `json:"sampleAlerts"`  // Keep a few samples for detail view
	Resolved        bool            `json:"resolved"`      // True if all alerts in this group are resolved
	ResolvedCount   int             `json:"resolvedCount"` // Number of resolved alerts in this group
	GroupID         string          `json:"groupId"`       // Unique identifier for the group
}

// AlertsResponse represents the response containing multiple alerts
type AlertsResponse struct {
	Alerts     []AlertResponse `json:"alerts"`
	TotalCount int             `json:"totalCount"`
}

// GroupedAlertsResponse represents the response containing grouped/deduplicated alerts
type GroupedAlertsResponse struct {
	Groups     []GroupedAlert `json:"groups"`
	TotalCount int            `json:"totalCount"` // Total individual alerts
	GroupCount int            `json:"groupCount"` // Number of unique groups
}

// ResolvedAlert represents a resolved alert entry
type ResolvedAlert struct {
	AlertID    string `json:"alertId"`
	ResolvedAt int64  `json:"resolvedAt"`
}

// ResolvedAlertsStore manages the resolved alerts
type ResolvedAlertsStore struct {
	Alerts map[string]ResolvedAlert `json:"alerts"` // Map of alertId -> ResolvedAlert
}

// ResolveAlertRequest represents a request to resolve an alert
type ResolveAlertRequest struct {
	AlertID string `json:"alertId"`
	GroupID string `json:"groupId"` // Optional: resolve entire group
}

// ResolveAlertResponse represents the response to a resolve request
type ResolveAlertResponse struct {
	Success     bool     `json:"success"`
	Message     string   `json:"message"`
	ResolvedAt  int64    `json:"resolvedAt"`
	ResolvedIDs []string `json:"resolvedIds,omitempty"` // IDs that were resolved
}

// handleAlerts handles GET requests for alerts
func (s *Server) handleAlerts(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	bounded := r.URL.Query().Get("mcpPage") == "true"
	release := admitAlertRead(w, r, bounded)
	if release == nil {
		return
	}
	defer release()

	// Parse query parameters
	query := r.URL.Query()
	limitStr := query.Get("limit")
	offsetStr := query.Get("offset")
	severityFilter := query.Get("severity")
	ruleNameFilter := query.Get("ruleName")
	sortOrder := query.Get("sort") // "asc" or "desc", default is "desc" (newest first)

	limit := 100 // default limit
	offset := 0  // default offset

	if limitStr != "" {
		if l, err := strconv.Atoi(limitStr); err == nil && l > 0 {
			limit = l
		}
	}

	if offsetStr != "" {
		if o, err := strconv.Atoi(offsetStr); err == nil && o >= 0 {
			offset = o
		}
	}

	if sortOrder == "" {
		sortOrder = "desc"
	}

	// Determine the output directory
	outDir, _ := s.resolveOutDirFromRequest(r)

	if outDir == "" {
		RespondJSON(w, http.StatusServiceUnavailable, map[string]any{
			"error": "No output directory selected",
		})
		return
	}

	// Read alerts from the alerts audit record file
	alertsFile := filepath.Join(outDir, "Alert.ncap.gz")
	if bounded {
		s.serveRawAlertPage(w, r, alertsFile)
		return
	}
	alerts, ok := s.alertsForResponse(w, r, alertsFile, bounded)
	if !ok {
		return
	}

	// Apply filters
	filtered := make([]AlertResponse, 0)
	for _, alert := range alerts {
		if groupID := query.Get("groupId"); groupID != "" && generateGroupID(alert.RuleName, alert.Severity) != groupID {
			continue
		}
		// Filter by severity
		if severityFilter != "" && !strings.EqualFold(alert.Severity, severityFilter) {
			continue
		}

		// Filter by rule name
		if ruleNameFilter != "" && !strings.EqualFold(alert.RuleName, ruleNameFilter) {
			continue
		}

		filtered = append(filtered, alert)
	}

	// Sort alerts
	sort.Slice(filtered, func(i, j int) bool {
		if sortOrder == "asc" {
			return filtered[i].Timestamp < filtered[j].Timestamp
		}
		return filtered[i].Timestamp > filtered[j].Timestamp
	})

	// Apply pagination
	totalCount := len(filtered)
	start := offset
	end := offset + limit

	if start >= totalCount {
		filtered = []AlertResponse{}
	} else {
		if end > totalCount {
			end = totalCount
		}
		filtered = filtered[start:end]
	}

	RespondJSON(w, http.StatusOK, AlertsResponse{
		Alerts:     filtered,
		TotalCount: totalCount,
	})
}

// readAlertsFromFile reads alerts from the Alert.ncap.gz file
func (s *Server) readAlertsFromFile(filePath string) ([]AlertResponse, error) {
	return s.readAlertAudit(nil, filePath)
}

var errAlertPageSourceLimit = errors.New("alert page source exceeds scan limits")
var errAlertAuditChanged = errors.New("alert audit changed during scan; retry the request")

var alertReadSlots = make(chan struct{}, 2)

func admitAlertRead(w http.ResponseWriter, r *http.Request, bounded bool) func() {
	if !bounded {
		return func() {}
	}
	if r.Context().Err() != nil {
		return nil
	}
	select {
	case alertReadSlots <- struct{}{}:
		return func() { <-alertReadSlots }
	default:
		RespondJSON(w, http.StatusTooManyRequests, map[string]string{"error": "alert reads are busy"})
		return nil
	}
}

func (s *Server) alertsForResponse(w http.ResponseWriter, r *http.Request, filePath string, bounded bool) ([]AlertResponse, bool) {
	var ctx context.Context
	if bounded {
		ctx = r.Context()
	}
	alerts, err := s.readAlertAudit(ctx, filePath)
	if err == nil {
		return alerts, true
	}
	s.respondAlertReadError(w, ctx, err)
	return nil, false
}

func (s *Server) respondAlertReadError(w http.ResponseWriter, ctx context.Context, err error) {
	if ctx != nil && ctx.Err() != nil {
		return
	}
	if errors.Is(err, errAlertPageSourceLimit) {
		RespondJSON(w, http.StatusRequestEntityTooLarge, map[string]string{"error": err.Error()})
		return
	}
	if errors.Is(err, errAlertAuditChanged) {
		RespondJSON(w, http.StatusConflict, map[string]string{"error": errAlertAuditChanged.Error()})
		return
	}
	log.Printf("[WebUI] Failed to read alerts: %v", err)
	RespondJSON(w, http.StatusInternalServerError, map[string]string{"error": "Failed to read alerts"})
}

func (s *Server) readAlertAudit(ctx context.Context, filePath string) ([]AlertResponse, error) {
	return s.scanAlertAudit(ctx, filePath, maxCollectionPageScanBytes, maxCollectionPageRows, maxCollectionPageScanBytes, nil)
}

func (s *Server) scanAlertAudit(ctx context.Context, filePath string, byteLimit, rowLimit, frameCap int, visit func(AlertResponse) error) ([]AlertResponse, error) {
	var reader *AuditRecordReader
	var opened os.FileInfo
	var err error
	if ctx == nil {
		reader, err = NewAuditRecordReader(filePath)
	} else {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		file, info, openErr := artifactio.Open(filepath.Dir(filePath), filepath.Base(filePath))
		if openErr != nil {
			err = openErr
		} else if info.Size() > int64(byteLimit) {
			file.Close()
			return nil, fmt.Errorf("%w: stored audit exceeds %d bytes", errAlertPageSourceLimit, byteLimit)
		} else {
			opened = info
			reader, err = auditRecordReaderFromInput(file, io.NewSectionReader(file, 0, info.Size()), true, func(in io.Reader) io.Reader {
				return auditContextReader{ctx: ctx, input: in}
			})
		}
	}
	if errors.Is(err, os.ErrNotExist) {
		return []AlertResponse{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to open alerts file: %w", err)
	}
	defer reader.Close()

	// Read header to initialize reader
	header, err := reader.ReadHeader()
	if err != nil {
		return nil, fmt.Errorf("failed to read header: %w", err)
	}
	if ctx != nil && header.Type != types.Type_NC_Alert {
		return nil, fmt.Errorf("unexpected alert audit type %s", header.Type)
	}

	// Load resolved alerts
	outDir := filepath.Dir(filePath)
	var resolvedStore *ResolvedAlertsStore
	if ctx != nil {
		resolvedStore, err = s.loadPageResolvedAlerts(ctx, outDir)
		if err != nil {
			return nil, err
		}
	} else {
		resolvedStore, err = s.loadResolvedAlerts(outDir)
		if err != nil {
			log.Printf("[WebUI] Failed to load resolved alerts: %v (continuing without resolved status)", err)
			resolvedStore = &ResolvedAlertsStore{Alerts: make(map[string]ResolvedAlert)}
		}
	}

	alerts := make([]AlertResponse, 0)
	remaining := byteLimit
	rows := 0

	// Read all records
	for {
		var record any
		if ctx == nil {
			record, err = reader.NextRecord()
		} else {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			frameLimit := min(remaining, frameCap)
			if rows == rowLimit {
				frameLimit = 0
			}
			var raw []byte
			raw, err = reader.delimitedReader.NextWithLimit(uint64(max(frameLimit, 1)))
			if errors.Is(err, delimited.ErrRecordLimit) || (err == nil && (len(raw) > frameLimit || rows == rowLimit)) {
				return nil, fmt.Errorf("%w: %d records, %d decoded bytes or %d bytes per frame", errAlertPageSourceLimit, rowLimit, byteLimit, frameCap)
			}
			if err == nil {
				rows++
				remaining -= len(raw)
				record, err = reader.DecodeRecord(raw)
			}
		}
		if err != nil {
			if err == io.EOF {
				break
			}
			return nil, fmt.Errorf("failed to read alert record: %w", err)
		}

		// Type assert to Alert
		alert, ok := record.(*types.Alert)
		if !ok {
			log.Printf("[WebUI] Record is not an Alert type")
			continue
		}

		alertResp := alertResponse(alert)

		// Check if resolved
		resolved, resolvedAt := isAlertResolved(alertResp.AlertID, resolvedStore)
		alertResp.Resolved = resolved
		alertResp.ResolvedAt = resolvedAt

		if visit != nil {
			if err := visit(alertResp); err != nil {
				return nil, err
			}
		} else {
			alerts = append(alerts, alertResp)
		}
	}

	if opened != nil {
		current, err := os.Lstat(filePath)
		if err != nil || !os.SameFile(opened, current) || opened.Size() != current.Size() || !opened.ModTime().Equal(current.ModTime()) {
			return nil, errAlertAuditChanged
		}
	}
	return alerts, nil
}

const (
	alertStatsScanBytes      = 256 << 20
	alertStatsScanRows       = 1 << 20
	alertStatsFrameBytes     = 1 << 20
	alertStatsDimensionBytes = 512 << 10
	alertStatsResponseBytes  = 8 << 20
)

// handleAlertStats returns statistics about alerts
func (s *Server) handleAlertStats(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	release := admitAlertRead(w, r, true)
	if release == nil {
		return
	}
	defer release()

	// Determine the output directory
	outDir, _ := s.resolveOutDirFromRequest(r)

	if outDir == "" {
		RespondJSON(w, http.StatusServiceUnavailable, map[string]any{
			"error": "No output directory selected",
		})
		return
	}

	// Read alerts from the alerts audit record file
	alertsFile := filepath.Join(outDir, "Alert.ncap.gz")
	bySeverity := make(map[string]int)
	byRule := make(map[string]int)
	criticalCount, total, dimensions := 0, 0, 0
	type groupKey struct{ rule, severity string }
	alertGroups := make(map[groupKey]struct{})
	recentAlerts := make([]AlertResponse, 0, 10)
	_, err := s.scanAlertAudit(r.Context(), alertsFile, alertStatsScanBytes, alertStatsScanRows, alertStatsFrameBytes, func(alert AlertResponse) error {
		key := groupKey{alert.RuleName, alert.Severity}
		if _, ok := alertGroups[key]; !ok {
			dimensions += len(key.rule) + len(key.severity) + 128
			if dimensions > alertStatsDimensionBytes {
				return fmt.Errorf("%w: summary dimension budget exceeded", errAlertPageSourceLimit)
			}
			alertGroups[key] = struct{}{}
		}
		total++
		bySeverity[alert.Severity]++
		byRule[alert.RuleName]++
		if strings.EqualFold(alert.Severity, "critical") {
			criticalCount++
		}
		if len(recentAlerts) < cap(recentAlerts) || alert.Timestamp > recentAlerts[len(recentAlerts)-1].Timestamp {
			if len(recentAlerts) < cap(recentAlerts) {
				recentAlerts = append(recentAlerts, alert)
			} else {
				recentAlerts[len(recentAlerts)-1] = alert
			}
			sort.SliceStable(recentAlerts, func(i, j int) bool { return recentAlerts[i].Timestamp > recentAlerts[j].Timestamp })
		}
		return nil
	})
	if err != nil {
		s.respondAlertReadError(w, r.Context(), err)
		return
	}

	payload, err := json.Marshal(map[string]any{
		"totalAlerts":    total,
		"groupCount":     len(alertGroups),
		"bySeverity":     bySeverity,
		"byRule":         byRule,
		"recentAlerts":   recentAlerts,
		"criticalAlerts": criticalCount,
		"lastUpdate":     time.Now().Unix(),
	})
	if err != nil {
		s.respondAlertReadError(w, r.Context(), err)
		return
	}
	if len(payload) > alertStatsResponseBytes {
		s.respondAlertReadError(w, r.Context(), fmt.Errorf("%w: statistics response exceeds %d bytes", errAlertPageSourceLimit, alertStatsResponseBytes))
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(payload)
}

// handleClearAlerts handles requests to clear all alerts
func (s *Server) handleClearAlerts(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Determine the output directory
	outDir, _ := s.resolveOutDirFromRequest(r)

	if outDir == "" {
		RespondJSON(w, http.StatusServiceUnavailable, map[string]any{
			"error": "No output directory selected",
		})
		return
	}

	// Delete the alerts file
	release, available := leaseOfflineMutation(outDir)
	if !available {
		RespondJSON(w, http.StatusConflict, map[string]any{"error": "Capture output is busy"})
		return
	}
	defer release()
	alertsFile := filepath.Join(outDir, "Alert.ncap.gz")
	if err := os.Remove(alertsFile); err != nil && !os.IsNotExist(err) {
		log.Printf("[WebUI] Failed to delete alerts file: %v", err)
		RespondJSON(w, http.StatusInternalServerError, map[string]any{
			"error": "Failed to clear alerts",
		})
		return
	}

	log.Printf("[WebUI] Cleared all alerts")

	RespondJSON(w, http.StatusOK, map[string]any{
		"success": true,
		"message": "All alerts cleared successfully",
	})
}

// handleGroupedAlerts handles GET requests for grouped/deduplicated alerts
func (s *Server) handleGroupedAlerts(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	bounded := r.URL.Query().Get("mcpPage") == "true"
	release := admitAlertRead(w, r, bounded)
	if release == nil {
		return
	}
	defer release()

	// Parse query parameters
	query := r.URL.Query()
	limitStr := query.Get("limit")
	offsetStr := query.Get("offset")
	severityFilter := query.Get("severity")
	ruleNameFilter := query.Get("ruleName")
	sortOrder := query.Get("sort") // "asc" or "desc", default is "desc" (newest first)
	sortBy := query.Get("sortBy")  // "count", "lastSeen", "firstSeen", "severity"

	limit := 100 // default limit
	offset := 0  // default offset

	if limitStr != "" {
		if l, err := strconv.Atoi(limitStr); err == nil && l > 0 {
			limit = l
		}
	}

	if offsetStr != "" {
		if o, err := strconv.Atoi(offsetStr); err == nil && o >= 0 {
			offset = o
		}
	}

	if sortOrder == "" {
		sortOrder = "desc"
	}

	if sortBy == "" {
		sortBy = "lastSeen"
	}

	// Determine the output directory
	outDir, _ := s.resolveOutDirFromRequest(r)

	if outDir == "" {
		RespondJSON(w, http.StatusServiceUnavailable, map[string]any{
			"error": "No output directory selected",
		})
		return
	}

	// Read alerts from the alerts audit record file
	alertsFile := filepath.Join(outDir, "Alert.ncap.gz")
	var groups []GroupedAlert
	if bounded {
		if _, err := parseCollectionPage(r); err != nil {
			RespondJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		acc := newAlertGroups(maxCollectionPageScanBytes)
		_, err := s.scanAlertAudit(r.Context(), alertsFile, alertStatsScanBytes, alertStatsScanRows, alertStatsFrameBytes, func(alert AlertResponse) error {
			return acc.add(alert, severityFilter, ruleNameFilter)
		})
		if err != nil {
			s.respondAlertReadError(w, r.Context(), err)
			return
		}
		groups = acc.finish()
	} else {
		alerts, ok := s.alertsForResponse(w, r, alertsFile, false)
		if !ok {
			return
		}
		groups = groupAlerts(alerts, severityFilter, ruleNameFilter)
	}
	if classification := query.Get("classification"); classification != "" {
		filtered := make([]GroupedAlert, 0, len(groups))
		for _, group := range groups {
			for _, tag := range group.Tags {
				if tag == classification {
					filtered = append(filtered, group)
					break
				}
			}
		}
		groups = filtered
	}

	// Sort groups
	sortGroupedAlerts(groups, sortBy, sortOrder)

	// Apply pagination
	totalCount := 0
	for _, g := range groups {
		totalCount += g.Count
	}
	groupCount := len(groups)
	if query.Get("mcpPage") == "true" {
		if search := strings.ToLower(query.Get("pageSearch")); search != "" {
			matched := make([]GroupedAlert, 0)
			totalCount = 0
			for _, group := range groups {
				raw, err := json.Marshal(group)
				if err != nil {
					RespondJSON(w, 500, map[string]string{"error": err.Error()})
					return
				}
				if strings.Contains(strings.ToLower(string(raw)), search) {
					matched = append(matched, group)
					totalCount += group.Count
				}
			}
			groups, groupCount = matched, len(matched)
		}
		rows, err := groupedAlertPageRows(groups)
		if err != nil {
			RespondJSON(w, 500, map[string]string{"error": err.Error()})
			return
		}
		respondFilteredCollectionPage(w, r, rows, "groups", map[string]any{"totalCount": totalCount, "groupCount": groupCount})
		return
	}
	start := offset
	end := offset + limit

	if start >= groupCount {
		groups = []GroupedAlert{}
	} else {
		if end > groupCount {
			end = groupCount
		}
		groups = groups[start:end]
	}

	RespondJSON(w, http.StatusOK, GroupedAlertsResponse{
		Groups:     groups,
		TotalCount: totalCount,
		GroupCount: groupCount,
	})
}

// groupAlerts groups alerts by rule name and severity, collecting unique values
func groupAlerts(alerts []AlertResponse, severityFilter, ruleNameFilter string) []GroupedAlert {
	acc := newAlertGroups(-1)
	for _, alert := range alerts {
		_ = acc.add(alert, severityFilter, ruleNameFilter)
	}
	return acc.finish()
}

type alertGroupKey struct{ ruleName, severity string }

type alertGroups struct {
	groups    map[alertGroupKey]*GroupedAlert
	unique    map[alertGroupKey][4]map[string]bool
	remaining int
}

func newAlertGroups(budget int) *alertGroups {
	return &alertGroups{groups: make(map[alertGroupKey]*GroupedAlert), unique: make(map[alertGroupKey][4]map[string]bool), remaining: budget}
}

func (a *alertGroups) add(alert AlertResponse, severityFilter, ruleNameFilter string) error {
	if severityFilter != "" && !strings.EqualFold(alert.Severity, severityFilter) {
		return nil
	}
	if ruleNameFilter != "" && !strings.EqualFold(alert.RuleName, ruleNameFilter) {
		return nil
	}

	key := alertGroupKey{
		ruleName: alert.RuleName,
		severity: alert.Severity,
	}

	group, exists := a.groups[key]
	values := [4]string{alert.SrcIP, alert.DstIP, extractPort(alert, "SrcPort"), extractPort(alert, "DstPort")}
	seen := a.unique[key]
	if a.remaining >= 0 {
		charge := 0
		if !exists || len(group.SampleAlerts) < 5 {
			raw, err := json.Marshal(alert)
			if err != nil {
				return err
			}
			charge += len(raw) + 512
			if !exists {
				charge += len(raw) + 1024
			}
		}
		for i, value := range values {
			if value != "" && !seen[i][value] {
				charge += len(value) + 64
			}
		}
		if charge > a.remaining {
			return fmt.Errorf("%w: grouped alert state budget exceeded", errAlertPageSourceLimit)
		}
		a.remaining -= charge
	}
	if !exists {
		group = &GroupedAlert{
			RuleName:        alert.RuleName,
			Description:     alert.Description,
			Severity:        alert.Severity,
			RecordType:      alert.RecordType,
			Tags:            append([]string{}, alert.Tags...),
			MITRE:           alert.MITRE,
			RuleExpression:  alert.RuleExpression,
			Threshold:       alert.Threshold,
			ThresholdWindow: alert.ThresholdWindow,
			Count:           0,
			FirstSeen:       alert.Timestamp,
			LastSeen:        alert.Timestamp,
			UniqueSrcIPs:    []string{},
			UniqueDstIPs:    []string{},
			UniqueSrcPorts:  []string{},
			UniqueDstPorts:  []string{},
			SampleAlerts:    []AlertResponse{},
			ResolvedCount:   0,
			GroupID:         generateGroupID(alert.RuleName, alert.Severity),
		}
		a.groups[key] = group
		seen = [4]map[string]bool{{}, {}, {}, {}}
		a.unique[key] = seen
	}

	// Update group statistics
	group.Count++
	if alert.Resolved {
		group.ResolvedCount++
	}
	if alert.Timestamp < group.FirstSeen {
		group.FirstSeen = alert.Timestamp
	}
	if alert.Timestamp > group.LastSeen {
		group.LastSeen = alert.Timestamp
	}

	// Collect unique IPs and ports
	appendGroupUnique(&group.UniqueSrcIPs, seen[0], values[0])
	appendGroupUnique(&group.UniqueDstIPs, seen[1], values[1])
	appendGroupUnique(&group.UniqueSrcPorts, seen[2], values[2])
	appendGroupUnique(&group.UniqueDstPorts, seen[3], values[3])

	// Keep up to 5 sample alerts for detail view
	if len(group.SampleAlerts) < 5 {
		group.SampleAlerts = append(group.SampleAlerts, alert)
	}
	return nil
}

func (a *alertGroups) finish() []GroupedAlert {
	result := make([]GroupedAlert, 0, len(a.groups))
	for _, group := range a.groups {
		// Sort the unique values for consistent display
		sort.Strings(group.UniqueSrcIPs)
		sort.Strings(group.UniqueDstIPs)
		sort.Strings(group.UniqueSrcPorts)
		sort.Strings(group.UniqueDstPorts)

		// Mark group as resolved if all alerts in the group are resolved
		group.Resolved = group.ResolvedCount > 0 && group.ResolvedCount == group.Count

		result = append(result, *group)
	}

	return result
}

// sortGroupedAlerts sorts grouped alerts based on the specified field and order
// Uses multi-level sorting to ensure deterministic ordering:
// 1. Primary: user-selected field
// 2. Secondary: lastSeen (if not already primary)
// 3. Tertiary: ruleName (for complete determinism)
func sortGroupedAlerts(groups []GroupedAlert, sortBy, sortOrder string) {
	sort.Slice(groups, func(i, j int) bool {
		var less bool

		// Primary sort by the selected field
		switch sortBy {
		case "count":
			if groups[i].Count != groups[j].Count {
				less = groups[i].Count < groups[j].Count
			} else {
				// Secondary: sort by lastSeen when counts are equal
				if groups[i].LastSeen != groups[j].LastSeen {
					less = groups[i].LastSeen < groups[j].LastSeen
				} else {
					// Tertiary: sort by ruleName for complete determinism
					less = groups[i].RuleName < groups[j].RuleName
				}
			}
		case "firstSeen":
			if groups[i].FirstSeen != groups[j].FirstSeen {
				less = groups[i].FirstSeen < groups[j].FirstSeen
			} else {
				// Secondary: sort by lastSeen when firstSeen are equal
				if groups[i].LastSeen != groups[j].LastSeen {
					less = groups[i].LastSeen < groups[j].LastSeen
				} else {
					// Tertiary: sort by ruleName for complete determinism
					less = groups[i].RuleName < groups[j].RuleName
				}
			}
		case "severity":
			// Sort by severity level: critical > high > medium > low
			severityOrder := map[string]int{"critical": 4, "high": 3, "medium": 2, "low": 1}
			iVal := severityOrder[strings.ToLower(groups[i].Severity)]
			jVal := severityOrder[strings.ToLower(groups[j].Severity)]
			if iVal != jVal {
				less = iVal < jVal
			} else {
				// Secondary: sort by lastSeen when severity is equal
				if groups[i].LastSeen != groups[j].LastSeen {
					less = groups[i].LastSeen < groups[j].LastSeen
				} else {
					// Tertiary: sort by ruleName for complete determinism
					less = groups[i].RuleName < groups[j].RuleName
				}
			}
		default: // lastSeen
			if groups[i].LastSeen != groups[j].LastSeen {
				less = groups[i].LastSeen < groups[j].LastSeen
			} else {
				// Secondary: sort by count when lastSeen are equal
				if groups[i].Count != groups[j].Count {
					less = groups[i].Count < groups[j].Count
				} else {
					// Tertiary: sort by ruleName for complete determinism
					less = groups[i].RuleName < groups[j].RuleName
				}
			}
		}

		if sortOrder == "desc" {
			return !less
		}
		return less
	})
}

// extractPort attempts to extract port information from the alert
func extractPort(alert AlertResponse, portField string) string {
	// Try to parse the matched record JSON to extract port information
	if alert.MatchedRecord == "" {
		return ""
	}

	// Simple string search for port values in the JSON
	// This is a basic implementation - could be enhanced with proper JSON parsing if needed
	var data map[string]any
	if err := json.Unmarshal([]byte(alert.MatchedRecord), &data); err != nil {
		return ""
	}

	if val, ok := data[portField]; ok {
		return fmt.Sprintf("%v", val)
	}

	return ""
}

// generateAlertID generates a unique identifier for an alert
func generateAlertID(alert AlertResponse) string {
	if alert.GroupedEvaluation != nil {
		return alert.GroupedEvaluation.EventID
	}
	id := fmt.Sprintf("%s-%d-%s-%s", alert.RuleName, alert.Timestamp, alert.SrcIP, alert.DstIP)
	if alert.RuleDigest != "" {
		hash := sha256.Sum256([]byte(alert.RuleDigest + "/" + alert.TimestampNs + "/" + alert.DetectedAtNs + "/" + alert.MatchedRecordSHA256))
		return fmt.Sprintf("%s-v2-%x", id, hash[:16])
	}
	if alert.RecordType == "Behavior" || alert.RecordType == "NetworkDetection" {
		hash := sha256.Sum256([]byte(alert.MatchedRecord))
		return fmt.Sprintf("%s-%x", id, hash[:16])
	}
	return id
}

// generateGroupID generates a unique identifier for an alert group
func generateGroupID(ruleName, severity string) string {
	return fmt.Sprintf("%s-%s", ruleName, severity)
}

// getResolvedAlertsPath returns the path to the resolved alerts file
func (s *Server) getResolvedAlertsPath(outDir string) string {
	return filepath.Join(outDir, "resolved_alerts.json")
}

// loadResolvedAlerts loads the resolved alerts from disk
func (s *Server) loadResolvedAlerts(outDir string) (*ResolvedAlertsStore, error) {
	filePath := s.getResolvedAlertsPath(outDir)

	// If file doesn't exist, return empty store
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		return &ResolvedAlertsStore{
			Alerts: make(map[string]ResolvedAlert),
		}, nil
	}

	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read resolved alerts: %w", err)
	}
	return decodeResolvedAlerts(data)
}

const maxPageResolvedAlertBytes = 4 << 20

func (s *Server) loadPageResolvedAlerts(ctx context.Context, outDir string) (*ResolvedAlertsStore, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	file, info, err := artifactio.Open(outDir, filepath.Base(s.getResolvedAlertsPath(outDir)))
	if errors.Is(err, os.ErrNotExist) {
		return &ResolvedAlertsStore{}, nil
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

// saveResolvedAlerts saves the resolved alerts to disk
func (s *Server) saveResolvedAlerts(outDir string, store *ResolvedAlertsStore) error {
	filePath := s.getResolvedAlertsPath(outDir)

	data, err := json.MarshalIndent(store, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal resolved alerts: %w", err)
	}

	if err := os.WriteFile(filePath, data, 0644); err != nil {
		return fmt.Errorf("failed to write resolved alerts: %w", err)
	}

	return nil
}

// isAlertResolved checks if an alert is resolved
func isAlertResolved(alertID string, store *ResolvedAlertsStore) (bool, int64) {
	if resolved, ok := store.Alerts[alertID]; ok {
		return true, resolved.ResolvedAt
	}
	return false, 0
}

// handleResolveAlert handles POST requests to resolve an alert
func (s *Server) handleResolveAlert(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Parse request body
	var req ResolveAlertRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		RespondJSON(w, http.StatusBadRequest, map[string]any{
			"error": "Invalid request body",
		})
		return
	}

	// Determine the output directory
	s.mu.RLock()
	outDir := s.outDir
	if s.isServiceMode && s.currentSession != "" && s.sessionManager != nil {
		if session, ok := s.sessionManager.GetSession(s.currentSession); ok {
			outDir = session.OutputDir
		}
	}
	s.mu.RUnlock()

	if outDir == "" {
		RespondJSON(w, http.StatusServiceUnavailable, map[string]any{
			"error": "No output directory selected",
		})
		return
	}

	// Load resolved alerts store
	store, err := s.loadResolvedAlerts(outDir)
	if err != nil {
		log.Printf("[WebUI] Failed to load resolved alerts: %v", err)
		RespondJSON(w, http.StatusInternalServerError, map[string]any{
			"error": "Failed to load resolved alerts",
		})
		return
	}

	resolvedAt := time.Now().UnixMilli()
	resolvedIDs := []string{}

	// If GroupID is provided, resolve all alerts in the group
	if req.GroupID != "" {
		// Read all alerts to find those in this group
		alertsFile := filepath.Join(outDir, "Alert.ncap.gz")
		alerts, err := s.readAlertsFromFile(alertsFile)
		if err != nil {
			log.Printf("[WebUI] Failed to read alerts: %v", err)
			RespondJSON(w, http.StatusInternalServerError, map[string]any{
				"error": "Failed to read alerts",
			})
			return
		}

		// Find all alerts matching this group
		for i := range alerts {
			alert := &alerts[i]
			alertID := generateAlertID(*alert)
			groupID := generateGroupID(alert.RuleName, alert.Severity)

			if groupID == req.GroupID {
				store.Alerts[alertID] = ResolvedAlert{
					AlertID:    alertID,
					ResolvedAt: resolvedAt,
				}
				resolvedIDs = append(resolvedIDs, alertID)
			}
		}
	} else if req.AlertID != "" {
		// Resolve single alert
		store.Alerts[req.AlertID] = ResolvedAlert{
			AlertID:    req.AlertID,
			ResolvedAt: resolvedAt,
		}
		resolvedIDs = append(resolvedIDs, req.AlertID)
	} else {
		RespondJSON(w, http.StatusBadRequest, map[string]any{
			"error": "Either alertId or groupId must be provided",
		})
		return
	}

	// Save resolved alerts store
	if err := s.saveResolvedAlerts(outDir, store); err != nil {
		log.Printf("[WebUI] Failed to save resolved alerts: %v", err)
		RespondJSON(w, http.StatusInternalServerError, map[string]any{
			"error": "Failed to save resolved alerts",
		})
		return
	}

	log.Printf("[WebUI] Resolved %d alert(s)", len(resolvedIDs))

	RespondJSON(w, http.StatusOK, ResolveAlertResponse{
		Success:     true,
		Message:     fmt.Sprintf("Resolved %d alert(s)", len(resolvedIDs)),
		ResolvedAt:  resolvedAt,
		ResolvedIDs: resolvedIDs,
	})
}

// handleUnresolveAlert handles POST requests to unresolve an alert
func (s *Server) handleUnresolveAlert(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Parse request body
	var req ResolveAlertRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		RespondJSON(w, http.StatusBadRequest, map[string]any{
			"error": "Invalid request body",
		})
		return
	}

	// Determine the output directory
	s.mu.RLock()
	outDir := s.outDir
	if s.isServiceMode && s.currentSession != "" && s.sessionManager != nil {
		if session, ok := s.sessionManager.GetSession(s.currentSession); ok {
			outDir = session.OutputDir
		}
	}
	s.mu.RUnlock()

	if outDir == "" {
		RespondJSON(w, http.StatusServiceUnavailable, map[string]any{
			"error": "No output directory selected",
		})
		return
	}

	// Load resolved alerts store
	store, err := s.loadResolvedAlerts(outDir)
	if err != nil {
		log.Printf("[WebUI] Failed to load resolved alerts: %v", err)
		RespondJSON(w, http.StatusInternalServerError, map[string]any{
			"error": "Failed to load resolved alerts",
		})
		return
	}

	unresolvedIDs := []string{}

	// If GroupID is provided, unresolve all alerts in the group
	if req.GroupID != "" {
		// Read all alerts to find those in this group
		alertsFile := filepath.Join(outDir, "Alert.ncap.gz")
		alerts, err := s.readAlertsFromFile(alertsFile)
		if err != nil {
			log.Printf("[WebUI] Failed to read alerts: %v", err)
			RespondJSON(w, http.StatusInternalServerError, map[string]any{
				"error": "Failed to read alerts",
			})
			return
		}

		// Find all alerts matching this group
		for i := range alerts {
			alert := &alerts[i]
			alertID := generateAlertID(*alert)
			groupID := generateGroupID(alert.RuleName, alert.Severity)

			if groupID == req.GroupID {
				delete(store.Alerts, alertID)
				unresolvedIDs = append(unresolvedIDs, alertID)
			}
		}
	} else if req.AlertID != "" {
		// Unresolve single alert
		delete(store.Alerts, req.AlertID)
		unresolvedIDs = append(unresolvedIDs, req.AlertID)
	} else {
		RespondJSON(w, http.StatusBadRequest, map[string]any{
			"error": "Either alertId or groupId must be provided",
		})
		return
	}

	// Save resolved alerts store
	if err := s.saveResolvedAlerts(outDir, store); err != nil {
		log.Printf("[WebUI] Failed to save resolved alerts: %v", err)
		RespondJSON(w, http.StatusInternalServerError, map[string]any{
			"error": "Failed to save resolved alerts",
		})
		return
	}

	log.Printf("[WebUI] Unresolved %d alert(s)", len(unresolvedIDs))

	RespondJSON(w, http.StatusOK, map[string]any{
		"success":       true,
		"message":       fmt.Sprintf("Unresolved %d alert(s)", len(unresolvedIDs)),
		"unresolvedIds": unresolvedIDs,
	})
}
