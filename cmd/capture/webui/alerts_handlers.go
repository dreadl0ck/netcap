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
	"cmp"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math"
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

	// Kind is "finding" or "inventory"; alert views default to findings.
	Kind string `json:"kind"`

	// What a threshold, cardinality or detector alert counted.
	Count        uint64   `json:"count,omitempty"`
	FirstSeenNs  string   `json:"firstSeenNs,omitempty"`
	LastSeenNs   string   `json:"lastSeenNs,omitempty"`
	AggregateKey string   `json:"aggregateKey,omitempty"`
	Examples     []string `json:"examples,omitempty"`
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
	// UniqueValuesTruncated: a unique list stopped at maxGroupUniqueValues.
	UniqueValuesTruncated bool `json:"uniqueValuesTruncated,omitempty"`
}

// AlertsResponse represents the response containing multiple alerts
type AlertsResponse struct {
	Alerts                 []AlertResponse `json:"alerts"`
	TotalCount             int             `json:"totalCount"`
	SkippedOversizedAlerts int             `json:"skippedOversizedAlerts,omitempty"`
}

// GroupedAlertsResponse represents the response containing grouped/deduplicated alerts
type GroupedAlertsResponse struct {
	Groups                 []GroupedAlert `json:"groups"`
	TotalCount             int            `json:"totalCount"` // Total individual alerts
	GroupCount             int            `json:"groupCount"` // Number of unique groups
	SkippedOversizedAlerts int            `json:"skippedOversizedAlerts,omitempty"`
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
	if offset+limit > maxAlertListWindow {
		RespondJSON(w, http.StatusBadRequest, map[string]any{"error": fmt.Sprintf("offset+limit must not exceed %d; narrow with groupId, severity or ruleName", maxAlertListWindow)})
		return
	}
	groupFilter := query.Get("groupId")
	kindMatch, err := alertKindFilter(r)
	if err != nil {
		RespondJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}
	match := func(alert *types.Alert) bool {
		return kindMatch(alert) && (groupFilter == "" || generateGroupID(alert.RuleName, alert.Severity) == groupFilter) &&
			(severityFilter == "" || strings.EqualFold(alert.Severity, severityFilter)) &&
			(ruleNameFilter == "" || strings.EqualFold(alert.RuleName, ruleNameFilter))
	}
	window := newAlertWindow(offset+limit, sortOrder == "asc", alertListBudgetBytes)
	ctx, scanStats := withAlertScanStats(r.Context())
	totalCount := 0
	_, err = s.scanFilteredAlertAudit(ctx, alertsFile, 0, alertStatsScanRows, alertStatsFrameBytes, match, func(alert AlertResponse) error {
		totalCount++
		return window.add(alert)
	})
	if err != nil {
		s.respondAlertReadError(w, r.Context(), err)
		return
	}
	page := window.sorted()
	start := min(offset, len(page))
	page = page[start:min(len(page), start+limit)]
	w.Header().Set("X-Netcap-Skipped-Oversized-Alerts", strconv.Itoa(scanStats.skippedOversized))
	RespondJSON(w, http.StatusOK, AlertsResponse{
		Alerts:                 page,
		TotalCount:             totalCount,
		SkippedOversizedAlerts: scanStats.skippedOversized,
	})
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

func (s *Server) scanAlertAudit(ctx context.Context, filePath string, byteLimit, rowLimit, frameCap int, visit func(AlertResponse) error) ([]AlertResponse, error) {
	return s.scanFilteredAlertAudit(ctx, filePath, byteLimit, rowLimit, frameCap, nil, visit)
}

func (s *Server) scanFilteredAlertAudit(ctx context.Context, filePath string, byteLimit, rowLimit, frameCap int, match func(*types.Alert) bool, visit func(AlertResponse) error) ([]AlertResponse, error) {
	alerts := make([]AlertResponse, 0)
	err := s.walkAlertAudit(ctx, filePath, byteLimit, rowLimit, frameCap, func(alert *types.Alert, resolved *ResolvedAlertsStore) error {
		if match != nil && !match(alert) {
			return nil
		}
		response := resolvedAlertResponse(alert, resolved)
		if visit != nil {
			return visit(response)
		}
		alerts = append(alerts, response)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return alerts, nil
}

func resolvedAlertResponse(alert *types.Alert, store *ResolvedAlertsStore) AlertResponse {
	response := alertResponse(alert)
	response.Resolved, response.ResolvedAt = isAlertResolved(alert, response.AlertID, store)
	return response
}

func (s *Server) walkAlertAudit(ctx context.Context, filePath string, byteLimit, rowLimit, frameCap int, visit func(*types.Alert, *ResolvedAlertsStore) error) error {
	var reader *AuditRecordReader
	var opened os.FileInfo
	var err error
	if ctx == nil {
		reader, err = NewAuditRecordReader(filePath)
	} else {
		if err := ctx.Err(); err != nil {
			return err
		}
		file, info, openErr := artifactio.Open(filepath.Dir(filePath), filepath.Base(filePath))
		if openErr != nil {
			err = openErr
		} else if byteLimit > 0 && info.Size() > int64(byteLimit) {
			file.Close()
			return fmt.Errorf("%w: stored alert audit exceeds %d bytes", errAlertPageSourceLimit, byteLimit)
		} else {
			opened = info
			reader, err = auditRecordReaderFromInput(file, io.NewSectionReader(file, 0, info.Size()), true, func(in io.Reader) io.Reader {
				return auditContextReader{ctx: ctx, input: in}
			})
		}
	}
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("failed to open alerts file: %w", err)
	}
	defer reader.Close()

	// Read header to initialize reader
	header, err := reader.ReadHeader()
	if err != nil {
		return fmt.Errorf("failed to read header: %w", err)
	}
	if ctx != nil && header.Type != types.Type_NC_Alert {
		return fmt.Errorf("unexpected alert audit type %s", header.Type)
	}

	// Load resolved alerts
	outDir := filepath.Dir(filePath)
	var resolvedStore *ResolvedAlertsStore
	if ctx != nil {
		resolvedStore, err = s.loadPageResolvedAlerts(ctx, outDir)
		if err != nil {
			return err
		}
	} else {
		resolvedStore, err = s.loadResolvedAlerts(outDir)
		if err != nil {
			log.Printf("[WebUI] Failed to load resolved alerts: %v (continuing without resolved status)", err)
			resolvedStore = &ResolvedAlertsStore{Alerts: make(map[string]ResolvedAlert)}
		}
	}

	// byteLimit <= 0 lifts the decoded total; paged views stream every row and
	// only the row count and per-alert frame size bound the scan.
	remaining := byteLimit
	if byteLimit <= 0 {
		remaining = math.MaxInt
	}
	rows := 0

	// Read all records
	for {
		var record any
		if ctx == nil {
			record, err = reader.NextRecord()
		} else {
			if err := ctx.Err(); err != nil {
				return err
			}
			frameLimit := min(remaining, frameCap)
			if rows == rowLimit {
				frameLimit = 0
			}
			var raw []byte
			raw, err = reader.delimitedReader.NextWithLimit(uint64(max(frameLimit, 1)))
			var tooLarge *delimited.RecordLimitError
			switch {
			case rows == rowLimit && (err == nil || errors.As(err, &tooLarge)):
				return fmt.Errorf("%w: alert audit exceeds %d records", errAlertPageSourceLimit, rowLimit)
			case errors.As(err, &tooLarge) && tooLarge.Size > uint64(frameCap):
				// Older audits can hold alerts above the frame cap; skip and
				// count them rather than failing every view of the session.
				if err := reader.delimitedReader.Discard(tooLarge.Size); err != nil {
					return fmt.Errorf("failed to skip oversized alert record: %w", err)
				}
				rows++
				if stats, ok := ctx.Value(alertScanStatsKey{}).(*alertScanStats); ok {
					stats.skippedOversized++
				}
				continue
			case err == nil && len(raw) > frameCap:
				return fmt.Errorf("%w: an alert record exceeds %d bytes", errAlertPageSourceLimit, frameCap)
			case errors.As(err, &tooLarge) || err == nil && len(raw) > frameLimit:
				return fmt.Errorf("%w: decoded alert audit exceeds %d bytes", errAlertPageSourceLimit, byteLimit)
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
			return fmt.Errorf("failed to read alert record: %w", err)
		}

		// Type assert to Alert
		alert, ok := record.(*types.Alert)
		if !ok {
			log.Printf("[WebUI] Record is not an Alert type")
			continue
		}
		if err := visit(alert, resolvedStore); err != nil {
			return err
		}
	}

	if opened != nil {
		current, err := os.Lstat(filePath)
		if err != nil || !os.SameFile(opened, current) || opened.Size() != current.Size() || !opened.ModTime().Equal(current.ModTime()) {
			return errAlertAuditChanged
		}
	}
	return nil
}

const (
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
	recent := make([]*types.Alert, 0, 10)
	var resolved *ResolvedAlertsStore
	kindMatch, err := alertKindFilter(r)
	if err != nil {
		RespondJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}
	byKind := map[string]int{}
	scanCtx, scanStats := withAlertScanStats(r.Context())
	err = s.walkAlertAudit(scanCtx, alertsFile, 0, alertStatsScanRows, alertStatsFrameBytes, func(alert *types.Alert, store *ResolvedAlertsStore) error {
		resolved = store
		byKind[alertKind(alert)]++
		if !kindMatch(alert) {
			return nil
		}
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
		millis := alert.Timestamp / 1_000_000
		if len(recent) < cap(recent) || millis > recent[len(recent)-1].Timestamp/1_000_000 {
			insert := sort.Search(len(recent), func(i int) bool {
				return recent[i].Timestamp/1_000_000 < millis
			})
			if len(recent) < cap(recent) {
				recent = append(recent, nil)
			}
			copy(recent[insert+1:], recent[insert:])
			recent[insert] = alert
		}
		return nil
	})
	if err != nil {
		s.respondAlertReadError(w, r.Context(), err)
		return
	}

	recentAlerts := make([]json.RawMessage, 0, len(recent))
	remaining := alertStatsResponseBytes
	tooLarge := func() {
		s.respondAlertReadError(w, r.Context(), fmt.Errorf("%w: statistics response exceeds %d bytes", errAlertPageSourceLimit, alertStatsResponseBytes))
	}
	for _, alert := range recent {
		row, err := json.Marshal(resolvedAlertResponse(alert, resolved))
		if err != nil {
			s.respondAlertReadError(w, r.Context(), err)
			return
		}
		if len(row) > remaining {
			tooLarge()
			return
		}
		remaining -= len(row)
		recentAlerts = append(recentAlerts, row)
	}
	payload, err := json.Marshal(map[string]any{
		"totalAlerts":    total,
		"groupCount":     len(alertGroups),
		"bySeverity":     bySeverity,
		"byRule":         byRule,
		"recentAlerts":   recentAlerts,
		"criticalAlerts": criticalCount,
		"lastUpdate":     time.Now().Unix(),
		// Alerts above the frame limit in audits written before v0.16.14.
		"skippedOversizedAlerts": scanStats.skippedOversized,
		// Counts over every kind; the other fields follow ?kind.
		"byKind": byKind,
	})
	if err != nil {
		s.respondAlertReadError(w, r.Context(), err)
		return
	}
	if len(payload) > alertStatsResponseBytes {
		tooLarge()
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
		"success":     true,
		"message":     "All alerts cleared successfully",
		"messageI18n": requestUIMessage(r, "alerts.cleared", "All alerts cleared successfully", nil),
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
	if bounded {
		if _, err := parseCollectionPage(r); err != nil {
			RespondJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
	}
	budget := alertListBudgetBytes
	if bounded {
		budget = maxCollectionPageScanBytes
	}
	kindMatch, err := alertKindFilter(r)
	if err != nil {
		RespondJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}
	acc := newAlertGroups(budget)
	ctx, scanStats := withAlertScanStats(r.Context())
	_, err = s.scanFilteredAlertAudit(ctx, alertsFile, 0, alertStatsScanRows, alertStatsFrameBytes, kindMatch, func(alert AlertResponse) error {
		return acc.add(alert, severityFilter, ruleNameFilter)
	})
	if err != nil {
		s.respondAlertReadError(w, r.Context(), err)
		return
	}
	groups := acc.finish()
	w.Header().Set("X-Netcap-Skipped-Oversized-Alerts", strconv.Itoa(scanStats.skippedOversized))
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

	// Filtered here so groupCount and pages match what the UI shows.
	if query.Get("hideResolved") == "true" {
		open := groups[:0]
		for _, group := range groups {
			if !group.Resolved {
				open = append(open, group)
			}
		}
		groups = open
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
		respondFilteredCollectionPage(w, r, rows, "groups", map[string]any{"totalCount": totalCount, "groupCount": groupCount, "skippedOversizedAlerts": scanStats.skippedOversized})
		return
	}
	start := min(offset, groupCount)
	groups = groups[start : start+min(limit, groupCount-start)]

	RespondJSON(w, http.StatusOK, GroupedAlertsResponse{
		Groups:                 groups,
		TotalCount:             totalCount,
		GroupCount:             groupCount,
		SkippedOversizedAlerts: scanStats.skippedOversized,
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
	srcPort, dstPort := groupedAlertPorts(alert)
	values := [4]string{alert.SrcIP, alert.DstIP, srcPort, dstPort}
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
			if value != "" && !seen[i][value] && len(seen[i]) < maxGroupUniqueValues {
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

	// Collect unique IPs and ports; a flood group can have one per alert.
	for i, list := range []*[]string{&group.UniqueSrcIPs, &group.UniqueDstIPs, &group.UniqueSrcPorts, &group.UniqueDstPorts} {
		if values[i] != "" && !seen[i][values[i]] && len(seen[i]) >= maxGroupUniqueValues {
			group.UniqueValuesTruncated = true
			continue
		}
		appendGroupUnique(list, seen[i], values[i])
	}

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

func sortGroupedAlerts(groups []GroupedAlert, sortBy, sortOrder string) {
	severityRank := map[string]int{"critical": 4, "high": 3, "medium": 2, "low": 1}
	sort.Slice(groups, func(i, j int) bool {
		if sortOrder == "desc" {
			i, j = j, i
		}
		a, b := &groups[i], &groups[j]
		var order int
		switch sortBy {
		case "count":
			order = cmp.Compare(a.Count, b.Count)
		case "firstSeen":
			order = cmp.Compare(a.FirstSeen, b.FirstSeen)
		case "severity":
			order = cmp.Compare(severityRank[strings.ToLower(a.Severity)], severityRank[strings.ToLower(b.Severity)])
		default: // lastSeen
			return cmp.Or(cmp.Compare(a.LastSeen, b.LastSeen), cmp.Compare(a.Count, b.Count),
				cmp.Compare(a.RuleName, b.RuleName), cmp.Compare(a.Severity, b.Severity)) < 0
		}
		return cmp.Or(order, cmp.Compare(a.LastSeen, b.LastSeen),
			cmp.Compare(a.RuleName, b.RuleName), cmp.Compare(a.Severity, b.Severity)) < 0
	})
}

func groupedAlertPorts(alert AlertResponse) (src, dst string) {
	src, dst = alert.SrcPort, alert.DstPort
	if (src == "" || dst == "") && alert.MatchedRecord != "" {
		var record struct{ SrcPort, DstPort any }
		if json.Unmarshal([]byte(alert.MatchedRecord), &record) == nil {
			if src == "" && record.SrcPort != nil {
				src = fmt.Sprint(record.SrcPort)
			}
			if dst == "" && record.DstPort != nil {
				dst = fmt.Sprint(record.DstPort)
			}
		}
	}
	return src, dst
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

type alertScanStatsKey struct{}

// alertScanStats counts what a bounded alert scan left out.
type alertScanStats struct{ skippedOversized int }

func withAlertScanStats(ctx context.Context) (context.Context, *alertScanStats) {
	stats := &alertScanStats{}
	return context.WithValue(ctx, alertScanStatsKey{}, stats), stats
}
