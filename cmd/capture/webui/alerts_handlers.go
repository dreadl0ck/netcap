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
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/dreadl0ck/netcap/types"
)

// AlertResponse represents an alert for the API
type AlertResponse struct {
	Timestamp       int64    `json:"timestamp"`
	Name            string   `json:"name"`
	Description     string   `json:"description"`
	RuleName        string   `json:"ruleName"`
	RecordType      string   `json:"recordType"`
	Severity        string   `json:"severity"`
	Tags            []string `json:"tags"`
	MITRE           string   `json:"mitre"`
	SrcIP           string   `json:"srcIP"`
	DstIP           string   `json:"dstIP"`
	MatchedRecord   string   `json:"matchedRecord"`
	RuleExpression  string   `json:"ruleExpression"`
	Threshold       int32    `json:"threshold"`
	ThresholdWindow int32    `json:"thresholdWindow"`
	Resolved        bool     `json:"resolved"`
	ResolvedAt      int64    `json:"resolvedAt,omitempty"`
	AlertID         string   `json:"alertId"` // Unique identifier for the alert
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
	s.mu.RLock()
	outDir := s.outDir

	// In service mode, use the current session's output directory
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

	// Read alerts from the alerts audit record file
	alertsFile := filepath.Join(outDir, "Alert.ncap.gz")
	alerts, err := s.readAlertsFromFile(alertsFile)
	if err != nil {
		log.Printf("[WebUI] Failed to read alerts: %v", err)
		// Return empty list if file doesn't exist or can't be read
		RespondJSON(w, http.StatusOK, AlertsResponse{
			Alerts:     []AlertResponse{},
			TotalCount: 0,
		})
		return
	}

	// Apply filters
	filtered := make([]AlertResponse, 0)
	for _, alert := range alerts {
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
	// Check if file exists
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		return []AlertResponse{}, nil
	}

	// Open the audit record file
	reader, err := NewAuditRecordReader(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open alerts file: %w", err)
	}
	defer reader.Close()

	// Read header to initialize reader
	_, err = reader.ReadHeader()
	if err != nil {
		return nil, fmt.Errorf("failed to read header: %w", err)
	}

	// Load resolved alerts
	outDir := filepath.Dir(filePath)
	resolvedStore, err := s.loadResolvedAlerts(outDir)
	if err != nil {
		log.Printf("[WebUI] Failed to load resolved alerts: %v (continuing without resolved status)", err)
		resolvedStore = &ResolvedAlertsStore{Alerts: make(map[string]ResolvedAlert)}
	}

	alerts := make([]AlertResponse, 0)

	// Read all records
	for {
		record, err := reader.NextRecord()
		if err != nil {
			if err == io.EOF {
				break
			}
			log.Printf("[WebUI] Error reading alert record: %v", err)
			continue
		}

		// Type assert to Alert
		alert, ok := record.(*types.Alert)
		if !ok {
			log.Printf("[WebUI] Record is not an Alert type")
			continue
		}

		// Convert timestamp from nanoseconds to milliseconds for JavaScript
		timestampMs := alert.Timestamp / 1000000

		alertResp := AlertResponse{
			Timestamp:       timestampMs,
			Name:            alert.Name,
			Description:     alert.Description,
			RuleName:        alert.RuleName,
			RecordType:      alert.RecordType,
			Severity:        alert.Severity,
			Tags:            alert.Tags,
			MITRE:           alert.MITRE,
			SrcIP:           alert.SrcIP,
			DstIP:           alert.DstIP,
			MatchedRecord:   alert.MatchedRecord,
			RuleExpression:  alert.RuleExpression,
			Threshold:       alert.Threshold,
			ThresholdWindow: alert.ThresholdWindow,
		}

		// Generate alert ID
		alertResp.AlertID = generateAlertID(alertResp)

		// Check if resolved
		resolved, resolvedAt := isAlertResolved(alertResp.AlertID, resolvedStore)
		alertResp.Resolved = resolved
		alertResp.ResolvedAt = resolvedAt

		alerts = append(alerts, alertResp)
	}

	return alerts, nil
}

// handleAlertStats returns statistics about alerts
func (s *Server) handleAlertStats(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Determine the output directory
	s.mu.RLock()
	outDir := s.outDir

	// In service mode, use the current session's output directory
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

	// Read alerts from the alerts audit record file
	alertsFile := filepath.Join(outDir, "Alert.ncap.gz")
	alerts, err := s.readAlertsFromFile(alertsFile)
	if err != nil {
		log.Printf("[WebUI] Failed to read alerts: %v", err)
		RespondJSON(w, http.StatusOK, map[string]any{
			"totalAlerts":    0,
			"groupCount":     0,
			"bySeverity":     map[string]int{},
			"byRule":         map[string]int{},
			"recentAlerts":   []AlertResponse{},
			"criticalAlerts": 0,
		})
		return
	}

	// Calculate statistics
	bySeverity := make(map[string]int)
	byRule := make(map[string]int)
	criticalCount := 0
	// Track unique alert groups (rule + severity combinations)
	alertGroups := make(map[string]struct{})

	for _, alert := range alerts {
		bySeverity[alert.Severity]++
		byRule[alert.RuleName]++
		if strings.EqualFold(alert.Severity, "critical") {
			criticalCount++
		}
		// Create a unique key for each rule + severity combination
		groupKey := alert.RuleName + "|" + alert.Severity
		alertGroups[groupKey] = struct{}{}
	}

	// Get recent alerts (last 10)
	recentAlerts := make([]AlertResponse, 0)
	if len(alerts) > 0 {
		// Sort by timestamp descending
		sort.Slice(alerts, func(i, j int) bool {
			return alerts[i].Timestamp > alerts[j].Timestamp
		})

		count := min(len(alerts), 10)
		recentAlerts = alerts[:count]
	}

	RespondJSON(w, http.StatusOK, map[string]any{
		"totalAlerts":    len(alerts),
		"groupCount":     len(alertGroups),
		"bySeverity":     bySeverity,
		"byRule":         byRule,
		"recentAlerts":   recentAlerts,
		"criticalAlerts": criticalCount,
		"lastUpdate":     time.Now().Unix(),
	})
}

// handleClearAlerts handles requests to clear all alerts
func (s *Server) handleClearAlerts(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Determine the output directory
	s.mu.RLock()
	outDir := s.outDir

	// In service mode, use the current session's output directory
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

	// Delete the alerts file
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
	s.mu.RLock()
	outDir := s.outDir

	// In service mode, use the current session's output directory
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

	// Read alerts from the alerts audit record file
	alertsFile := filepath.Join(outDir, "Alert.ncap.gz")
	alerts, err := s.readAlertsFromFile(alertsFile)
	if err != nil {
		log.Printf("[WebUI] Failed to read alerts: %v", err)
		// Return empty list if file doesn't exist or can't be read
		RespondJSON(w, http.StatusOK, GroupedAlertsResponse{
			Groups:     []GroupedAlert{},
			TotalCount: 0,
			GroupCount: 0,
		})
		return
	}

	// Group alerts
	groups := groupAlerts(alerts, severityFilter, ruleNameFilter)

	// Sort groups
	sortGroupedAlerts(groups, sortBy, sortOrder)

	// Apply pagination
	totalCount := 0
	for _, g := range groups {
		totalCount += g.Count
	}
	groupCount := len(groups)
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
	type groupKey struct {
		ruleName string
		severity string
	}

	groupMap := make(map[groupKey]*GroupedAlert)

	for _, alert := range alerts {
		// Apply filters
		if severityFilter != "" && !strings.EqualFold(alert.Severity, severityFilter) {
			continue
		}
		if ruleNameFilter != "" && !strings.EqualFold(alert.RuleName, ruleNameFilter) {
			continue
		}

		key := groupKey{
			ruleName: alert.RuleName,
			severity: alert.Severity,
		}

		group, exists := groupMap[key]
		if !exists {
			group = &GroupedAlert{
				RuleName:        alert.RuleName,
				Description:     alert.Description,
				Severity:        alert.Severity,
				RecordType:      alert.RecordType,
				Tags:            alert.Tags,
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
			groupMap[key] = group
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
		if alert.SrcIP != "" && !contains(group.UniqueSrcIPs, alert.SrcIP) {
			group.UniqueSrcIPs = append(group.UniqueSrcIPs, alert.SrcIP)
		}
		if alert.DstIP != "" && !contains(group.UniqueDstIPs, alert.DstIP) {
			group.UniqueDstIPs = append(group.UniqueDstIPs, alert.DstIP)
		}

		// Add source port if it exists in the matched record or is captured
		srcPort := extractPort(alert, "SrcPort")
		if srcPort != "" && !contains(group.UniqueSrcPorts, srcPort) {
			group.UniqueSrcPorts = append(group.UniqueSrcPorts, srcPort)
		}

		// Add destination port if it exists
		dstPort := extractPort(alert, "DstPort")
		if dstPort != "" && !contains(group.UniqueDstPorts, dstPort) {
			group.UniqueDstPorts = append(group.UniqueDstPorts, dstPort)
		}

		// Keep up to 5 sample alerts for detail view
		if len(group.SampleAlerts) < 5 {
			group.SampleAlerts = append(group.SampleAlerts, alert)
		}
	}

	// Convert map to slice
	result := make([]GroupedAlert, 0, len(groupMap))
	for _, group := range groupMap {
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

// contains checks if a string slice contains a specific string
func contains(slice []string, item string) bool {
	return slices.Contains(slice, item)
}

// generateAlertID generates a unique identifier for an alert
func generateAlertID(alert AlertResponse) string {
	// Use combination of rule name, timestamp, srcIP, dstIP to create unique ID
	return fmt.Sprintf("%s-%d-%s-%s", alert.RuleName, alert.Timestamp, alert.SrcIP, alert.DstIP)
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
