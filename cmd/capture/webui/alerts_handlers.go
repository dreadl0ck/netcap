/*
 * NETCAP - Traffic Analysis Framework
 * Copyright (c) 2017-2020 Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
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
}

// GroupedAlert represents a deduplicated/grouped alert
type GroupedAlert struct {
	RuleName        string   `json:"ruleName"`
	Description     string   `json:"description"`
	Severity        string   `json:"severity"`
	RecordType      string   `json:"recordType"`
	Tags            []string `json:"tags"`
	MITRE           string   `json:"mitre"`
	RuleExpression  string   `json:"ruleExpression"`
	Threshold       int32    `json:"threshold"`
	ThresholdWindow int32    `json:"thresholdWindow"`
	Count           int      `json:"count"`
	FirstSeen       int64    `json:"firstSeen"`
	LastSeen        int64    `json:"lastSeen"`
	UniqueSrcIPs    []string `json:"uniqueSrcIPs"`
	UniqueDstIPs    []string `json:"uniqueDstIPs"`
	UniqueSrcPorts  []string `json:"uniqueSrcPorts"`
	UniqueDstPorts  []string `json:"uniqueDstPorts"`
	SampleAlerts    []AlertResponse `json:"sampleAlerts"` // Keep a few samples for detail view
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
		RespondJSON(w, http.StatusServiceUnavailable, map[string]interface{}{
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

		alerts = append(alerts, AlertResponse{
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
		})
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
		RespondJSON(w, http.StatusServiceUnavailable, map[string]interface{}{
			"error": "No output directory selected",
		})
		return
	}

	// Read alerts from the alerts audit record file
	alertsFile := filepath.Join(outDir, "Alert.ncap.gz")
	alerts, err := s.readAlertsFromFile(alertsFile)
	if err != nil {
		log.Printf("[WebUI] Failed to read alerts: %v", err)
		RespondJSON(w, http.StatusOK, map[string]interface{}{
			"totalAlerts":    0,
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

	for _, alert := range alerts {
		bySeverity[alert.Severity]++
		byRule[alert.RuleName]++
		if strings.EqualFold(alert.Severity, "critical") {
			criticalCount++
		}
	}

	// Get recent alerts (last 10)
	recentAlerts := make([]AlertResponse, 0)
	if len(alerts) > 0 {
		// Sort by timestamp descending
		sort.Slice(alerts, func(i, j int) bool {
			return alerts[i].Timestamp > alerts[j].Timestamp
		})

		count := 10
		if len(alerts) < count {
			count = len(alerts)
		}
		recentAlerts = alerts[:count]
	}

	RespondJSON(w, http.StatusOK, map[string]interface{}{
		"totalAlerts":    len(alerts),
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
		RespondJSON(w, http.StatusServiceUnavailable, map[string]interface{}{
			"error": "No output directory selected",
		})
		return
	}

	// Delete the alerts file
	alertsFile := filepath.Join(outDir, "Alert.ncap.gz")
	if err := os.Remove(alertsFile); err != nil && !os.IsNotExist(err) {
		log.Printf("[WebUI] Failed to delete alerts file: %v", err)
		RespondJSON(w, http.StatusInternalServerError, map[string]interface{}{
			"error": "Failed to clear alerts",
		})
		return
	}

	log.Printf("[WebUI] Cleared all alerts")

	RespondJSON(w, http.StatusOK, map[string]interface{}{
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
	sortBy := query.Get("sortBy") // "count", "lastSeen", "firstSeen", "severity"

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
		RespondJSON(w, http.StatusServiceUnavailable, map[string]interface{}{
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
			}
			groupMap[key] = group
		}

		// Update group statistics
		group.Count++
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
	var data map[string]interface{}
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
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

