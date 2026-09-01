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
	"reflect"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/dreadl0ck/netcap/defaults"
	"github.com/dreadl0ck/netcap/types"
)

// HandleChartData returns a handler that generates charts for a specific output directory (for service mode)
func HandleChartData(outDir string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		// Parse query parameters
		auditType := r.URL.Query().Get("type")
		field := r.URL.Query().Get("field")
		chartType := r.URL.Query().Get("chartType")
		interval := r.URL.Query().Get("interval")
		showLegendStr := r.URL.Query().Get("showLegend")
		maxDataPointsStr := r.URL.Query().Get("maxDataPoints")

		if auditType == "" || field == "" {
			http.Error(w, "Missing required parameters: type, field", http.StatusBadRequest)
			return
		}

		if chartType == "" {
			chartType = "line"
		}

		// Parse showLegend (default to true)
		showLegend := true
		if showLegendStr != "" && showLegendStr != "true" {
			showLegend = false
		}

		// Parse maxDataPoints (default to 1000)
		maxDataPoints := 1000
		if maxDataPointsStr != "" {
			if parsed, err := strconv.Atoi(maxDataPointsStr); err == nil && parsed > 0 {
				maxDataPoints = parsed
			}
		}

		// No default interval - empty means use all records with actual timestamps

		// Generate chart using go-echarts
		generator := NewChartGenerator(auditType, field, chartType, interval, showLegend, maxDataPoints)
		chartHTML, err := generator.GenerateChart(outDir)
		if err != nil {
			log.Printf("[WebUI] Failed to generate chart: %v", err)
			http.Error(w, fmt.Sprintf("Failed to generate chart: %v", err), http.StatusInternalServerError)
			return
		}

		// Serve HTML
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if _, err := io.Copy(w, chartHTML); err != nil {
			log.Printf("[WebUI] Failed to write chart HTML: %v", err)
		}
	}
}

// HandleChartFields returns a handler that returns available fields for a specific output directory (for service mode)
func HandleChartFields(outDir string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		auditType := r.URL.Query().Get("type")
		if auditType == "" {
			http.Error(w, "Missing required parameter: type", http.StatusBadRequest)
			return
		}

		// Construct file path
		filePath := filepath.Join(outDir, auditType+defaults.FileExtension+".gz")

		// Read up to 100 records to get field information
		reader, err := NewAuditRecordReader(filePath)
		if err != nil {
			http.Error(w, fmt.Sprintf("Failed to open audit file: %v", err), http.StatusInternalServerError)
			return
		}
		defer reader.Close()

		// Read header
		_, err = reader.ReadHeader()
		if err != nil {
			http.Error(w, fmt.Sprintf("Failed to read header: %v", err), http.StatusInternalServerError)
			return
		}

		// Read up to 100 records to inspect fields across multiple records
		fields, totalFields := extractAllFieldsAcrossRecords(reader, 100)

		response := ChartFieldsResponse{
			Type:          auditType,
			Fields:        fields,
			TotalFields:   totalFields,
			FilteredCount: totalFields - len(fields),
		}

		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(response); err != nil {
			log.Printf("[WebUI] Failed to encode chart fields response: %v", err)
			http.Error(w, fmt.Sprintf("Failed to encode response: %v", err), http.StatusInternalServerError)
		}
	}
}

// ChartDataPoint represents a single data point in a chart
type ChartDataPoint struct {
	Timestamp int64   `json:"timestamp"`
	Value     float64 `json:"value"`
}

// ChartDataResponse contains the chart data and metadata
type ChartDataResponse struct {
	Type     string           `json:"type"`
	Field    string           `json:"field"`
	Interval string           `json:"interval"`
	Data     []ChartDataPoint `json:"data"`
	Count    int              `json:"count"`
	MinValue float64          `json:"minValue"`
	MaxValue float64          `json:"maxValue"`
	AvgValue float64          `json:"avgValue"`
}

// ChartFieldsResponse lists available numeric fields for charting
type ChartFieldsResponse struct {
	Type          string           `json:"type"`
	Fields        []ChartFieldInfo `json:"fields"`
	TotalFields   int              `json:"totalFields"`   // Total possible fields including empty ones
	FilteredCount int              `json:"filteredCount"` // Number of fields filtered out due to no data
}

// ChartFieldInfo represents metadata about a field for charting
type ChartFieldInfo struct {
	Name        string `json:"name"`
	Type        string `json:"type"`
	Description string `json:"description"`
}

// resolveChartScopeDirs returns one or more output directories matching the
// requested scope. Possible scope values:
//   - "" or "current": the currently-active output dir (legacy behavior).
//   - "all": every completed session/file's output dir.
//   - any other value: treated as a pcap selector (session id in service mode,
//     or input file path / id in local mode).
//
// The returned status is the HTTP status to use if err is non-nil.
func (s *Server) resolveChartScopeDirs(scope string, r *http.Request) ([]string, int, error) {
	s.mu.RLock()
	isServiceMode := s.isServiceMode
	currentSession := s.currentSession
	outDir := s.outDir
	baseOutDir := s.baseOutDir
	inputFiles := append([]string(nil), s.inputFiles...)
	fileOutputDirs := make(map[string]string, len(s.fileOutputDirs))
	for k, v := range s.fileOutputDirs {
		fileOutputDirs[k] = v
	}
	fileIDToPath := make(map[string]string, len(s.fileIDToPath))
	for k, v := range s.fileIDToPath {
		fileIDToPath[k] = v
	}
	s.mu.RUnlock()

	// Helper: derive an output dir for an input file in local mode
	deriveLocalOutDir := func(inputFile string) string {
		if dir, ok := fileOutputDirs[inputFile]; ok {
			return dir
		}
		if len(inputFiles) == 1 {
			return baseOutDir
		}
		base := filepath.Base(inputFile)
		for _, ext := range []string{".pcap", ".pcapng", ".cap", ".dmp"} {
			if before, ok := strings.CutSuffix(base, ext); ok {
				base = before
				break
			}
		}
		return filepath.Join(baseOutDir, base)
	}

	switch scope {
	case "", "current":
		dir := outDir
		if isServiceMode && currentSession != "" && s.sessionManager != nil {
			if sess, ok := s.sessionManager.GetSession(currentSession); ok {
				dir = sess.OutputDir
			}
		}
		if dir == "" {
			return nil, http.StatusServiceUnavailable, fmt.Errorf("no output directory available")
		}
		return []string{dir}, http.StatusOK, nil
	case "all":
		var dirs []string
		seen := make(map[string]bool)
		add := func(d string) {
			if d == "" || seen[d] {
				return
			}
			seen[d] = true
			dirs = append(dirs, d)
		}
		if isServiceMode && s.sessionManager != nil {
			// Own sessions plus the preloaded demo pcaps -- never every
			// visitor's uploads, which is what GetAllSessions would return.
			for _, sess := range s.sessionManager.GetAccessibleSessions(s.getUserIP(r)) {
				if sess.Status == StatusCompleted && sess.OutputDir != "" {
					add(sess.OutputDir)
				}
			}
		} else {
			for _, in := range inputFiles {
				add(deriveLocalOutDir(in))
			}
			if len(dirs) == 0 && outDir != "" {
				add(outDir)
			}
		}
		if len(dirs) == 0 {
			return nil, http.StatusServiceUnavailable, fmt.Errorf("no completed captures available")
		}
		return dirs, http.StatusOK, nil
	default:
		// Treat scope as a pcap identifier. Accept several forms because the
		// frontend may send any of: session id, full input file path, or just
		// the file's basename.
		if isServiceMode && s.sessionManager != nil {
			clientIP := s.getUserIP(r)

			// Direct session-id lookup is the cheapest, but must still be
			// ownership-checked: GetSession resolves any id in the manager, so
			// without this a visitor holding another visitor's session id could
			// chart their capture.
			if sess, ok := s.sessionManager.GetSession(scope); ok {
				if !sess.IsPreloaded && sess.IP != clientIP {
					return nil, http.StatusNotFound, fmt.Errorf("unknown scope: %s", scope)
				}
				if sess.OutputDir == "" {
					return nil, http.StatusNotFound, fmt.Errorf("session has no output directory yet")
				}
				return []string{sess.OutputDir}, http.StatusOK, nil
			}
			// Fall back to scanning: PcapsPage / scope selector uses InputFile
			// (full path) as the value, so match by InputFile, InputFilename,
			// and basename. Scoped to accessible sessions -- matching on
			// basename across every session let one visitor read another's
			// capture by guessing an ordinary filename.
			scopeBase := filepath.Base(scope)
			for _, sess := range s.sessionManager.GetAccessibleSessions(clientIP) {
				if sess.OutputDir == "" {
					continue
				}
				if sess.InputFile == scope || sess.InputFilename == scope ||
					filepath.Base(sess.InputFile) == scopeBase {
					return []string{sess.OutputDir}, http.StatusOK, nil
				}
			}
		}
		// Local mode: scope may be a file path, file id, or basename.
		if path, ok := fileIDToPath[scope]; ok {
			return []string{deriveLocalOutDir(path)}, http.StatusOK, nil
		}
		for _, in := range inputFiles {
			if in == scope || filepath.Base(in) == scope {
				return []string{deriveLocalOutDir(in)}, http.StatusOK, nil
			}
		}
		return nil, http.StatusNotFound, fmt.Errorf("unknown scope: %s", scope)
	}
}

// handleChartData generates and serves HTML charts using go-echarts
func (s *Server) handleChartData(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Parse query parameters
	auditType := r.URL.Query().Get("type")
	field := r.URL.Query().Get("field")
	chartType := r.URL.Query().Get("chartType") // line, bar, area, scatter, pie
	interval := r.URL.Query().Get("interval")   // e.g., "1s", "1m", "1h"
	showLegendStr := r.URL.Query().Get("showLegend")
	maxDataPointsStr := r.URL.Query().Get("maxDataPoints")
	scope := r.URL.Query().Get("scope") // "all", "current" (default), or pcap id/path

	if auditType == "" || field == "" {
		http.Error(w, "Missing required parameters: type, field", http.StatusBadRequest)
		return
	}

	if chartType == "" {
		chartType = "line" // default to line chart
	}

	// Parse showLegend (default to true)
	showLegend := true
	if showLegendStr != "" && showLegendStr != "true" {
		showLegend = false
	}

	// Parse maxDataPoints (default to 1000)
	maxDataPoints := 1000
	if maxDataPointsStr != "" {
		if parsed, err := strconv.Atoi(maxDataPointsStr); err == nil && parsed > 0 {
			maxDataPoints = parsed
		}
	}

	dirs, status, err := s.resolveChartScopeDirs(scope, r)
	if err != nil {
		log.Printf("[WebUI] chart: scope %q resolution failed: %v", scope, err)
		http.Error(w, err.Error(), status)
		return
	}

	// format=json: skip HTML rendering and return the raw time-series
	// data directly. Used by the MCP chart_data tool and any non-browser
	// caller that wants the numbers (not the chart). Default interval is
	// 1s when omitted, mirroring the HTML path's go-echarts default.
	if r.URL.Query().Get("format") == "json" {
		intervalForJSON := interval
		if intervalForJSON == "" {
			intervalForJSON = "1s"
		}
		merged, err := s.aggregateChartDataAcrossDirs(dirs, auditType, field, intervalForJSON, maxDataPoints)
		if err != nil {
			log.Printf("[WebUI] chart json: aggregate failed (type=%s field=%s scope=%s): %v",
				auditType, field, scope, err)
			http.Error(w, fmt.Sprintf("Failed to aggregate chart data: %v", err), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(merged); err != nil {
			log.Printf("[WebUI] chart json: encode failed: %v", err)
		}
		return
	}

	// Generate chart using go-echarts
	start := time.Now()
	generator := NewChartGenerator(auditType, field, chartType, interval, showLegend, maxDataPoints)
	chartHTML, err := generator.GenerateChartFromDirs(dirs)
	if err != nil {
		log.Printf("[WebUI] Failed to generate chart (type=%s field=%s scope=%s dirs=%d): %v", auditType, field, scope, len(dirs), err)
		http.Error(w, fmt.Sprintf("Failed to generate chart: %v", err), http.StatusInternalServerError)
		return
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		log.Printf("[WebUI] chart: slow generation (type=%s field=%s scope=%s dirs=%d) took %s", auditType, field, scope, len(dirs), elapsed)
	}

	// Serve HTML
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if _, err := io.Copy(w, chartHTML); err != nil {
		log.Printf("[WebUI] Failed to write chart HTML: %v", err)
	}
}

// aggregateChartDataAcrossDirs runs the existing per-file chart-data
// extractor across every directory selected by the scope resolver and
// merges the time-series. The result is the raw ChartDataResponse the
// React frontend would otherwise compute client-side from the HTML.
//
// When dirs is empty or no usable data is found we return an empty
// (zero-record) response rather than an error so callers can distinguish
// "no data" from "couldn't open file".
func (s *Server) aggregateChartDataAcrossDirs(dirs []string, auditType, field, interval string, maxDataPoints int) (*ChartDataResponse, error) {
	merged := &ChartDataResponse{
		Type:     auditType,
		Field:    field,
		Interval: interval,
		Data:     []ChartDataPoint{},
	}
	if len(dirs) == 0 {
		return merged, nil
	}
	buckets := map[int64]float64{} // timestamp -> sum of values
	var minVal, maxVal, total float64
	first := true

	for _, dir := range dirs {
		filePath := filepath.Join(dir, auditType+".ncap.gz")
		if _, statErr := os.Stat(filePath); statErr != nil {
			continue // tolerate missing per-type files
		}
		resp, err := s.extractChartData(filePath, auditType, field, interval)
		if err != nil {
			return nil, err
		}
		for _, p := range resp.Data {
			buckets[p.Timestamp] += p.Value
		}
		merged.Count += resp.Count
		total += resp.AvgValue * float64(resp.Count)
		if first || resp.MinValue < minVal {
			minVal = resp.MinValue
		}
		if first || resp.MaxValue > maxVal {
			maxVal = resp.MaxValue
		}
		first = false
	}

	// Materialise + sort the merged buckets.
	keys := make([]int64, 0, len(buckets))
	for k := range buckets {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i] < keys[j] })

	// Down-sample uniformly when over the cap (matches the HTML path's
	// max-data-points contract).
	if maxDataPoints > 0 && len(keys) > maxDataPoints {
		step := float64(len(keys)) / float64(maxDataPoints)
		out := make([]int64, 0, maxDataPoints)
		for i := 0; i < maxDataPoints; i++ {
			out = append(out, keys[int(float64(i)*step)])
		}
		keys = out
	}

	merged.Data = make([]ChartDataPoint, 0, len(keys))
	for _, k := range keys {
		merged.Data = append(merged.Data, ChartDataPoint{Timestamp: k, Value: buckets[k]})
	}
	merged.MinValue = minVal
	merged.MaxValue = maxVal
	if merged.Count > 0 {
		merged.AvgValue = total / float64(merged.Count)
	}
	return merged, nil
}

// extractChartData reads audit records and extracts time-series data for the specified field
func (s *Server) extractChartData(filePath, auditType, fieldName, intervalStr string) (*ChartDataResponse, error) {
	reader, err := NewAuditRecordReader(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open audit file: %w", err)
	}
	defer reader.Close()

	// Read header
	_, err = reader.ReadHeader()
	if err != nil {
		return nil, fmt.Errorf("failed to read header: %w", err)
	}

	// Parse interval
	duration, err := time.ParseDuration(intervalStr)
	if err != nil {
		return nil, fmt.Errorf("invalid interval: %w", err)
	}

	// Map to aggregate values by time bucket
	timeBuckets := make(map[int64][]float64)
	var minValue, maxValue, sum float64
	minValue = -1
	totalCount := 0

	// Read all records and extract field values
	for {
		msg, err := reader.NextRecord()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("failed to read record: %w", err)
		}

		// Get timestamp - all audit records implement Time() method
		var timestamp int64
		if ar, ok := msg.(types.AuditRecord); ok {
			timestamp = ar.Time()
		} else {
			continue
		}

		// Extract field value using reflection
		value, err := extractNumericField(msg, fieldName)
		if err != nil {
			continue // Skip records where field extraction fails
		}

		// Calculate time bucket
		bucket := (timestamp / int64(duration)) * int64(duration)

		// Add value to bucket
		timeBuckets[bucket] = append(timeBuckets[bucket], value)

		// Update statistics
		if minValue == -1 || value < minValue {
			minValue = value
		}
		if value > maxValue {
			maxValue = value
		}
		sum += value
		totalCount++
	}

	if totalCount == 0 {
		return nil, fmt.Errorf("no records found with valid numeric field %s", fieldName)
	}

	// Aggregate buckets
	var dataPoints []ChartDataPoint
	for bucket, values := range timeBuckets {
		// Calculate average for the bucket
		var bucketSum float64
		for _, v := range values {
			bucketSum += v
		}
		avg := bucketSum / float64(len(values))

		dataPoints = append(dataPoints, ChartDataPoint{
			Timestamp: bucket,
			Value:     avg,
		})
	}

	// Sort by timestamp
	sort.Slice(dataPoints, func(i, j int) bool {
		return dataPoints[i].Timestamp < dataPoints[j].Timestamp
	})

	avgValue := sum / float64(totalCount)

	return &ChartDataResponse{
		Type:     auditType,
		Field:    fieldName,
		Interval: intervalStr,
		Data:     dataPoints,
		Count:    len(dataPoints),
		MinValue: minValue,
		MaxValue: maxValue,
		AvgValue: avgValue,
	}, nil
}

// extractNumericField uses reflection to extract a numeric field from a message
// Supports nested field access using dot notation (e.g., "ReqCookies.Name")
func extractNumericField(msg any, fieldPath string) (float64, error) {
	v := reflect.ValueOf(msg)

	// Handle pointer
	if v.Kind() == reflect.Pointer {
		v = v.Elem()
	}

	if v.Kind() != reflect.Struct {
		return 0, fmt.Errorf("message is not a struct")
	}

	// Navigate through nested fields using dot notation
	field, err := navigateToField(v, fieldPath)
	if err != nil {
		return 0, err
	}

	// Convert to float64 based on type
	switch field.Kind() {
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return float64(field.Int()), nil
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return float64(field.Uint()), nil
	case reflect.Float32, reflect.Float64:
		return field.Float(), nil
	case reflect.Bool:
		if field.Bool() {
			return 1.0, nil
		}
		return 0.0, nil
	default:
		return 0, fmt.Errorf("field %s is not a numeric type", fieldPath)
	}
}

// navigateToField navigates through nested struct fields using dot notation
// For slice fields, it takes the first element
// For map fields, it uses the next part as the map key
func navigateToField(v reflect.Value, fieldPath string) (reflect.Value, error) {
	parts := strings.Split(fieldPath, ".")

	for i := 0; i < len(parts); i++ {
		part := parts[i]

		// Handle pointer
		if v.Kind() == reflect.Pointer {
			if v.IsNil() {
				return reflect.Value{}, fmt.Errorf("nil pointer at %s", strings.Join(parts[:i+1], "."))
			}
			v = v.Elem()
		}

		// Handle slice - take first element if slice is not empty
		if v.Kind() == reflect.Slice {
			if v.Len() == 0 {
				return reflect.Value{}, fmt.Errorf("empty slice at %s", strings.Join(parts[:i], "."))
			}
			v = v.Index(0)

			// Handle pointer in slice element
			if v.Kind() == reflect.Pointer {
				if v.IsNil() {
					return reflect.Value{}, fmt.Errorf("nil pointer in slice at %s", strings.Join(parts[:i], "."))
				}
				v = v.Elem()
			}
		}

		if v.Kind() != reflect.Struct {
			return reflect.Value{}, fmt.Errorf("not a struct at %s", strings.Join(parts[:i], "."))
		}

		// Find field by name
		field := v.FieldByName(part)
		if !field.IsValid() {
			return reflect.Value{}, fmt.Errorf("field %s not found", strings.Join(parts[:i+1], "."))
		}

		// Check if this field is a map and we have more parts
		if field.Kind() == reflect.Map && i+1 < len(parts) {
			// The next part is the map key
			mapKey := parts[i+1]
			keyValue := reflect.ValueOf(mapKey)

			// Look up the value in the map
			mapValue := field.MapIndex(keyValue)
			if !mapValue.IsValid() {
				return reflect.Value{}, fmt.Errorf("map key %s not found in %s", mapKey, part)
			}

			// Skip the next part since we used it as the map key
			i++
			// If this was the last part, we're done
			if i == len(parts)-1 {
				return mapValue, nil
			}

			// Continue with the map value
			v = mapValue
			continue
		}

		v = field
	}

	return v, nil
}

// handleChartFields returns available numeric fields for a given audit record type
func (s *Server) handleChartFields(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	auditType := r.URL.Query().Get("type")
	if auditType == "" {
		http.Error(w, "Missing required parameter: type", http.StatusBadRequest)
		return
	}
	scope := r.URL.Query().Get("scope")

	dirs, status, err := s.resolveChartScopeDirs(scope, r)
	if err != nil {
		log.Printf("[WebUI] chart fields: scope %q resolution failed: %v", scope, err)
		http.Error(w, err.Error(), status)
		return
	}

	// Field schema is identical across captures, so probe the first dir that
	// actually has the file.
	var reader *AuditRecordReader
	var lastErr error
	for _, dir := range dirs {
		filePath := filepath.Join(dir, auditType+defaults.FileExtension+".gz")
		r2, err := NewAuditRecordReader(filePath)
		if err != nil {
			lastErr = err
			continue
		}
		reader = r2
		break
	}
	if reader == nil {
		http.Error(w, fmt.Sprintf("Failed to open audit file in any scope dir: %v", lastErr), http.StatusInternalServerError)
		return
	}
	defer reader.Close()

	// Read header
	_, err = reader.ReadHeader()
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to read header: %v", err), http.StatusInternalServerError)
		return
	}

	// Read up to 100 records to inspect fields across multiple records
	fields, totalFields := extractAllFieldsAcrossRecords(reader, 100)

	response := ChartFieldsResponse{
		Type:          auditType,
		Fields:        fields,
		TotalFields:   totalFields,
		FilteredCount: totalFields - len(fields),
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(response); err != nil {
		log.Printf("[WebUI] Failed to encode chart fields response: %v", err)
		http.Error(w, fmt.Sprintf("Failed to encode response: %v", err), http.StatusInternalServerError)
	}
}

// extractAllFields returns a list of all chartable fields (numeric and string) from a struct
// This includes nested fields using dot notation (e.g., "ReqCookies.Name")
// and map keys (e.g., "RequestHeader.Accept", "RequestHeader.Content-Type")
func extractAllFields(msg any) []ChartFieldInfo {
	fields, _ := extractAllFieldsWithCount(msg)
	return fields
}

// extractAllFieldsWithCount returns a list of all chartable fields and the total count including filtered fields
// extractAllFieldsAcrossRecords reads up to maxRecords records and collects all fields that have values in any of those records
func extractAllFieldsAcrossRecords(reader *AuditRecordReader, maxRecords int) ([]ChartFieldInfo, int) {
	// Use a map to track unique fields found across all records
	fieldMap := make(map[string]ChartFieldInfo)
	var totalCount int
	recordsRead := 0

	for recordsRead < maxRecords {
		msg, err := reader.NextRecord()
		if err != nil {
			if err == io.EOF {
				break // End of file reached
			}
			log.Printf("[WebUI] Error reading record %d: %v", recordsRead+1, err)
			break
		}

		// Extract fields from this record
		fields, total := extractAllFieldsWithCount(msg)

		// Use the total count from the first record (structure should be consistent)
		if recordsRead == 0 {
			totalCount = total
		}

		// Add all found fields to the map (union of all fields found)
		for _, field := range fields {
			if _, exists := fieldMap[field.Name]; !exists {
				fieldMap[field.Name] = field
			}
		}

		recordsRead++
	}

	// Convert map to slice and sort by name for consistent output
	result := make([]ChartFieldInfo, 0, len(fieldMap))
	for _, field := range fieldMap {
		result = append(result, field)
	}

	sort.Slice(result, func(i, j int) bool {
		return result[i].Name < result[j].Name
	})

	log.Printf("[WebUI] Extracted fields from %d records: found %d fields with data out of %d total fields",
		recordsRead, len(result), totalCount)

	return result, totalCount
}

func extractAllFieldsWithCount(msg any) ([]ChartFieldInfo, int) {
	var fields []ChartFieldInfo
	var totalCount int

	v := reflect.ValueOf(msg)
	if v.Kind() == reflect.Pointer {
		v = v.Elem()
	}

	if v.Kind() != reflect.Struct {
		return fields, totalCount
	}

	// Extract fields recursively, tracking both populated and total fields
	extractFieldsRecursive(v, "", &fields, &totalCount, 0, 3) // max depth of 3 to prevent infinite recursion

	return fields, totalCount
}

// extractFieldsRecursive recursively extracts fields from a struct, including nested structs, slices of structs, and map keys
// Also counts total possible fields including those filtered out
func extractFieldsRecursive(v reflect.Value, prefix string, fields *[]ChartFieldInfo, totalCount *int, depth int, maxDepth int) {
	if depth >= maxDepth {
		return
	}

	if v.Kind() == reflect.Pointer {
		if v.IsNil() {
			// Try to create a zero value to inspect its structure
			v = reflect.New(v.Type().Elem()).Elem()
		} else {
			v = v.Elem()
		}
	}

	if v.Kind() != reflect.Struct {
		return
	}

	t := v.Type()
	for i := 0; i < v.NumField(); i++ {
		field := v.Field(i)
		fieldType := t.Field(i)

		// Skip unexported fields
		if !fieldType.IsExported() {
			continue
		}

		fieldName := fieldType.Name
		if prefix != "" {
			fieldName = prefix + "." + fieldName
		}

		// Check field type and categorize
		typeName := ""
		isChartable := false
		shouldRecurse := false
		isPotentialField := false // Tracks if this is a chartable type, regardless of data

		switch field.Kind() {
		case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
			isPotentialField = true
			// Only include if non-zero or we're inspecting structure
			if field.Int() != 0 || v.IsZero() {
				typeName = "numeric (integer)"
				isChartable = true
			}
		case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
			isPotentialField = true
			if field.Uint() != 0 || v.IsZero() {
				typeName = "numeric (unsigned)"
				isChartable = true
			}
		case reflect.Float32, reflect.Float64:
			isPotentialField = true
			if field.Float() != 0 || v.IsZero() {
				typeName = "numeric (float)"
				isChartable = true
			}
		case reflect.Bool:
			isPotentialField = true
			typeName = "categorical (boolean)"
			isChartable = true
		case reflect.String:
			isPotentialField = true
			// Only include if non-empty or we're inspecting structure
			if field.String() != "" || v.IsZero() {
				typeName = "categorical (string)"
				isChartable = true
			}
		case reflect.Map:
			// Handle maps by extracting keys from actual data
			if field.Len() > 0 {
				// Map has data - extract keys
				for _, key := range field.MapKeys() {
					mapKeyName := fieldName + "." + key.String()
					mapValue := field.MapIndex(key)

					// Determine type of map values
					var mapTypeName string
					switch mapValue.Kind() {
					case reflect.String:
						if mapValue.String() != "" {
							mapTypeName = "categorical (string)"
						}
					case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
						if mapValue.Int() != 0 {
							mapTypeName = "numeric (integer)"
						}
					case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
						if mapValue.Uint() != 0 {
							mapTypeName = "numeric (unsigned)"
						}
					case reflect.Float32, reflect.Float64:
						if mapValue.Float() != 0 {
							mapTypeName = "numeric (float)"
						}
					case reflect.Bool:
						mapTypeName = "categorical (boolean)"
					}

					if mapTypeName != "" {
						*fields = append(*fields, ChartFieldInfo{
							Name:        mapKeyName,
							Type:        mapTypeName,
							Description: getFieldDescription(mapKeyName),
						})
					}
				}
				shouldRecurse = true // Skip adding the map itself as a field
			}
		case reflect.Slice:
			elemType := field.Type().Elem()
			if elemType.Kind() == reflect.String {
				isPotentialField = true
				// Only include if slice has data
				if field.Len() > 0 || v.IsZero() {
					typeName = "categorical (string array)"
					isChartable = true
				}
			} else if elemType.Kind() == reflect.Struct || (elemType.Kind() == reflect.Pointer && elemType.Elem().Kind() == reflect.Struct) {
				// Slice of structs - recurse into the first element if available, or a zero value
				shouldRecurse = true
				var elemValue reflect.Value
				if field.Len() > 0 {
					elemValue = field.Index(0)
					if elemValue.Kind() == reflect.Pointer {
						if !elemValue.IsNil() {
							elemValue = elemValue.Elem()
						} else {
							// Create zero value for inspection
							elemValue = reflect.New(elemType.Elem()).Elem()
						}
					}
				} else if v.IsZero() {
					// Creating zero value for structure inspection
					if elemType.Kind() == reflect.Pointer {
						elemValue = reflect.New(elemType.Elem()).Elem()
					} else {
						elemValue = reflect.New(elemType).Elem()
					}
				}
				if elemValue.IsValid() {
					extractFieldsRecursive(elemValue, fieldName, fields, totalCount, depth+1, maxDepth)
				}
			}
		case reflect.Struct:
			// Nested struct - recurse into it
			shouldRecurse = true
			extractFieldsRecursive(field, fieldName, fields, totalCount, depth+1, maxDepth)
		case reflect.Pointer:
			// Pointer to struct - recurse into it
			if field.Type().Elem().Kind() == reflect.Struct {
				shouldRecurse = true
				var elemValue reflect.Value
				if field.IsNil() {
					elemValue = reflect.New(field.Type().Elem()).Elem()
				} else {
					elemValue = field.Elem()
				}
				extractFieldsRecursive(elemValue, fieldName, fields, totalCount, depth+1, maxDepth)
			}
		}

		// Count all chartable fields (including empty ones)
		if isPotentialField {
			*totalCount++
		}

		// Only add to fields array if there's actual data
		if isChartable && !shouldRecurse {
			*fields = append(*fields, ChartFieldInfo{
				Name:        fieldName,
				Type:        typeName,
				Description: getFieldDescription(fieldName),
			})
		}
	}
}

// getFieldDescription returns a human-readable description for common field names
func getFieldDescription(fieldName string) string {
	descriptions := map[string]string{
		"Timestamp":      "Record timestamp in nanoseconds",
		"Size":           "Size in bytes",
		"Length":         "Length in bytes",
		"BytesClient":    "Bytes sent by client",
		"BytesServer":    "Bytes sent by server",
		"NumPackets":     "Number of packets",
		"TotalSize":      "Total size in bytes",
		"AppPayloadSize": "Application payload size in bytes",
		"Duration":       "Duration in nanoseconds",
		"Port":           "Port number",
		"SrcPort":        "Source port number",
		"DstPort":        "Destination port number",
		"StatusCode":     "HTTP status code",
		"ContentLength":  "Content length in bytes",
		"TTL":            "Time to live",
		"Checksum":       "Checksum value",
		"Window":         "TCP window size",
		"Seq":            "Sequence number",
		"Ack":            "Acknowledgment number",
		"IHL":            "IP header length",
		"TOS":            "Type of service",
		"ID":             "Identifier",
		"FragOffset":     "Fragment offset",
		"Protocol":       "Protocol number",
	}

	if desc, ok := descriptions[fieldName]; ok {
		return desc
	}

	// Generate description from field name
	return strings.Join(splitCamelCase(fieldName), " ")
}

// splitCamelCase splits a camelCase string into words
func splitCamelCase(s string) []string {
	var words []string
	var currentWord []rune

	for i, r := range s {
		if i > 0 && r >= 'A' && r <= 'Z' {
			if len(currentWord) > 0 {
				words = append(words, string(currentWord))
				currentWord = nil
			}
		}
		currentWord = append(currentWord, r)
	}

	if len(currentWord) > 0 {
		words = append(words, string(currentWord))
	}

	return words
}
