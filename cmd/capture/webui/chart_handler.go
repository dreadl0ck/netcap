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
	"path/filepath"
	"reflect"
	"sort"
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

		if auditType == "" || field == "" {
			http.Error(w, "Missing required parameters: type, field", http.StatusBadRequest)
			return
		}

		if chartType == "" {
			chartType = "line"
		}

		// No default interval - empty means use all records with actual timestamps

		// Generate chart using go-echarts
		generator := NewChartGenerator(auditType, field, chartType, interval)
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

		// Read one record to get field information
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

		// Read one record to inspect fields
		msg, err := reader.NextRecord()
		if err != nil {
			http.Error(w, fmt.Sprintf("Failed to read record: %v", err), http.StatusInternalServerError)
			return
		}

		// Extract all fields (numeric and string) using reflection
		fields := extractAllFields(msg)

		response := ChartFieldsResponse{
			Type:   auditType,
			Fields: fields,
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
	Type   string           `json:"type"`
	Fields []ChartFieldInfo `json:"fields"`
}

// ChartFieldInfo represents metadata about a field for charting
type ChartFieldInfo struct {
	Name        string `json:"name"`
	Type        string `json:"type"`
	Description string `json:"description"`
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

	if auditType == "" || field == "" {
		http.Error(w, "Missing required parameters: type, field", http.StatusBadRequest)
		return
	}

	if chartType == "" {
		chartType = "line" // default to line chart
	}

	// No default interval - empty means use all records with actual timestamps

	// Get output directory
	s.mu.RLock()
	outDir := s.outDir
	s.mu.RUnlock()

	if outDir == "" {
		http.Error(w, "No output directory available", http.StatusServiceUnavailable)
		return
	}

	// Generate chart using go-echarts
	generator := NewChartGenerator(auditType, field, chartType, interval)
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
func extractNumericField(msg interface{}, fieldName string) (float64, error) {
	v := reflect.ValueOf(msg)

	// Handle pointer
	if v.Kind() == reflect.Ptr {
		v = v.Elem()
	}

	if v.Kind() != reflect.Struct {
		return 0, fmt.Errorf("message is not a struct")
	}

	// Find field by name
	field := v.FieldByName(fieldName)
	if !field.IsValid() {
		return 0, fmt.Errorf("field %s not found", fieldName)
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
		return 0, fmt.Errorf("field %s is not a numeric type", fieldName)
	}
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

	// Get output directory
	s.mu.RLock()
	outDir := s.outDir
	s.mu.RUnlock()

	if outDir == "" {
		http.Error(w, "No output directory available", http.StatusServiceUnavailable)
		return
	}

	// Construct file path
	filePath := filepath.Join(outDir, auditType+defaults.FileExtension+".gz")

	// Read one record to get field information
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

	// Read one record to inspect fields
	msg, err := reader.NextRecord()
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to read record: %v", err), http.StatusInternalServerError)
		return
	}

	// Extract all fields (numeric and string) using reflection
	fields := extractAllFields(msg)

	response := ChartFieldsResponse{
		Type:   auditType,
		Fields: fields,
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(response); err != nil {
		log.Printf("[WebUI] Failed to encode chart fields response: %v", err)
		http.Error(w, fmt.Sprintf("Failed to encode response: %v", err), http.StatusInternalServerError)
	}
}

// extractAllFields returns a list of all chartable fields (numeric and string) from a struct
func extractAllFields(msg interface{}) []ChartFieldInfo {
	var fields []ChartFieldInfo

	v := reflect.ValueOf(msg)
	if v.Kind() == reflect.Ptr {
		v = v.Elem()
	}

	if v.Kind() != reflect.Struct {
		return fields
	}

	t := v.Type()
	for i := 0; i < v.NumField(); i++ {
		field := v.Field(i)
		fieldType := t.Field(i)

		// Skip unexported fields
		if !field.CanInterface() {
			continue
		}

		// Check field type and categorize
		typeName := ""
		isChartable := false

		switch field.Kind() {
		case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
			typeName = "numeric (integer)"
			isChartable = true
		case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
			typeName = "numeric (unsigned)"
			isChartable = true
		case reflect.Float32, reflect.Float64:
			typeName = "numeric (float)"
			isChartable = true
		case reflect.Bool:
			typeName = "categorical (boolean)"
			isChartable = true
		case reflect.String:
			typeName = "categorical (string)"
			isChartable = true
		case reflect.Slice:
			if field.Type().Elem().Kind() == reflect.String {
				typeName = "categorical (string array)"
				isChartable = true
			}
		}

		if isChartable {
			fields = append(fields, ChartFieldInfo{
				Name:        fieldType.Name,
				Type:        typeName,
				Description: getFieldDescription(fieldType.Name),
			})
		}
	}

	return fields
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
