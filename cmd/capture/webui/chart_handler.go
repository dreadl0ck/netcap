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
	fields, totalFields := extractAllFieldsWithCount(msg)

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
// Supports nested field access using dot notation (e.g., "ReqCookies.Name")
func extractNumericField(msg interface{}, fieldPath string) (float64, error) {
	v := reflect.ValueOf(msg)

	// Handle pointer
	if v.Kind() == reflect.Ptr {
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
		if v.Kind() == reflect.Ptr {
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
			if v.Kind() == reflect.Ptr {
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
	fields, totalFields := extractAllFieldsWithCount(msg)

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
func extractAllFields(msg interface{}) []ChartFieldInfo {
	fields, _ := extractAllFieldsWithCount(msg)
	return fields
}

// extractAllFieldsWithCount returns a list of all chartable fields and the total count including filtered fields
func extractAllFieldsWithCount(msg interface{}) ([]ChartFieldInfo, int) {
	var fields []ChartFieldInfo
	var totalCount int

	v := reflect.ValueOf(msg)
	if v.Kind() == reflect.Ptr {
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

	if v.Kind() == reflect.Ptr {
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
			} else if elemType.Kind() == reflect.Struct || (elemType.Kind() == reflect.Ptr && elemType.Elem().Kind() == reflect.Struct) {
				// Slice of structs - recurse into the first element if available, or a zero value
				shouldRecurse = true
				var elemValue reflect.Value
				if field.Len() > 0 {
					elemValue = field.Index(0)
					if elemValue.Kind() == reflect.Ptr {
						if !elemValue.IsNil() {
							elemValue = elemValue.Elem()
						} else {
							// Create zero value for inspection
							elemValue = reflect.New(elemType.Elem()).Elem()
						}
					}
				} else if v.IsZero() {
					// Creating zero value for structure inspection
					if elemType.Kind() == reflect.Ptr {
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
		case reflect.Ptr:
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

