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
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/expr-lang/expr/vm"

	"github.com/dreadl0ck/netcap/defaults"
	netfilter "github.com/dreadl0ck/netcap/filter"
	netio "github.com/dreadl0ck/netcap/io"
	"github.com/dreadl0ck/netcap/types"
)

// HandleAuditFiles returns list of audit record files for a given output directory
func HandleAuditFiles(outputDir string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		if outputDir == "" {
			RespondJSON(w, http.StatusOK, []AuditFileInfo{})
			return
		}

		files, err := ListAuditFiles(outputDir)
		if err != nil {
			log.Printf("[WebUI] Error listing audit files: %v", err)
			RespondJSON(w, http.StatusInternalServerError, map[string]string{
				"error": fmt.Sprintf("Failed to list audit files: %v", err),
			})
			return
		}

		RespondJSON(w, http.StatusOK, files)
	}
}

// HandleAuditRecords streams audit records from a file
func HandleAuditRecords(outputDir string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Extract audit type from URL path
		encodedPath := strings.TrimPrefix(r.URL.Path, "/api/audit/")
		parts := strings.Split(encodedPath, "/")
		if len(parts) < 1 {
			http.Error(w, "Invalid audit type", http.StatusBadRequest)
			return
		}

		// URL-decode the audit type
		auditType, err := url.PathUnescape(parts[0])
		if err != nil {
			http.Error(w, "Invalid audit type encoding", http.StatusBadRequest)
			return
		}

		action := "stream"
		if len(parts) > 1 {
			action = parts[1]
		}

		// For fields action, we don't need the file to exist
		if action == "fields" {
			HandleAuditFields(w, r, auditType)
			return
		}

		// For values action, we need the file
		if action == "values" {
			fileName := auditType + defaults.FileExtension + ".gz"
			filePath := filepath.Join(outputDir, fileName)
			HandleAuditFieldValues(w, r, filePath, auditType)
			return
		}

		// Build file path
		fileName := auditType + defaults.FileExtension + ".gz"
		filePath := filepath.Join(outputDir, fileName)

		// Check if file exists
		if _, err := os.Stat(filePath); os.IsNotExist(err) {
			RespondJSON(w, http.StatusNotFound, map[string]string{
				"error": fmt.Sprintf("Audit file not found: %s", auditType),
			})
			return
		}

		if action == "meta" {
			HandleAuditMeta(w, r, filePath, auditType)
		} else {
			HandleAuditStream(w, r, filePath, auditType)
		}
	}
}

// HandleLogFiles returns list of log files for a given output directory
func HandleLogFiles(outputDir string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		if outputDir == "" {
			RespondJSON(w, http.StatusOK, []FileInfo{})
			return
		}

		// Look for all .log files in output directory
		var logs []FileInfo

		entries, err := os.ReadDir(outputDir)
		if err != nil {
			RespondJSON(w, http.StatusOK, []FileInfo{})
			return
		}

		for _, entry := range entries {
			// Skip directories
			if entry.IsDir() {
				continue
			}

			name := entry.Name()

			// Only include .log files
			if !strings.HasSuffix(name, ".log") {
				continue
			}

			info, err := entry.Info()
			if err != nil {
				continue
			}

			// Skip empty log files (size 0)
			if info.Size() == 0 {
				continue
			}

			logs = append(logs, FileInfo{
				Name:         name,
				Path:         filepath.Join(outputDir, name),
				Size:         info.Size(),
				ModifiedTime: info.ModTime().Unix(),
				IsCompleted:  true,
			})
		}

		// Sort logs by name for consistent ordering
		sort.Slice(logs, func(i, j int) bool {
			return logs[i].Name < logs[j].Name
		})

		RespondJSON(w, http.StatusOK, logs)
	}
}

// HandleLogContent returns the content of a log file
func HandleLogContent(outputDir string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		// Extract log name from URL
		encodedLogName := strings.TrimPrefix(r.URL.Path, "/api/logs/")
		if encodedLogName == "" {
			http.Error(w, "Log name required", http.StatusBadRequest)
			return
		}

		// URL-decode the log name
		logName, err := url.PathUnescape(encodedLogName)
		if err != nil {
			http.Error(w, "Invalid log name encoding", http.StatusBadRequest)
			return
		}

		// Sanitize filename
		logName = filepath.Base(logName)
		logPath := filepath.Join(outputDir, logName)

		// Read log file
		content, err := os.ReadFile(logPath)
		if err != nil {
			http.Error(w, "Log file not found", http.StatusNotFound)
			return
		}

		// Return raw log content as plain text
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		w.Write(content)
	}
}

// HandleAuditStats returns statistics for specific audit record types
func HandleAuditStats(outputDir string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		response := AuditStatsResponse{
			TotalRecords:       0,
			ExploitCount:       0,
			VulnerabilityCount: 0,
			CredentialsCount:   0,
			SoftwareCount:      0,
		}

		if outputDir == "" {
			RespondJSON(w, http.StatusOK, response)
			return
		}

		files, err := os.ReadDir(outputDir)
		if err != nil {
			log.Printf("[WebUI] Failed to read directory %s for audit stats: %v", outputDir, err)
			RespondJSON(w, http.StatusOK, response)
			return
		}

		// Count records for specific audit types
		for _, file := range files {
			if file.IsDir() {
				continue
			}

			name := file.Name()
			// Check for audit record files (.ncap.gz)
			if !strings.HasSuffix(name, defaults.FileExtension+".gz") {
				continue
			}

			// Extract type name (remove .ncap.gz)
			typeName := strings.TrimSuffix(name, ".gz")
			typeName = strings.TrimSuffix(typeName, defaults.FileExtension)

			fullPath := filepath.Join(outputDir, name)

			// Count records for this file
			count := CountRecords(fullPath)
			if count == 0 {
				continue
			}

			// Add to total
			response.TotalRecords += count

			// Check if this is one of the specific audit types we're tracking
			switch typeName {
			case "Exploit":
				response.ExploitCount = count
			case "Vulnerability":
				response.VulnerabilityCount = count
			case "Credentials":
				response.CredentialsCount = count
			case "Software":
				response.SoftwareCount = count
			}
		}

		RespondJSON(w, http.StatusOK, response)
	}
}

// ListAuditFiles returns a list of audit files in the given directory
func ListAuditFiles(outputDir string) ([]AuditFileInfo, error) {
	var files []AuditFileInfo

	// Check if directory exists first
	if _, err := os.Stat(outputDir); os.IsNotExist(err) {
		// Directory doesn't exist yet, return empty list instead of error
		return files, nil
	}

	entries, err := os.ReadDir(outputDir)
	if err != nil {
		return nil, err
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		name := entry.Name()
		if !strings.HasSuffix(name, defaults.FileExtension+".gz") {
			continue
		}

		info, err := entry.Info()
		if err != nil {
			continue
		}

		// Extract audit type
		auditType := strings.TrimSuffix(strings.TrimSuffix(name, ".gz"), defaults.FileExtension)

		// Count records
		recordCount := CountRecords(filepath.Join(outputDir, name))

		files = append(files, AuditFileInfo{
			FileInfo: FileInfo{
				Name:         name,
				Path:         filepath.Join(outputDir, name),
				Size:         info.Size(),
				ModifiedTime: info.ModTime().Unix(),
				IsCompleted:  true,
			},
			Type:        auditType,
			RecordCount: recordCount,
			Layer:       GetLayerName(GetLayerType(auditType)),
		})
	}

	// Sort files by layer hierarchy
	SortAuditFiles(files)

	return files, nil
}

// CountRecords counts the number of records in an audit file
func CountRecords(filePath string) int64 {
	reader, err := netio.Open(filePath, defaults.BufferSize)
	if err != nil {
		return 0
	}
	defer reader.Close()

	count := int64(0)
	header, err := reader.ReadHeader()
	if err != nil || header == nil {
		return 0
	}

	record := netio.InitRecord(header.Type)
	if record == nil {
		return 0
	}

	for {
		err := reader.Next(record)
		if err != nil {
			break
		}
		count++
	}

	return count
}

// HandleAuditMeta returns metadata for an audit file
func HandleAuditMeta(w http.ResponseWriter, r *http.Request, filePath, auditType string) {
	recordCount := CountRecords(filePath)

	RespondJSON(w, http.StatusOK, map[string]interface{}{
		"type":        auditType,
		"recordCount": recordCount,
		"filePath":    filePath,
	})
}

// HandleAuditStream streams audit records via Server-Sent Events
func HandleAuditStream(w http.ResponseWriter, r *http.Request, filePath, auditType string) {
	startTime := time.Now()

	// Parse query parameters
	offset := 0
	limit := 500 // Default limit (max 500)

	if offsetStr := r.URL.Query().Get("offset"); offsetStr != "" {
		if val, err := strconv.Atoi(offsetStr); err == nil && val >= 0 {
			offset = val
		}
	}

	if limitStr := r.URL.Query().Get("limit"); limitStr != "" {
		if val, err := strconv.Atoi(limitStr); err == nil && val > 0 && val <= 500 {
			limit = val
		}
	}

	// Get filter expression
	filterExpr := r.URL.Query().Get("filter")

	// Check if streaming is supported BEFORE setting headers
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "Streaming not supported", http.StatusInternalServerError)
		return
	}

	// Setup SSE headers - must be done before any writes
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	// Helper function to send SSE error event
	sendError := func(errorMsg string) {
		errorJSON, _ := json.Marshal(map[string]string{"error": errorMsg})
		fmt.Fprintf(w, "event: error\ndata: %s\n\n", string(errorJSON))
		flusher.Flush()
	}

	// Create audit record reader
	auditReader, err := NewAuditRecordReader(filePath)
	if err != nil {
		log.Printf("[WebUI] Failed to open audit record file %s: %v", filePath, err)
		if err == io.EOF {
			sendError("Audit record file is incomplete or being written")
		} else {
			sendError(fmt.Sprintf("Failed to open audit record file: %v", err))
		}
		return
	}
	defer auditReader.Close()

	// Read the header first (required before reading records)
	header, err := auditReader.ReadHeader()
	if err != nil {
		log.Printf("[WebUI] Failed to read header from %s: %v", filePath, err)
		if err == io.EOF {
			sendError("Audit record file is incomplete or being written")
		} else {
			sendError(fmt.Sprintf("Failed to read header: %v", err))
		}
		return
	}

	// Compile filter expression if provided
	var filterProgram *vm.Program
	if filterExpr != "" {
		filterProgram, err = netfilter.CompileExpression(filterExpr, header.Type)
		if err != nil {
			log.Printf("[WebUI] Failed to compile filter expression: %v", err)
			sendError(fmt.Sprintf("Invalid filter expression: %v", err))
			return
		}
	}

	// Skip to offset (only if no filter - filtering requires scanning all records)
	if filterExpr == "" {
		if err := auditReader.Skip(offset); err != nil {
			fmt.Fprintf(w, "event: error\ndata: {\"error\": \"Failed to skip to offset\"}\n\n")
			flusher.Flush()
			return
		}
	}

	// Stream records
	count := 0
	totalScanned := 0
	matchedCount := 0

	for {
		record, err := auditReader.NextRecord()
		if err == io.EOF {
			break
		}
		if err != nil {
			fmt.Fprintf(w, "event: error\ndata: {\"error\": \"%v\"}\n\n", err)
			flusher.Flush()
			break
		}

		totalScanned++

		// Apply filter if provided
		if filterProgram != nil {
			auditRecord, ok := record.(types.AuditRecord)
			if !ok {
				continue
			}

			match, err := netfilter.EvaluateExpression(filterProgram, auditRecord)
			if err != nil {
				log.Printf("[WebUI] Filter evaluation error: %v", err)
				continue
			}

			if !match {
				continue
			}
			matchedCount++
		} else {
			matchedCount++
		}

		// Skip records before offset (when filtering)
		if filterExpr != "" && matchedCount <= offset {
			continue
		}

		// Only send records if we haven't reached the limit yet
		// But continue scanning to get accurate totalScanned count
		if count < limit {
			// Convert record to JSON
			jsonData, err := json.Marshal(record)
			if err != nil {
				log.Printf("[WebUI] JSON marshal error: %v", err)
				continue
			}

			fmt.Fprintf(w, "event: record\ndata: %s\n\n", string(jsonData))
			flusher.Flush()

			count++

			// Send progress update every 100 records returned
			if count%100 == 0 {
				fmt.Fprintf(w, "event: progress\ndata: {\"count\": %d, \"scanned\": %d}\n\n", count, totalScanned)
				flusher.Flush()
			}
		}

		// Continue scanning all records even after reaching limit
		// to get accurate totalScanned count
	}

	executionTime := time.Since(startTime)

	// Send completion event with execution time
	fmt.Fprintf(w, "event: complete\ndata: {\"total\": %d, \"scanned\": %d, \"executionTimeMs\": %d}\n\n",
		count, totalScanned, executionTime.Milliseconds())
	flusher.Flush()
}

// FieldsResponse is the API response for field information
type FieldsResponse struct {
	RecordType string      `json:"recordType"`
	Fields     []FieldInfo `json:"fields"`
	Helpers    []string    `json:"helpers"`
}

// HandleAuditFields returns field information for a specific audit record type
func HandleAuditFields(w http.ResponseWriter, r *http.Request, recordTypeName string) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Convert type name to Type enum
	recordType := types.Type(types.Type_value["NC_"+recordTypeName])
	if recordType == 0 { // 0 is the default/unknown type
		RespondJSON(w, http.StatusBadRequest, map[string]interface{}{
			"error": fmt.Sprintf("Unknown record type: %s", recordTypeName),
		})
		return
	}

	// Create a sample record to extract field information
	record := netio.InitRecord(recordType)
	if record == nil {
		RespondJSON(w, http.StatusBadRequest, map[string]interface{}{
			"error": fmt.Sprintf("Failed to initialize record type: %s", recordTypeName),
		})
		return
	}

	// Extract fields using reflection
	fields := extractFields(record, "", 0)

	// Add helper functions
	helpers := []string{
		"InSubnet",
		"IsPrivateIP",
		"IsPublicIP",
		"ParsePort",
		"PortInRange",
		"TimeInRange",
		"DurationSince",
		"FormatTime",
		"ContainsAny",
		"MatchesPattern",
	}

	RespondJSON(w, http.StatusOK, FieldsResponse{
		RecordType: recordTypeName,
		Fields:     fields,
		Helpers:    helpers,
	})
}

// extractFields recursively extracts field information from a struct
func extractFields(v interface{}, prefix string, depth int) []FieldInfo {
	fields := make([]FieldInfo, 0)

	// Limit recursion depth to avoid explosion
	if depth > 2 {
		return fields
	}

	val := reflect.ValueOf(v)
	if val.Kind() == reflect.Ptr {
		if val.IsNil() {
			return fields
		}
		val = val.Elem()
	}

	if val.Kind() != reflect.Struct {
		return fields
	}

	typ := val.Type()

	for i := 0; i < val.NumField(); i++ {
		field := typ.Field(i)
		fieldValue := val.Field(i)

		// Skip unexported fields
		if !field.IsExported() {
			continue
		}

		// Skip XXX_ fields (protobuf internal)
		if strings.HasPrefix(field.Name, "XXX_") {
			continue
		}

		fieldName := field.Name
		if prefix != "" {
			fieldName = prefix + "." + field.Name
		}

		fieldType := field.Type.String()

		// Add the field
		fields = append(fields, FieldInfo{
			Name: fieldName,
			Type: fieldType,
		})

		// For nested structs, recursively extract fields
		if field.Type.Kind() == reflect.Struct && depth < 2 {
			nestedFields := extractFields(fieldValue.Interface(), fieldName, depth+1)
			fields = append(fields, nestedFields...)
		}

		// For pointer to struct
		if field.Type.Kind() == reflect.Ptr && field.Type.Elem().Kind() == reflect.Struct && depth < 2 {
			// Create a new instance for reflection
			if !fieldValue.IsNil() {
				nestedFields := extractFields(fieldValue.Interface(), fieldName, depth+1)
				fields = append(fields, nestedFields...)
			} else {
				// Try to create a new instance to get field names
				newInstance := reflect.New(field.Type.Elem())
				nestedFields := extractFields(newInstance.Interface(), fieldName, depth+1)
				fields = append(fields, nestedFields...)
			}
		}

		// For slices of structs, show array notation
		if field.Type.Kind() == reflect.Slice && depth < 2 {
			elemType := field.Type.Elem()
			if elemType.Kind() == reflect.Ptr {
				elemType = elemType.Elem()
			}
			if elemType.Kind() == reflect.Struct {
				// Create sample element for reflection
				sampleElem := reflect.New(elemType).Interface()
				nestedFields := extractFields(sampleElem, fieldName+"[0]", depth+1)
				fields = append(fields, nestedFields...)
			}
		}
	}

	return fields
}

// FieldValuesResponse is the API response for field values
type FieldValuesResponse struct {
	RecordType    string              `json:"recordType"`
	FieldValues   map[string][]string `json:"fieldValues"`
	SampleSize    int                 `json:"sampleSize"`
	MaxPerField   int                 `json:"maxPerField"`
	RecordScanned int                 `json:"recordsScanned"`
}

// HandleAuditFieldValues returns sample values for fields in a specific audit record type
func HandleAuditFieldValues(w http.ResponseWriter, r *http.Request, filePath, recordTypeName string) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Check if file exists
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		RespondJSON(w, http.StatusNotFound, map[string]interface{}{
			"error": fmt.Sprintf("Audit file not found: %s", recordTypeName),
		})
		return
	}

	// Open the audit record file
	reader, err := NewAuditRecordReader(filePath)
	if err != nil {
		RespondJSON(w, http.StatusInternalServerError, map[string]interface{}{
			"error": fmt.Sprintf("Failed to open audit record file: %v", err),
		})
		return
	}
	defer reader.Close()

	// Read header
	_, err = reader.ReadHeader()
	if err != nil {
		RespondJSON(w, http.StatusInternalServerError, map[string]interface{}{
			"error": fmt.Sprintf("Failed to read header: %v", err),
		})
		return
	}

	const maxValuesPerField = 20
	const maxRecordsToScan = 200

	// Map to collect unique values per field
	fieldValues := make(map[string]map[string]bool)
	recordsScanned := 0

	// Read records and collect values
	for recordsScanned < maxRecordsToScan {
		record, err := reader.NextRecord()
		if err == io.EOF {
			break
		}
		if err != nil {
			log.Printf("[WebUI] Error reading record: %v", err)
			continue
		}

		recordsScanned++

		// Extract field values using reflection
		extractFieldValues(record, "", fieldValues, maxValuesPerField, 0)
	}

	// Convert to response format
	result := make(map[string][]string)
	for fieldName, valuesMap := range fieldValues {
		values := make([]string, 0, len(valuesMap))
		for value := range valuesMap {
			values = append(values, value)
		}
		sort.Strings(values)
		result[fieldName] = values
	}

	RespondJSON(w, http.StatusOK, FieldValuesResponse{
		RecordType:    recordTypeName,
		FieldValues:   result,
		SampleSize:    maxRecordsToScan,
		MaxPerField:   maxValuesPerField,
		RecordScanned: recordsScanned,
	})
}

// extractFieldValues recursively extracts unique field values from a struct
func extractFieldValues(v interface{}, prefix string, fieldValues map[string]map[string]bool, maxPerField int, depth int) {
	// Limit recursion depth
	if depth > 2 {
		return
	}

	val := reflect.ValueOf(v)
	if val.Kind() == reflect.Ptr {
		if val.IsNil() {
			return
		}
		val = val.Elem()
	}

	if val.Kind() != reflect.Struct {
		return
	}

	typ := val.Type()

	for i := 0; i < val.NumField(); i++ {
		field := typ.Field(i)
		fieldValue := val.Field(i)

		// Skip unexported fields
		if !field.IsExported() {
			continue
		}

		// Skip XXX_ fields (protobuf internal)
		if strings.HasPrefix(field.Name, "XXX_") {
			continue
		}

		fieldName := field.Name
		if prefix != "" {
			fieldName = prefix + "." + field.Name
		}

		// Initialize map for this field if needed
		if _, exists := fieldValues[fieldName]; !exists {
			fieldValues[fieldName] = make(map[string]bool)
		}

		// Skip if we already have max values for this field
		if len(fieldValues[fieldName]) >= maxPerField {
			continue
		}

		// Extract value based on type
		if !fieldValue.CanInterface() {
			continue
		}

		switch field.Type.Kind() {
		case reflect.String:
			strVal := fieldValue.String()
			if strVal != "" && len(fieldValues[fieldName]) < maxPerField {
				fieldValues[fieldName][strVal] = true
			}

		case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
			intVal := fieldValue.Int()
			if len(fieldValues[fieldName]) < maxPerField {
				fieldValues[fieldName][fmt.Sprintf("%d", intVal)] = true
			}

		case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
			uintVal := fieldValue.Uint()
			if len(fieldValues[fieldName]) < maxPerField {
				fieldValues[fieldName][fmt.Sprintf("%d", uintVal)] = true
			}

		case reflect.Float32, reflect.Float64:
			floatVal := fieldValue.Float()
			if len(fieldValues[fieldName]) < maxPerField {
				fieldValues[fieldName][fmt.Sprintf("%g", floatVal)] = true
			}

		case reflect.Bool:
			boolVal := fieldValue.Bool()
			if len(fieldValues[fieldName]) < maxPerField {
				fieldValues[fieldName][fmt.Sprintf("%t", boolVal)] = true
			}

		case reflect.Struct:
			// Recurse into nested struct
			if depth < 2 {
				extractFieldValues(fieldValue.Interface(), fieldName, fieldValues, maxPerField, depth+1)
			}

		case reflect.Ptr:
			if !fieldValue.IsNil() && field.Type.Elem().Kind() == reflect.Struct && depth < 2 {
				extractFieldValues(fieldValue.Interface(), fieldName, fieldValues, maxPerField, depth+1)
			}

		case reflect.Slice:
			// For slices, sample first few elements
			if fieldValue.Len() > 0 {
				elemType := field.Type.Elem()
				if elemType.Kind() == reflect.Ptr {
					elemType = elemType.Elem()
				}

				if elemType.Kind() == reflect.Struct && depth < 2 {
					// Sample first element with array notation
					firstElem := fieldValue.Index(0)
					extractFieldValues(firstElem.Interface(), fieldName+"[0]", fieldValues, maxPerField, depth+1)
				}
			}
		}
	}
}
