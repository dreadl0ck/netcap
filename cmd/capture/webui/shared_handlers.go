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
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/dreadl0ck/netcap/defaults"
	netio "github.com/dreadl0ck/netcap/io"
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
		parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/api/audit/"), "/")
		if len(parts) < 1 {
			http.Error(w, "Invalid audit type", http.StatusBadRequest)
			return
		}

		auditType := parts[0]
		action := "stream"
		if len(parts) > 1 {
			action = parts[1]
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
		logName := strings.TrimPrefix(r.URL.Path, "/api/logs/")
		if logName == "" {
			http.Error(w, "Log name required", http.StatusBadRequest)
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
	// Parse query parameters
	offset := 0
	limit := 1000 // Default limit

	if offsetStr := r.URL.Query().Get("offset"); offsetStr != "" {
		if val, err := strconv.Atoi(offsetStr); err == nil && val >= 0 {
			offset = val
		}
	}

	if limitStr := r.URL.Query().Get("limit"); limitStr != "" {
		if val, err := strconv.Atoi(limitStr); err == nil && val > 0 && val <= 10000 {
			limit = val
		}
	}

	// Create audit record reader
	auditReader, err := NewAuditRecordReader(filePath)
	if err != nil {
		if err == io.EOF {
			RespondJSON(w, http.StatusServiceUnavailable, map[string]string{
				"error": "Audit record file is incomplete or being written",
			})
		} else {
			RespondJSON(w, http.StatusInternalServerError, map[string]string{
				"error": fmt.Sprintf("Failed to open audit record file: %v", err),
			})
		}
		return
	}
	defer auditReader.Close()

	// Read the header first (required before reading records)
	_, err = auditReader.ReadHeader()
	if err != nil {
		if err == io.EOF {
			RespondJSON(w, http.StatusServiceUnavailable, map[string]string{
				"error": "Audit record file is incomplete or being written",
			})
		} else {
			RespondJSON(w, http.StatusInternalServerError, map[string]string{
				"error": fmt.Sprintf("Failed to read header: %v", err),
			})
		}
		return
	}

	// Setup SSE
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	flusher, ok := w.(http.Flusher)
	if !ok {
		RespondJSON(w, http.StatusInternalServerError, map[string]string{
			"error": "Streaming not supported",
		})
		return
	}

	// Skip to offset
	if err := auditReader.Skip(offset); err != nil {
		fmt.Fprintf(w, "event: error\ndata: {\"error\": \"Failed to skip to offset\"}\n\n")
		flusher.Flush()
		return
	}

	// Stream records
	count := 0
	for count < limit {
		jsonData, err := auditReader.NextAsJSON()
		if err == io.EOF {
			break
		}
		if err != nil {
			fmt.Fprintf(w, "event: error\ndata: {\"error\": \"%v\"}\n\n", err)
			flusher.Flush()
			break
		}

		fmt.Fprintf(w, "event: record\ndata: %s\n\n", jsonData)
		flusher.Flush()

		count++

		// Send progress update every 100 records
		if count%100 == 0 {
			fmt.Fprintf(w, "event: progress\ndata: {\"count\": %d}\n\n", count)
			flusher.Flush()
		}
	}

	// Send completion event
	fmt.Fprintf(w, "event: complete\ndata: {\"total\": %d}\n\n", count)
	flusher.Flush()
}
