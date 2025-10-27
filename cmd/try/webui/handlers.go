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

	"github.com/dreadl0ck/netcap/defaults"
	netio "github.com/dreadl0ck/netcap/io"
)

// StatusResponse represents the capture status (compatible with capture webUI)
type StatusResponse struct {
	IsProcessing    bool     `json:"isProcessing"`
	OutputDir       string   `json:"outputDir"`
	InputFiles      []string `json:"inputFiles"`
	ServerStarted   int64    `json:"serverStarted"`
	ActiveInputFile string   `json:"activeInputFile"`
	IsMultiFile     bool     `json:"isMultiFile"`
	IsTryService    bool     `json:"isTryService"` // Flag to indicate try service mode
}

// FileInfo represents file metadata
type FileInfo struct {
	Name         string  `json:"name"`
	Path         string  `json:"path"`
	Size         int64   `json:"size"`
	ModifiedTime int64   `json:"modifiedTime"`
	IsCompleted  bool    `json:"isCompleted"`
	Error        *string `json:"error,omitempty"`
}

// AuditFileInfo extends FileInfo with audit record specific metadata
type AuditFileInfo struct {
	FileInfo
	Type        string `json:"type"`
	RecordCount int64  `json:"recordCount,omitempty"`
	Layer       string `json:"layer"`
}

// SessionInfo interface for accessing session data
type SessionInfo interface {
	GetSessionID() string
	GetStatus() string
	GetOutputDir() string
	GetInputFilename() string
	IsResultsReady() bool
}

// HandleStatus returns the current session status
func HandleStatus(sessionMgr interface{}, sessionID string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		// Get session from manager (we'll cast this in the actual implementation)
		// For now, serve a basic response
		response := StatusResponse{
			IsProcessing:    false,
			OutputDir:       "",
			InputFiles:      []string{},
			ServerStarted:   GetServerStartTime().Unix(),
			ActiveInputFile: "",
			IsMultiFile:     false,
			IsTryService:    true,
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	}
}

// HandleAuditFiles returns list of audit record files
func HandleAuditFiles(outputDir string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		if outputDir == "" {
			respondJSON(w, http.StatusOK, []AuditFileInfo{})
			return
		}

		files, err := listAuditFiles(outputDir)
		if err != nil {
			log.Printf("[WebUI] Error listing audit files: %v", err)
			respondJSON(w, http.StatusInternalServerError, map[string]string{
				"error": fmt.Sprintf("Failed to list audit files: %v", err),
			})
			return
		}

		respondJSON(w, http.StatusOK, files)
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
			respondJSON(w, http.StatusNotFound, map[string]string{
				"error": fmt.Sprintf("Audit file not found: %s", auditType),
			})
			return
		}

		if action == "meta" {
			handleAuditMeta(w, r, filePath, auditType)
		} else {
			handleAuditStream(w, r, filePath, auditType)
		}
	}
}

// HandleLogFiles returns list of log files
func HandleLogFiles(outputDir string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		if outputDir == "" {
			respondJSON(w, http.StatusOK, []FileInfo{})
			return
		}

		// Look for all .log files in output directory
		var logs []FileInfo

		entries, err := os.ReadDir(outputDir)
		if err != nil {
			respondJSON(w, http.StatusOK, []FileInfo{})
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

		respondJSON(w, http.StatusOK, logs)
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
			respondJSON(w, http.StatusNotFound, map[string]string{
				"error": "Log file not found",
			})
			return
		}

		respondJSON(w, http.StatusOK, map[string]string{
			"content": string(content),
		})
	}
}

// AuditStatsResponse represents the audit record statistics response
type AuditStatsResponse struct {
	TotalRecords       int64 `json:"totalRecords"`
	ExploitCount       int64 `json:"exploitCount"`
	VulnerabilityCount int64 `json:"vulnerabilityCount"`
	CredentialsCount   int64 `json:"credentialsCount"`
	SoftwareCount      int64 `json:"softwareCount"`
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
			respondJSON(w, http.StatusOK, response)
			return
		}

		files, err := os.ReadDir(outputDir)
		if err != nil {
			log.Printf("[WebUI] Failed to read directory %s for audit stats: %v", outputDir, err)
			respondJSON(w, http.StatusOK, response)
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
			count := countRecords(fullPath)
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

		respondJSON(w, http.StatusOK, response)
	}
}

// Helper functions

func listAuditFiles(outputDir string) ([]AuditFileInfo, error) {
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
		recordCount := countRecords(filepath.Join(outputDir, name))

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

func countRecords(filePath string) int64 {
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

// Removed determineLayer - now using GetLayerName(GetLayerType()) from sorting.go

func handleAuditMeta(w http.ResponseWriter, r *http.Request, filePath, auditType string) {
	recordCount := countRecords(filePath)

	respondJSON(w, http.StatusOK, map[string]interface{}{
		"type":        auditType,
		"recordCount": recordCount,
		"filePath":    filePath,
	})
}

func handleAuditStream(w http.ResponseWriter, r *http.Request, filePath, auditType string) {
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
			respondJSON(w, http.StatusServiceUnavailable, map[string]string{
				"error": "Audit record file is incomplete or being written",
			})
		} else {
			respondJSON(w, http.StatusInternalServerError, map[string]string{
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
			respondJSON(w, http.StatusServiceUnavailable, map[string]string{
				"error": "Audit record file is incomplete or being written",
			})
		} else {
			respondJSON(w, http.StatusInternalServerError, map[string]string{
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
		respondJSON(w, http.StatusInternalServerError, map[string]string{
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

func respondJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}
