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
	"strconv"
	"strings"
	"time"

	"github.com/dreadl0ck/netcap/defaults"
	netio "github.com/dreadl0ck/netcap/io"
)

// StatusResponse represents the capture status
type StatusResponse struct {
	IsProcessing    bool      `json:"isProcessing"`
	OutputDir       string    `json:"outputDir"`
	InputFiles      []string  `json:"inputFiles"`
	ServerStarted   time.Time `json:"serverStarted"`
	ActiveInputFile string    `json:"activeInputFile"`
	IsMultiFile     bool      `json:"isMultiFile"`
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

var serverStartTime = time.Now()

// handleStatus returns the current capture status
func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	s.mu.RLock()
	// Ensure inputFiles is never nil for JSON encoding
	inputFiles := s.inputFiles
	if inputFiles == nil {
		inputFiles = []string{}
	}

	response := StatusResponse{
		IsProcessing:    s.isProcessing,
		OutputDir:       s.outDir,
		InputFiles:      inputFiles,
		ServerStarted:   serverStartTime,
		ActiveInputFile: s.activeInputFile,
		IsMultiFile:     len(inputFiles) > 1,
	}

	// Add completed files info
	completedFiles := make(map[string]bool)
	for k, v := range s.completedFiles {
		completedFiles[k] = v
	}
	s.mu.RUnlock()

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(response); err != nil {
		http.Error(w, fmt.Sprintf("Failed to encode response: %v", err), http.StatusInternalServerError)
	}
}

// handleInputFiles returns list of input PCAP files
func (s *Server) handleInputFiles(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	s.mu.RLock()
	completedFiles := make(map[string]bool)
	for k, v := range s.completedFiles {
		completedFiles[k] = v
	}
	inputFiles := s.inputFiles
	fileErrors := make(map[string]FileError)
	for k, v := range s.fileErrors {
		fileErrors[k] = v
	}
	s.mu.RUnlock()

	files := make([]FileInfo, 0)
	for _, path := range inputFiles {
		info, err := os.Stat(path)
		if err != nil {
			continue
		}

		fileInfo := FileInfo{
			Name:         filepath.Base(path),
			Path:         path,
			Size:         info.Size(),
			ModifiedTime: info.ModTime().Unix(),
			IsCompleted:  completedFiles[path],
		}

		// Add error information if available
		if ferr, hasError := fileErrors[path]; hasError {
			fileInfo.Error = &ferr.Error
		}

		files = append(files, fileInfo)
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(files); err != nil {
		http.Error(w, fmt.Sprintf("Failed to encode response: %v", err), http.StatusInternalServerError)
	}
}

// handleAuditFiles returns list of audit record files
func (s *Server) handleAuditFiles(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	auditFiles := make([]AuditFileInfo, 0)

	s.mu.RLock()
	outDir := s.outDir
	activeFile := s.activeInputFile
	s.mu.RUnlock()

	log.Printf("[WebUI] Reading audit files from: %s (active file: %s)", outDir, activeFile)

	if outDir == "" {
		log.Printf("[WebUI] Output directory is empty, returning empty list")
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(auditFiles)
		return
	}

	files, err := os.ReadDir(outDir)
	if err != nil {
		// If directory doesn't exist yet, return empty array
		log.Printf("[WebUI] Failed to read directory %s: %v", outDir, err)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(auditFiles)
		return
	}

	log.Printf("[WebUI] Found %d files in directory", len(files))
	for _, file := range files {
		if file.IsDir() {
			continue
		}

		name := file.Name()
		// Check for audit record files (.ncap or .ncap.gz)
		if !strings.HasSuffix(name, defaults.FileExtension) &&
			!strings.HasSuffix(name, defaults.FileExtensionCompressed) {
			continue
		}

		fullPath := filepath.Join(s.outDir, name)
		info, err := file.Info()
		if err != nil {
			continue
		}

		// Extract type name (remove .ncap or .ncap.gz)
		typeName := strings.TrimSuffix(name, defaults.FileExtensionCompressed)
		typeName = strings.TrimSuffix(typeName, defaults.FileExtension)

		auditFile := AuditFileInfo{
			FileInfo: FileInfo{
				Name:         name,
				Path:         fullPath,
				Size:         info.Size(),
				ModifiedTime: info.ModTime().Unix(),
			},
			Type:  typeName,
			Layer: GetLayerName(GetLayerType(typeName)),
		}

		// Try to count records (this might be slow for large files)
		// We'll do this asynchronously or on-demand in a real implementation
		count, err := netio.Count(fullPath)
		if err == nil {
			auditFile.RecordCount = count
		} else {
			// If we can't count records, the file might be incomplete or being written
			// Set recordCount to 0 so it gets filtered out by the frontend
			log.Printf("[WebUI] Failed to count records for %s: %v (file may be incomplete)", fullPath, err)
			auditFile.RecordCount = 0
		}

		auditFiles = append(auditFiles, auditFile)
	}

	// Sort audit files hierarchically by layer type
	SortAuditFiles(auditFiles)

	log.Printf("[WebUI] Returning %d audit files", len(auditFiles))
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(auditFiles)
}

// handleLogFiles returns list of log files
func (s *Server) handleLogFiles(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	logFiles := make([]FileInfo, 0)

	if s.outDir == "" {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(logFiles)
		return
	}

	files, err := os.ReadDir(s.outDir)
	if err != nil {
		// If directory doesn't exist yet, return empty array
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(logFiles)
		return
	}
	for _, file := range files {
		if file.IsDir() {
			continue
		}

		name := file.Name()
		if !strings.HasSuffix(name, ".log") {
			continue
		}

		fullPath := filepath.Join(s.outDir, name)
		info, err := file.Info()
		if err != nil {
			continue
		}

		// Skip empty log files
		if info.Size() == 0 {
			continue
		}

		logFiles = append(logFiles, FileInfo{
			Name:         name,
			Path:         fullPath,
			Size:         info.Size(),
			ModifiedTime: info.ModTime().Unix(),
		})
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(logFiles)
}

// handleAuditRecords handles audit record requests (both metadata and streaming)
func (s *Server) handleAuditRecords(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Extract type from URL path: /api/audit/{type}/{action}
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/api/audit/"), "/")
	if len(parts) < 2 {
		http.Error(w, "Invalid path", http.StatusBadRequest)
		return
	}

	auditType := parts[0]
	action := parts[1]

	switch action {
	case "meta":
		s.handleAuditMetadata(w, r, auditType)
	case "stream":
		s.handleAuditStream(w, r, auditType)
	default:
		http.Error(w, "Invalid action", http.StatusBadRequest)
	}
}

// handleAuditMetadata returns metadata about an audit record file
func (s *Server) handleAuditMetadata(w http.ResponseWriter, r *http.Request, auditType string) {
	filePath := s.getAuditFilePath(auditType)
	if filePath == "" {
		http.Error(w, "Audit record file not found", http.StatusNotFound)
		return
	}

	reader, err := NewAuditRecordReader(filePath)
	if err != nil {
		if err == io.EOF {
			http.Error(w, "Audit record file is incomplete or being written. Please try again later.", http.StatusServiceUnavailable)
		} else {
			http.Error(w, fmt.Sprintf("Failed to open audit record file: %v", err), http.StatusInternalServerError)
		}
		return
	}
	defer reader.Close()

	header, err := reader.ReadHeader()
	if err != nil {
		if err == io.EOF {
			http.Error(w, "Audit record file is incomplete or being written. Please try again later.", http.StatusServiceUnavailable)
		} else {
			http.Error(w, fmt.Sprintf("Failed to read header: %v", err), http.StatusInternalServerError)
		}
		return
	}

	count, _ := netio.Count(filePath)

	metadata := map[string]interface{}{
		"type":        auditType,
		"version":     header.Version,
		"inputSource": header.InputSource,
		"created":     header.Created,
		"recordCount": count,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(metadata)
}

// handleAuditStream streams audit records using Server-Sent Events
func (s *Server) handleAuditStream(w http.ResponseWriter, r *http.Request, auditType string) {
	log.Printf("[WebUI] Starting audit stream for type: %s", auditType)

	// Parse query parameters
	offset := 0
	limit := 1000 // Default limit

	if offsetStr := r.URL.Query().Get("offset"); offsetStr != "" {
		if o, err := strconv.Atoi(offsetStr); err == nil {
			offset = o
		}
	}

	if limitStr := r.URL.Query().Get("limit"); limitStr != "" {
		if l, err := strconv.Atoi(limitStr); err == nil && l > 0 && l <= 10000 {
			limit = l
		}
	}

	log.Printf("[WebUI] Stream parameters: offset=%d, limit=%d", offset, limit)

	filePath := s.getAuditFilePath(auditType)
	if filePath == "" {
		log.Printf("[WebUI] File not found for audit type: %s", auditType)
		http.Error(w, "Audit record file not found", http.StatusNotFound)
		return
	}

	log.Printf("[WebUI] Opening audit file: %s", filePath)
	reader, err := NewAuditRecordReader(filePath)
	if err != nil {
		log.Printf("[WebUI] Failed to open audit file: %v", err)
		if err == io.EOF {
			http.Error(w, "Audit record file is incomplete or being written. Please try again later.", http.StatusServiceUnavailable)
		} else {
			http.Error(w, fmt.Sprintf("Failed to open audit record file: %v", err), http.StatusInternalServerError)
		}
		return
	}
	defer reader.Close()

	// Read the header first (this is required before reading records)
	log.Printf("[WebUI] Reading file header")
	_, err = reader.ReadHeader()
	if err != nil {
		log.Printf("[WebUI] Failed to read header: %v", err)
		if err == io.EOF {
			http.Error(w, "Audit record file is incomplete or being written. Please try again later.", http.StatusServiceUnavailable)
		} else {
			http.Error(w, fmt.Sprintf("Failed to read header: %v", err), http.StatusInternalServerError)
		}
		return
	}

	// Set SSE headers
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "Streaming not supported", http.StatusInternalServerError)
		return
	}

	// Skip to offset
	if err := reader.Skip(offset); err != nil {
		log.Printf("[WebUI] Failed to skip to offset %d: %v", offset, err)
		fmt.Fprintf(w, "event: error\ndata: {\"error\": \"Failed to skip to offset\"}\n\n")
		flusher.Flush()
		return
	}

	log.Printf("[WebUI] Starting to stream records")

	// Stream records
	count := 0
	for count < limit {
		record, err := reader.NextAsJSON()
		if err == io.EOF {
			break
		}
		if err != nil {
			fmt.Fprintf(w, "event: error\ndata: {\"error\": \"%v\"}\n\n", err)
			flusher.Flush()
			break
		}

		fmt.Fprintf(w, "event: record\ndata: %s\n\n", record)
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

// handleLogContent streams log file contents
func (s *Server) handleLogContent(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Extract log name from URL: /api/logs/{name}
	logName := strings.TrimPrefix(r.URL.Path, "/api/logs/")
	if logName == "" {
		http.Error(w, "Log name required", http.StatusBadRequest)
		return
	}

	// Security: prevent directory traversal
	if strings.Contains(logName, "..") || strings.Contains(logName, "/") {
		http.Error(w, "Invalid log name", http.StatusBadRequest)
		return
	}

	logPath := filepath.Join(s.outDir, logName)
	if _, err := os.Stat(logPath); os.IsNotExist(err) {
		http.Error(w, "Log file not found", http.StatusNotFound)
		return
	}

	file, err := os.Open(logPath)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to open log file: %v", err), http.StatusInternalServerError)
		return
	}
	defer file.Close()

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	io.Copy(w, file)
}

// getAuditFilePath finds the full path for an audit record type
// It uses the directory based on activeInputFile if set, otherwise uses outDir
func (s *Server) getAuditFilePath(auditType string) string {
	s.mu.RLock()
	outDir := s.outDir
	activeFile := s.activeInputFile
	baseOutDir := s.baseOutDir
	s.mu.RUnlock()

	// If user has selected a specific file to view, use that file's directory
	// This prevents issues when processing moves to a new file but user is still viewing an old one
	if activeFile != "" {
		baseName := filepath.Base(activeFile)
		// Remove file extension to get directory name
		dirName := baseName
		for _, ext := range []string{".pcap", ".pcapng", ".cap", ".dmp"} {
			if strings.HasSuffix(dirName, ext) {
				dirName = strings.TrimSuffix(dirName, ext)
				break
			}
		}
		outDir = filepath.Join(baseOutDir, dirName)
		log.Printf("[WebUI] Using directory for active file %s: %s", activeFile, outDir)
	}

	// Try compressed version first
	compressedPath := filepath.Join(outDir, auditType+defaults.FileExtensionCompressed)
	if _, err := os.Stat(compressedPath); err == nil {
		log.Printf("[WebUI] Found audit file: %s", compressedPath)
		return compressedPath
	}

	// Try uncompressed version
	uncompressedPath := filepath.Join(outDir, auditType+defaults.FileExtension)
	if _, err := os.Stat(uncompressedPath); err == nil {
		log.Printf("[WebUI] Found audit file: %s", uncompressedPath)
		return uncompressedPath
	}

	log.Printf("[WebUI] Audit file not found for type: %s (tried %s and %s)", auditType, compressedPath, uncompressedPath)
	return ""
}

// handleSetDirectory handles requests to change the active directory for multi-file mode
func (s *Server) handleSetDirectory(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		InputFile string `json:"inputFile"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, fmt.Sprintf("Invalid request: %v", err), http.StatusBadRequest)
		return
	}

	if req.InputFile == "" {
		http.Error(w, "Input file not specified", http.StatusBadRequest)
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	// Find the input file in our list
	found := false
	for _, f := range s.inputFiles {
		if f == req.InputFile {
			found = true
			break
		}
	}

	if !found {
		http.Error(w, "Input file not found in list", http.StatusNotFound)
		return
	}

	// Check if file is completed
	if !s.completedFiles[req.InputFile] {
		http.Error(w, "File processing not yet complete", http.StatusBadRequest)
		return
	}

	// Calculate the output directory for this file
	// Use the same logic as getOutputDirForFile in main.go
	// Strip the file extension to get the directory name
	baseName := filepath.Base(req.InputFile)
	// Remove all known pcap extensions
	dirName := baseName
	for _, ext := range []string{".pcap", ".pcapng", ".cap", ".dmp"} {
		if strings.HasSuffix(dirName, ext) {
			dirName = strings.TrimSuffix(dirName, ext)
			break
		}
	}

	newOutDir := filepath.Join(s.baseOutDir, dirName)

	// Update the active directory and file
	s.outDir = newOutDir
	s.activeInputFile = req.InputFile

	log.Printf("[WebUI] Active directory changed to: %s (for file: %s)", newOutDir, req.InputFile)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success":         true,
		"outputDir":       newOutDir,
		"activeInputFile": req.InputFile,
	})
}
