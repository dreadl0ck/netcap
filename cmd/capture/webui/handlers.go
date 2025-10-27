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
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/dreadl0ck/netcap"
	"github.com/dreadl0ck/netcap/dbs"
	"github.com/dreadl0ck/netcap/defaults"
	"github.com/dreadl0ck/netcap/dpi"
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

// handleDatabaseInfo returns information about the currently loaded databases
func (s *Server) handleDatabaseInfo(w http.ResponseWriter, r *http.Request) {
	log.Printf("[WebUI] handleDatabaseInfo called: method=%s", r.Method)

	if r.Method != http.MethodGet {
		log.Printf("[WebUI] handleDatabaseInfo: method not allowed: %s", r.Method)
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Read database version
	configRoot := getConfigRootPath()
	versionFile := filepath.Join(configRoot, ".db-version")
	versionData, err := os.ReadFile(versionFile)
	version := "unknown"
	if err == nil {
		version = strings.TrimSpace(string(versionData))
		log.Printf("[WebUI] handleDatabaseInfo: version=%s", version)
	} else {
		log.Printf("[WebUI] handleDatabaseInfo: failed to read version file: %v", err)
	}

	// Get database folder path
	dbPath := getDataBaseFolderPath()
	log.Printf("[WebUI] handleDatabaseInfo: dbPath=%s", dbPath)

	// Check if database directory exists
	if _, err := os.Stat(dbPath); err != nil {
		log.Printf("[WebUI] handleDatabaseInfo: database directory does not exist or is inaccessible: %v", err)
		// Still return a valid response with empty files
	}

	// Scan database directory for files
	type DBFileInfo struct {
		Name         string `json:"name"`
		Path         string `json:"path"`
		Size         int64  `json:"size"`
		Type         string `json:"type"`
		ModifiedTime int64  `json:"modifiedTime"`
	}

	dbFiles := make([]DBFileInfo, 0)
	var totalSize int64

	files, err := os.ReadDir(dbPath)
	if err != nil {
		log.Printf("[WebUI] handleDatabaseInfo: failed to read database directory: %v", err)
		// Continue with empty files list
	} else {
		log.Printf("[WebUI] handleDatabaseInfo: found %d entries in database directory", len(files))
		for _, file := range files {
			name := file.Name()

			// Skip hidden files and metadata files
			if strings.HasPrefix(name, ".") || strings.HasPrefix(name, "._") {
				continue
			}

			fullPath := filepath.Join(dbPath, name)
			var size int64
			var modTime time.Time

			if file.IsDir() {
				// Only process directories that are bleve indices
				if !strings.HasSuffix(name, ".bleve") && !strings.Contains(name, ".bleve") {
					continue
				}

				// Calculate directory size recursively for bleve indices
				size, err = calculateDirectorySize(fullPath)
				if err != nil {
					log.Printf("[WebUI] handleDatabaseInfo: failed to calculate directory size for %s: %v", name, err)
					continue
				}

				// Get directory modification time
				info, err := file.Info()
				if err != nil {
					log.Printf("[WebUI] handleDatabaseInfo: failed to get directory info for %s: %v", name, err)
					continue
				}
				modTime = info.ModTime()
			} else {
				// Regular file
				info, err := file.Info()
				if err != nil {
					log.Printf("[WebUI] handleDatabaseInfo: failed to get file info for %s: %v", name, err)
					continue
				}
				size = info.Size()
				modTime = info.ModTime()
			}

			// Determine database type
			dbType := "other"
			switch {
			case strings.HasSuffix(name, ".mmdb"):
				dbType = "maxmind"
			case strings.HasSuffix(name, ".bleve") || strings.Contains(name, ".bleve"):
				dbType = "bleve"
			case strings.HasSuffix(name, ".json"):
				dbType = "json"
			case strings.HasSuffix(name, ".csv"):
				dbType = "csv"
			case name == "hosts":
				dbType = "hosts"
			case name == "services":
				dbType = "services"
			}

			dbFiles = append(dbFiles, DBFileInfo{
				Name:         name,
				Path:         fullPath,
				Size:         size,
				Type:         dbType,
				ModifiedTime: modTime.Unix(),
			})

			totalSize += size
		}
		log.Printf("[WebUI] handleDatabaseInfo: returning %d database files, total size: %d bytes", len(dbFiles), totalSize)
	}

	response := map[string]interface{}{
		"version":        version,
		"dbPath":         dbPath,
		"configRootPath": configRoot,
		"files":          dbFiles,
		"totalSize":      totalSize,
		"fileCount":      len(dbFiles),
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(response); err != nil {
		log.Printf("[WebUI] handleDatabaseInfo: failed to encode response: %v", err)
		http.Error(w, fmt.Sprintf("Failed to encode response: %v", err), http.StatusInternalServerError)
		return
	}

	log.Printf("[WebUI] handleDatabaseInfo: response sent successfully")
}

// handleUpdateDatabases handles database update requests
func (s *Server) handleUpdateDatabases(w http.ResponseWriter, r *http.Request) {
	log.Printf("[WebUI] handleUpdateDatabases called: method=%s", r.Method)

	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Start database download in background
	go func() {
		log.Printf("[WebUI] Starting database download...")
		// Download with force=true to update even if we have the current version
		if err := dbs.DownloadDBs("", true); err != nil {
			log.Printf("[WebUI] Database download failed: %v", err)
		} else {
			log.Printf("[WebUI] Database download completed successfully")
		}
	}()

	response := map[string]interface{}{
		"success": true,
		"message": "Database update started in background. Check logs for progress.",
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(response); err != nil {
		log.Printf("[WebUI] handleUpdateDatabases: failed to encode response: %v", err)
		http.Error(w, fmt.Sprintf("Failed to encode response: %v", err), http.StatusInternalServerError)
		return
	}

	log.Printf("[WebUI] handleUpdateDatabases: response sent successfully")
}

// getConfigRootPath returns the netcap config root path
func getConfigRootPath() string {
	configRoot := os.Getenv("NC_CONFIG_ROOT")
	if configRoot == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return filepath.Join("/usr", "local", "etc", "netcap")
		}
		return filepath.Join(home, ".config", "netcap")
	}
	return configRoot
}

// getDataBaseFolderPath returns the database folder path
func getDataBaseFolderPath() string {
	return filepath.Join(getConfigRootPath(), "dbs")
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

// handleVersion returns version information
func (s *Server) handleVersion(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	response := map[string]string{
		"version":         netcap.Version,
		"commit":          netcap.Commit,
		"gopacketVersion": netcap.GopacketVersion,
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(response); err != nil {
		http.Error(w, fmt.Sprintf("Failed to encode response: %v", err), http.StatusInternalServerError)
	}
}

// SystemInfo represents system hardware information
type SystemInfo struct {
	NumCPU       int    `json:"numCPU"`
	NumGoroutine int    `json:"numGoroutine"`
	TotalMemory  uint64 `json:"totalMemory"`
	FreeMemory   uint64 `json:"freeMemory"`
	UsedMemory   uint64 `json:"usedMemory"`
	GOOS         string `json:"goos"`
	GOARCH       string `json:"goarch"`
}

// handleSystemInfo returns system information
func (s *Server) handleSystemInfo(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)

	info := SystemInfo{
		NumCPU:       runtime.NumCPU(),
		NumGoroutine: runtime.NumGoroutine(),
		TotalMemory:  getTotalMemory(),
		FreeMemory:   getFreeMemory(),
		UsedMemory:   memStats.Sys,
		GOOS:         runtime.GOOS,
		GOARCH:       runtime.GOARCH,
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(info); err != nil {
		http.Error(w, fmt.Sprintf("Failed to encode response: %v", err), http.StatusInternalServerError)
	}
}

// calculateDirectorySize recursively calculates the total size of a directory
func calculateDirectorySize(path string) (int64, error) {
	var size int64
	err := filepath.Walk(path, func(_ string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() {
			size += info.Size()
		}
		return nil
	})
	return size, err
}

// DPIInfo represents DPI configuration and version information
type DPIInfo struct {
	Enabled              bool     `json:"enabled"`
	HasSupport           bool     `json:"hasSupport"`
	NDPIVersion          string   `json:"ndpiVersion"`
	LibprotoidentVersion string   `json:"libprotoidentVersion"`
	GoDPIVersion         string   `json:"goDpiVersion"`
	ActiveModules        []string `json:"activeModules"`
	AvailableModules     []string `json:"availableModules"`
	// External documentation links for supported protocols
	NDPIProtocolsURL          string `json:"ndpiProtocolsUrl"`
	LibprotoidentProtocolsURL string `json:"libprotoidentProtocolsUrl"`
}

// handleDPIInfo returns DPI configuration and version information
func (s *Server) handleDPIInfo(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	info := DPIInfo{
		Enabled:                   dpi.IsEnabled(),
		HasSupport:                dpi.HasDPISupport(),
		NDPIVersion:               dpi.NDPIVersion,
		LibprotoidentVersion:      dpi.LibprotoidentVersion,
		GoDPIVersion:              dpi.GoDPIVersion,
		AvailableModules:          []string{"ndpi", "lpi", "go"},
		NDPIProtocolsURL:          "https://github.com/ntop/nDPI/wiki/Supported-Protocols",
		LibprotoidentProtocolsURL: "https://github.com/wanduow/libprotoident/wiki/SupportedProtocols",
	}

	// Determine active modules based on what's enabled
	// Note: This is informational only - actual module configuration happens at startup
	if dpi.IsEnabled() {
		// When DPI is enabled, we assume all modules are active
		// In a production scenario, you'd track which modules were actually initialized
		info.ActiveModules = []string{"ndpi", "lpi", "go"}
	} else {
		info.ActiveModules = []string{}
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(info); err != nil {
		http.Error(w, fmt.Sprintf("Failed to encode response: %v", err), http.StatusInternalServerError)
	}
}

// ConfigOption represents a configuration option
type ConfigOption struct {
	Name        string      `json:"name"`
	Value       interface{} `json:"value"`
	Default     interface{} `json:"default"`
	Type        string      `json:"type"`
	Description string      `json:"description"`
	Category    string      `json:"category"`
	IsEditable  bool        `json:"isEditable"`
}

// handleConfig returns the current configuration
func (s *Server) handleConfig(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Configuration is always read-only in webUI
	config := s.getConfigOptions()

	response := map[string]interface{}{
		"readOnly": true,
		"options":  config,
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(response); err != nil {
		http.Error(w, fmt.Sprintf("Failed to encode response: %v", err), http.StatusInternalServerError)
	}
}

// getConfigOptions returns the current configuration options from capture package
// Note: This function accesses internal flags from the capture package
func (s *Server) getConfigOptions() []ConfigOption {
	// Import flag values from the capture package
	// We use the defaults package for default values
	options := []ConfigOption{
		// Input/Output Configuration
		{
			Name:        "input",
			Value:       s.getInputValue(),
			Default:     "",
			Type:        "string",
			Description: "Read specified file, can either be a pcap or netcap audit record file",
			Category:    "Input/Output",
			IsEditable:  false,
		},
		{
			Name:        "out",
			Value:       s.outDir,
			Default:     "",
			Type:        "string",
			Description: "Specify output directory, will be created if it does not exist",
			Category:    "Input/Output",
			IsEditable:  false,
		},
		{
			Name:        "compress",
			Value:       true,
			Default:     true,
			Type:        "bool",
			Description: "Compress output with gzip",
			Category:    "Input/Output",
			IsEditable:  false,
		},

		// Performance Configuration
		{
			Name:        "workers",
			Value:       "runtime.NumCPU()*2",
			Default:     "runtime.NumCPU()*2",
			Type:        "int",
			Description: "Number of workers",
			Category:    "Performance",
			IsEditable:  false,
		},
		{
			Name:        "pbuf",
			Value:       defaults.PacketBuffer,
			Default:     defaults.PacketBuffer,
			Type:        "int",
			Description: "Set packet buffer size, for channels that feed data to workers",
			Category:    "Performance",
			IsEditable:  false,
		},
		{
			Name:        "membuf-size",
			Value:       defaults.BufferSize,
			Default:     defaults.BufferSize,
			Type:        "int",
			Description: "Set size for membuf",
			Category:    "Performance",
			IsEditable:  false,
		},

		// Network Capture Configuration
		{
			Name:        "bpf",
			Value:       "",
			Default:     "",
			Type:        "string",
			Description: "Supply a BPF filter to use prior to processing packets with netcap",
			Category:    "Network Capture",
			IsEditable:  false,
		},
		{
			Name:        "iface",
			Value:       "",
			Default:     "",
			Type:        "string",
			Description: "Attach to network interface and capture in live mode",
			Category:    "Network Capture",
			IsEditable:  false,
		},
		{
			Name:        "promisc",
			Value:       true,
			Default:     true,
			Type:        "bool",
			Description: "Toggle promiscuous mode for live capture",
			Category:    "Network Capture",
			IsEditable:  false,
		},
		{
			Name:        "snaplen",
			Value:       defaults.SnapLen,
			Default:     defaults.SnapLen,
			Type:        "int",
			Description: "Configure snaplen for live capture from interface",
			Category:    "Network Capture",
			IsEditable:  false,
		},

		// Decoder Configuration
		{
			Name:        "include",
			Value:       "",
			Default:     "",
			Type:        "string",
			Description: "Include specific decoders (comma-separated)",
			Category:    "Decoders",
			IsEditable:  false,
		},
		{
			Name:        "exclude",
			Value:       "",
			Default:     "",
			Type:        "string",
			Description: "Exclude specific decoders (comma-separated)",
			Category:    "Decoders",
			IsEditable:  false,
		},
		{
			Name:        "base",
			Value:       "ethernet",
			Default:     "ethernet",
			Type:        "string",
			Description: "Select base layer",
			Category:    "Decoders",
			IsEditable:  false,
		},
		{
			Name:        "opts",
			Value:       "lazy",
			Default:     "lazy",
			Type:        "string",
			Description: "Select decoding options",
			Category:    "Decoders",
			IsEditable:  false,
		},
		{
			Name:        "payload",
			Value:       false,
			Default:     false,
			Type:        "bool",
			Description: "Capture payload for supported layers",
			Category:    "Decoders",
			IsEditable:  false,
		},
		{
			Name:        "context",
			Value:       true,
			Default:     true,
			Type:        "bool",
			Description: "Add packet flow context to selected audit records",
			Category:    "Decoders",
			IsEditable:  false,
		},

		// Database and Enrichment
		{
			Name:        "macDB",
			Value:       true,
			Default:     true,
			Type:        "bool",
			Description: "Use mac to vendor database for device profiling",
			Category:    "Database",
			IsEditable:  false,
		},
		{
			Name:        "ja3DB",
			Value:       true,
			Default:     true,
			Type:        "bool",
			Description: "Use ja3 database for device profiling",
			Category:    "Database",
			IsEditable:  false,
		},
		{
			Name:        "serviceDB",
			Value:       true,
			Default:     true,
			Type:        "bool",
			Description: "Use serviceDB for device profiling",
			Category:    "Database",
			IsEditable:  false,
		},
		{
			Name:        "geoDB",
			Value:       false,
			Default:     false,
			Type:        "bool",
			Description: "Use geolocation for device profiling",
			Category:    "Database",
			IsEditable:  false,
		},
		{
			Name:        "dpi",
			Value:       dpi.IsEnabled(),
			Default:     false,
			Type:        "bool",
			Description: "Use DPI libs to enrich IPProfile audit records",
			Category:    "Database",
			IsEditable:  false,
		},
		{
			Name:        "reverse-dns",
			Value:       false,
			Default:     false,
			Type:        "bool",
			Description: "Resolve IPs to domains via the operating systems default DNS resolver",
			Category:    "Database",
			IsEditable:  false,
		},
		{
			Name:        "local-dns",
			Value:       false,
			Default:     false,
			Type:        "bool",
			Description: "Resolve DNS locally via hosts file in the database dir",
			Category:    "Database",
			IsEditable:  false,
		},

		// TCP Reassembly Configuration
		{
			Name:        "reassemble-connections",
			Value:       true,
			Default:     true,
			Type:        "bool",
			Description: "Reassemble TCP connections",
			Category:    "TCP Reassembly",
			IsEditable:  false,
		},
		{
			Name:        "flushevery",
			Value:       defaults.FlushEvery,
			Default:     defaults.FlushEvery,
			Type:        "int",
			Description: "Flush assembler every N packets",
			Category:    "TCP Reassembly",
			IsEditable:  false,
		},
		{
			Name:        "checksum",
			Value:       defaults.Checksum,
			Default:     defaults.Checksum,
			Type:        "bool",
			Description: "Check TCP checksum",
			Category:    "TCP Reassembly",
			IsEditable:  false,
		},
		{
			Name:        "nooptcheck",
			Value:       defaults.NoOptCheck,
			Default:     defaults.NoOptCheck,
			Type:        "bool",
			Description: "Do not check TCP options (useful to ignore MSS on captures with TSO)",
			Category:    "TCP Reassembly",
			IsEditable:  false,
		},
		{
			Name:        "ignorefsmerr",
			Value:       defaults.IgnoreFSMErr,
			Default:     defaults.IgnoreFSMErr,
			Type:        "bool",
			Description: "Ignore TCP FSM errors",
			Category:    "TCP Reassembly",
			IsEditable:  false,
		},
		{
			Name:        "allowmissinginit",
			Value:       defaults.AllowMissingInit,
			Default:     defaults.AllowMissingInit,
			Type:        "bool",
			Description: "Support streams without SYN/SYN+ACK/ACK sequence",
			Category:    "TCP Reassembly",
			IsEditable:  false,
		},
		{
			Name:        "close-pending-timeout",
			Value:       defaults.ClosePendingTimeout.String(),
			Default:     defaults.ClosePendingTimeout.String(),
			Type:        "duration",
			Description: "Reassembly: close connections that have pending bytes",
			Category:    "TCP Reassembly",
			IsEditable:  false,
		},
		{
			Name:        "close-inactive-timeout",
			Value:       defaults.CloseInactiveTimeout.String(),
			Default:     defaults.CloseInactiveTimeout.String(),
			Type:        "duration",
			Description: "Reassembly: close connections that are inactive",
			Category:    "TCP Reassembly",
			IsEditable:  false,
		},

		// Output Format Configuration
		{
			Name:        "proto",
			Value:       true,
			Default:     true,
			Type:        "bool",
			Description: "Output data as protobuf",
			Category:    "Output Format",
			IsEditable:  false,
		},
		{
			Name:        "json",
			Value:       false,
			Default:     false,
			Type:        "bool",
			Description: "Output data as JSON",
			Category:    "Output Format",
			IsEditable:  false,
		},
		{
			Name:        "csv",
			Value:       false,
			Default:     false,
			Type:        "bool",
			Description: "Output data as CSV",
			Category:    "Output Format",
			IsEditable:  false,
		},

		// Elastic Configuration
		{
			Name:        "elastic",
			Value:       false,
			Default:     false,
			Type:        "bool",
			Description: "Write data to elastic db",
			Category:    "Elastic",
			IsEditable:  false,
		},
		{
			Name:        "elastic-addrs",
			Value:       "",
			Default:     "",
			Type:        "string",
			Description: "Elastic db endpoints to write data to",
			Category:    "Elastic",
			IsEditable:  false,
		},
		{
			Name:        "elastic-user",
			Value:       "",
			Default:     "",
			Type:        "string",
			Description: "Elastic db username",
			Category:    "Elastic",
			IsEditable:  false,
		},

		// Advanced Configuration
		{
			Name:        "debug",
			Value:       s.GetDebugLogging(),
			Default:     false,
			Type:        "bool",
			Description: "Enable debug logging (can be toggled at runtime)",
			Category:    "Advanced",
			IsEditable:  true,
		},
		{
			Name:        "buf",
			Value:       true,
			Default:     true,
			Type:        "bool",
			Description: "Buffer data in memory before writing to disk",
			Category:    "Advanced",
			IsEditable:  false,
		},
		{
			Name:        "ignore-unknown",
			Value:       true,
			Default:     true,
			Type:        "bool",
			Description: "Disable writing unknown packets into a pcap file",
			Category:    "Advanced",
			IsEditable:  false,
		},
		{
			Name:        "free-os-mem",
			Value:       0,
			Default:     0,
			Type:        "int",
			Description: "Free OS memory every X minutes, disabled if set to 0",
			Category:    "Advanced",
			IsEditable:  false,
		},
		{
			Name:        "conn-flush-interval",
			Value:       defaults.ConnFlushInterval,
			Default:     defaults.ConnFlushInterval,
			Type:        "int",
			Description: "Flush connections every X flows",
			Category:    "Advanced",
			IsEditable:  false,
		},
		{
			Name:        "conn-timeout",
			Value:       defaults.ConnTimeOut.String(),
			Default:     defaults.ConnTimeOut.String(),
			Type:        "duration",
			Description: "Close connections older than X seconds",
			Category:    "Advanced",
			IsEditable:  false,
		},
		{
			Name:        "flow-flush-interval",
			Value:       defaults.FlowFlushInterval,
			Default:     defaults.FlowFlushInterval,
			Type:        "int",
			Description: "Flushes flows every X flows",
			Category:    "Advanced",
			IsEditable:  false,
		},
		{
			Name:        "flow-timeout",
			Value:       defaults.FlowTimeOut.String(),
			Default:     defaults.FlowTimeOut.String(),
			Type:        "duration",
			Description: "Closes flows older than flowTimeout",
			Category:    "Advanced",
			IsEditable:  false,
		},
	}

	return options
}

// getInputValue returns the input file(s) as a displayable string
func (s *Server) getInputValue() string {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if len(s.inputFiles) == 0 {
		return ""
	}
	if len(s.inputFiles) == 1 {
		return s.inputFiles[0]
	}
	return fmt.Sprintf("%d files", len(s.inputFiles))
}

// handleDebugToggle handles runtime debug logging toggle requests
func (s *Server) handleDebugToggle(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		// Return current debug state
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"enabled": s.GetDebugLogging(),
		})
		return
	}

	if r.Method == http.MethodPost {
		// Update debug state
		var req struct {
			Enabled bool `json:"enabled"`
		}

		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, fmt.Sprintf("Invalid request: %v", err), http.StatusBadRequest)
			return
		}

		s.SetDebugLogging(req.Enabled)

		// Update the collector's log level if available
		s.mu.RLock()
		collector := s.collector
		s.mu.RUnlock()

		if collector != nil {
			collector.SetLogLevel(req.Enabled)
		}

		log.Printf("[WebUI] Debug logging %s", map[bool]string{true: "enabled", false: "disabled"}[req.Enabled])

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"enabled": req.Enabled,
			"message": fmt.Sprintf("Debug logging %s", map[bool]string{true: "enabled", false: "disabled"}[req.Enabled]),
		})
		return
	}

	http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
}
