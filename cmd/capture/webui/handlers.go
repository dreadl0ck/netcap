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
	"archive/zip"
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync/atomic"
	"time"

	"github.com/dreadl0ck/netcap"
	"github.com/dreadl0ck/netcap/dbs"
	"github.com/dreadl0ck/netcap/defaults"
	"github.com/dreadl0ck/netcap/dpi"
	netio "github.com/dreadl0ck/netcap/io"
	"github.com/dreadl0ck/netcap/types"
)

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

	// Get logo sub text from runtime config if available
	var logoSubText string
	if s.runtimeConfig != nil {
		logoSubText = s.runtimeConfig.LogoSubText
	}

	response := StatusResponse{
		IsProcessing:    s.isProcessing,
		OutputDir:       s.outDir,
		InputFiles:      inputFiles,
		ServerStarted:   serverStartTime,
		ActiveInputFile: s.activeInputFile,
		IsMultiFile:     len(inputFiles) > 1,
		IsServiceMode:   s.isServiceMode,
		IsLiveMode:      s.isLiveMode,
		SessionID:       s.currentSession, // Include current session ID in service mode
		LogoSubText:     logoSubText,
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

	// In service mode, return sessions as files
	if s.isServiceMode && s.sessionManager != nil {
		clientIP := s.getUserIP(r)
		sessions := s.sessionManager.GetSessionsForIP(clientIP)

		files := make([]FileInfo, 0)

		// First, add preloaded pcaps (visible to all users)
		allSessions := s.sessionManager.GetAllSessions()
		for _, session := range allSessions {
			if !session.IsPreloaded {
				continue
			}

			fileInfo := FileInfo{
				ID:               session.SessionID, // Use session ID as file ID
				Name:             session.InputFilename,
				Path:             session.InputFile,
				Size:             session.InputFileSize,
				ModifiedTime:     session.UploadTimestamp.Unix(),
				IsCompleted:      session.Status == StatusCompleted,
				BPFFilter:        session.BPFFilter,
				ProcessingTime:   session.ProcessingTime,
				SessionID:        session.SessionID,
				HasReportedIssue: session.HasReportedIssue,
			}

			// Add error if failed
			if session.Status == StatusFailed && session.ErrorMessage != "" {
				fileInfo.Error = &session.ErrorMessage
				if session.ErrorLogPath != "" {
					fileInfo.ErrorLogPath = &session.ErrorLogPath
				}
			}

			files = append(files, fileInfo)
		}

		// Then add user's own uploaded files
		for _, session := range sessions {
			if session.IsPreloaded {
				continue
			}

			fileInfo := FileInfo{
				ID:               session.SessionID, // Use session ID as file ID
				Name:             session.InputFilename,
				Path:             session.InputFile,
				Size:             session.InputFileSize,
				ModifiedTime:     session.UploadTimestamp.Unix(),
				IsCompleted:      session.Status == StatusCompleted,
				BPFFilter:        session.BPFFilter,
				ProcessingTime:   session.ProcessingTime,
				SessionID:        session.SessionID,
				HasReportedIssue: session.HasReportedIssue,
			}

			// Add error if failed
			if session.Status == StatusFailed && session.ErrorMessage != "" {
				fileInfo.Error = &session.ErrorMessage
				if session.ErrorLogPath != "" {
					fileInfo.ErrorLogPath = &session.ErrorLogPath
				}
			}

			files = append(files, fileInfo)
		}

		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(files); err != nil {
			http.Error(w, fmt.Sprintf("Failed to encode response: %v", err), http.StatusInternalServerError)
		}
		return
	}

	// Local mode: return actual input files
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
	fileBPFFilters := make(map[string]string)
	for k, v := range s.fileBPFFilters {
		fileBPFFilters[k] = v
	}
	fileProcessingTime := make(map[string]float64)
	for k, v := range s.fileProcessingTime {
		fileProcessingTime[k] = v
	}
	reportedIssues := make(map[string]bool)
	for k, v := range s.reportedIssues {
		reportedIssues[k] = v
	}
	s.mu.RUnlock()

	files := make([]FileInfo, 0)
	for _, path := range inputFiles {
		info, err := os.Stat(path)
		if err != nil {
			continue
		}

		// Calculate file hash - use this as the file ID
		hash := calculateFileHash(path)
		fileID := hash
		if fileID == "" {
			// Fallback to basename if hash calculation fails
			fileID = filepath.Base(path)
		}

		// Store the mapping from ID to path
		s.mu.Lock()
		s.fileIDToPath[fileID] = path
		s.mu.Unlock()

		fileInfo := FileInfo{
			ID:               fileID,
			Name:             filepath.Base(path),
			Path:             path,
			Size:             info.Size(),
			ModifiedTime:     info.ModTime().Unix(),
			IsCompleted:      completedFiles[path],
			BPFFilter:        fileBPFFilters[path],
			ProcessingTime:   fileProcessingTime[path],
			Hash:             hash,
			HasReportedIssue: reportedIssues[hash],
		}

		// Add error information if available
		if ferr, hasError := fileErrors[path]; hasError {
			fileInfo.Error = &ferr.Error
			if ferr.ErrorLogPath != "" {
				fileInfo.ErrorLogPath = &ferr.ErrorLogPath
			}
		}

		files = append(files, fileInfo)
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(files); err != nil {
		http.Error(w, fmt.Sprintf("Failed to encode response: %v", err), http.StatusInternalServerError)
	}
}

// handleAuditFiles delegates to the shared handler
func (s *Server) handleAuditFiles(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	outDir := s.outDir

	// In service mode, use the current session's output directory
	if s.isServiceMode && s.currentSession != "" && s.sessionManager != nil {
		if session, ok := s.sessionManager.GetSession(s.currentSession); ok {
			outDir = session.OutputDir
		}
	}
	s.mu.RUnlock()

	HandleAuditFiles(outDir)(w, r)
}

// handleLogFiles delegates to the shared handler
func (s *Server) handleLogFiles(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	outDir := s.outDir

	// In service mode, use the current session's output directory
	if s.isServiceMode && s.currentSession != "" && s.sessionManager != nil {
		if session, ok := s.sessionManager.GetSession(s.currentSession); ok {
			outDir = session.OutputDir
		}
	}
	s.mu.RUnlock()

	HandleLogFiles(outDir)(w, r)
}

// handleAuditRecords delegates to the shared handler
func (s *Server) handleAuditRecords(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	outDir := s.outDir

	// In service mode, use the current session's output directory
	if s.isServiceMode && s.currentSession != "" && s.sessionManager != nil {
		if session, ok := s.sessionManager.GetSession(s.currentSession); ok {
			outDir = session.OutputDir
		}
	}
	s.mu.RUnlock()

	HandleAuditRecords(outDir)(w, r)
}

// handleLogContent delegates to the shared handler
func (s *Server) handleLogContent(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	outDir := s.outDir

	// In service mode, use the current session's output directory
	if s.isServiceMode && s.currentSession != "" && s.sessionManager != nil {
		if session, ok := s.sessionManager.GetSession(s.currentSession); ok {
			outDir = session.OutputDir
		}
	}
	s.mu.RUnlock()

	HandleLogContent(outDir)(w, r)
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

	// Service mode: find session by input file path
	// This handles both preloaded pcaps and user-uploaded captures
	if s.isServiceMode && s.sessionManager != nil {
		clientIP := s.getUserIP(r)

		// Search in user's sessions and preloaded sessions
		allSessions := s.sessionManager.GetAllSessions()
		var matchedSession *SessionInfo

		for _, session := range allSessions {
			// Match by input file path
			if session.InputFile == req.InputFile {
				// For preloaded sessions (IsPreloaded=true), any user can access
				// For user sessions, check IP ownership
				if session.IsPreloaded || session.IP == clientIP {
					matchedSession = session
					break
				}
			}
		}

		if matchedSession == nil {
			log.Printf("[WebUI] Session not found for input file: %s (IP: %s)", req.InputFile, clientIP)
			http.Error(w, "File not found or access denied", http.StatusNotFound)
			return
		}

		// Check if session is completed
		if matchedSession.Status != StatusCompleted {
			log.Printf("[WebUI] Session %s not completed yet (status: %s)", matchedSession.SessionID, matchedSession.Status)
			http.Error(w, fmt.Sprintf("Analysis not yet complete (status: %s)", matchedSession.Status), http.StatusBadRequest)
			return
		}

		// Set active session and output directory
		s.currentSession = matchedSession.SessionID
		s.outDir = matchedSession.OutputDir
		s.activeInputFile = matchedSession.InputFile

		log.Printf("[WebUI] Active session changed to: %s (file: %s, outputDir: %s)",
			matchedSession.SessionID, matchedSession.InputFilename, matchedSession.OutputDir)

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success":         true,
			"outputDir":       matchedSession.OutputDir,
			"activeInputFile": matchedSession.InputFile,
		})
		return
	}

	// Local mode: original logic
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

	// Get the actual output directory for this file
	newOutDir, exists := s.fileOutputDirs[req.InputFile]
	if !exists {
		// For single-file mode, use the current outDir as-is (it's already the correct directory)
		// For multi-file mode, calculate the subdirectory
		if len(s.inputFiles) == 1 {
			// Single file mode: outDir is already the correct per-file directory
			newOutDir = s.baseOutDir
			log.Printf("[WebUI] Single-file mode: using baseOutDir as-is: %s", newOutDir)
		} else {
			// Multi-file mode: calculate the subdirectory
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
			newOutDir = filepath.Join(s.baseOutDir, dirName)
			log.Printf("[WebUI] Multi-file mode: calculated path: %s (baseOutDir=%s, dirName=%s)",
				newOutDir, s.baseOutDir, dirName)
		}
	} else {
		log.Printf("[WebUI] Output directory found in map for file '%s': %s", req.InputFile, newOutDir)
	}

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

// handleReanalyze handles requests to reanalyze a PCAP file
// This deletes all existing audit records and queues a new analysis job
func (s *Server) handleReanalyze(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		InputFile string `json:"inputFile"`
		SessionID string `json:"sessionId,omitempty"` // For service mode
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, fmt.Sprintf("Invalid request: %v", err), http.StatusBadRequest)
		return
	}

	if req.InputFile == "" && req.SessionID == "" {
		http.Error(w, "Input file or session ID required", http.StatusBadRequest)
		return
	}

	// Service mode: handle by session ID
	if s.isServiceMode && s.sessionManager != nil && req.SessionID != "" {
		clientIP := s.getUserIP(r)
		session, ok := s.sessionManager.GetSession(req.SessionID)
		if !ok {
			http.Error(w, "Session not found", http.StatusNotFound)
			return
		}

		// Check access rights
		if !session.IsPreloaded && session.IP != clientIP {
			http.Error(w, "Access denied", http.StatusForbidden)
			return
		}

		// Check if already processing
		if session.Status == StatusProcessing || session.Status == StatusQueued {
			http.Error(w, "Analysis is already in progress", http.StatusConflict)
			return
		}

		// Verify input file exists
		if _, err := os.Stat(session.InputFile); os.IsNotExist(err) {
			http.Error(w, "Input file no longer exists", http.StatusNotFound)
			return
		}

		// Delete all existing audit records in the output directory
		if err := s.deleteAuditRecords(session.OutputDir); err != nil {
			log.Printf("[WebUI] Error deleting audit records for reanalysis: %v", err)
			http.Error(w, fmt.Sprintf("Failed to delete existing data: %v", err), http.StatusInternalServerError)
			return
		}

		// Reset session status
		s.sessionManager.UpdateSessionStatus(req.SessionID, StatusQueued, "", "")
		s.sessionManager.UpdateSessionProcessingTime(req.SessionID, 0)

		// Get DPI configuration
		s.mu.RLock()
		enableDPI := s.dpiConfigured
		s.mu.RUnlock()

		// Load BPF filter from saved configuration
		bpfConfig := s.loadBPFConfig()

		// Create new analysis job
		job := &AnalysisJob{
			SessionID:       req.SessionID,
			InputFile:       session.InputFile,
			OutputDir:       session.OutputDir,
			EnableDPI:       enableDPI,
			BPFFilter:       bpfConfig.Filter,
			IncludeDecoders: "",
			ExcludeDecoders: "",
		}

		// Queue the job
		select {
		case s.jobQueue <- job:
			atomic.AddInt64(&s.jobsScheduled, 1)
			log.Printf("[WebUI] Reanalysis job queued for session %s: %s", req.SessionID, session.InputFilename)
		default:
			http.Error(w, "Job queue is full", http.StatusServiceUnavailable)
			return
		}

		respondJSON(w, http.StatusOK, map[string]interface{}{
			"success":   true,
			"message":   "Reanalysis queued successfully",
			"sessionId": req.SessionID,
		})
		return
	}

	// Local mode: handle by input file path
	s.mu.Lock()

	// Find the input file in our list
	found := false
	for _, f := range s.inputFiles {
		if f == req.InputFile {
			found = true
			break
		}
	}

	if !found {
		s.mu.Unlock()
		http.Error(w, "Input file not found in list", http.StatusNotFound)
		return
	}

	// Check if already processing (not completed)
	if !s.completedFiles[req.InputFile] {
		// Could be still processing
		if _, hasError := s.fileErrors[req.InputFile]; !hasError {
			s.mu.Unlock()
			http.Error(w, "File is currently being processed", http.StatusConflict)
			return
		}
	}

	// Get the output directory for this file
	outputDir, exists := s.fileOutputDirs[req.InputFile]
	if !exists {
		// Calculate the subdirectory
		dirName := filepath.Base(req.InputFile)
		for ext := filepath.Ext(dirName); ext != ""; ext = filepath.Ext(dirName) {
			dirName = strings.TrimSuffix(dirName, ext)
		}
		outputDir = filepath.Join(s.baseOutDir, dirName)
	}

	// Reset completion status and errors
	delete(s.completedFiles, req.InputFile)
	delete(s.fileErrors, req.InputFile)
	delete(s.fileProcessingTime, req.InputFile)

	// Get DPI configuration
	enableDPI := s.dpiConfigured
	s.mu.Unlock()

	// Verify input file exists
	if _, err := os.Stat(req.InputFile); os.IsNotExist(err) {
		http.Error(w, "Input file no longer exists", http.StatusNotFound)
		return
	}

	// Delete all existing audit records in the output directory
	if err := s.deleteAuditRecords(outputDir); err != nil {
		log.Printf("[WebUI] Error deleting audit records for reanalysis: %v", err)
		http.Error(w, fmt.Sprintf("Failed to delete existing data: %v", err), http.StatusInternalServerError)
		return
	}

	// Load BPF filter from saved configuration
	bpfConfig := s.loadBPFConfig()

	// Create analysis job using filename as session ID (like in handleUpload)
	sessionID := filepath.Base(req.InputFile)
	job := &AnalysisJob{
		SessionID:       sessionID,
		InputFile:       req.InputFile,
		OutputDir:       outputDir,
		EnableDPI:       enableDPI,
		BPFFilter:       bpfConfig.Filter,
		IncludeDecoders: "",
		ExcludeDecoders: "",
	}

	// Queue the job
	if s.jobQueue == nil {
		http.Error(w, "Analysis queue not available", http.StatusServiceUnavailable)
		return
	}

	select {
	case s.jobQueue <- job:
		atomic.AddInt64(&s.jobsScheduled, 1)
		log.Printf("[WebUI] Reanalysis job queued for file: %s -> %s", req.InputFile, outputDir)
	default:
		http.Error(w, "Job queue is full", http.StatusServiceUnavailable)
		return
	}

	respondJSON(w, http.StatusOK, map[string]interface{}{
		"success":  true,
		"message":  "Reanalysis queued successfully",
		"filename": filepath.Base(req.InputFile),
		"path":     req.InputFile,
	})
}

// deleteAuditRecords removes all audit record files from the output directory
func (s *Server) deleteAuditRecords(outputDir string) error {
	if outputDir == "" {
		return fmt.Errorf("output directory not specified")
	}

	// Check if directory exists
	if _, err := os.Stat(outputDir); os.IsNotExist(err) {
		// Directory doesn't exist, nothing to delete
		return nil
	}

	// Read directory contents
	entries, err := os.ReadDir(outputDir)
	if err != nil {
		return fmt.Errorf("failed to read output directory: %w", err)
	}

	deletedCount := 0
	for _, entry := range entries {
		if entry.IsDir() {
			// Delete subdirectories like "files", "tcp", "udp"
			subDir := filepath.Join(outputDir, entry.Name())
			if err := os.RemoveAll(subDir); err != nil {
				log.Printf("[WebUI] Warning: failed to delete subdirectory %s: %v", subDir, err)
			} else {
				log.Printf("[WebUI] Deleted subdirectory: %s", subDir)
				deletedCount++
			}
		} else {
			// Delete files (ncap.gz files, logs, etc.)
			filePath := filepath.Join(outputDir, entry.Name())
			if err := os.Remove(filePath); err != nil {
				log.Printf("[WebUI] Warning: failed to delete file %s: %v", filePath, err)
			} else {
				deletedCount++
			}
		}
	}

	log.Printf("[WebUI] Deleted %d items from output directory: %s", deletedCount, outputDir)
	return nil
}

// handleVersion returns version information
func (s *Server) handleVersion(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Get short version of commit hash (first 7 characters)
	shortCommit := netcap.Commit
	if len(shortCommit) > 7 {
		shortCommit = shortCommit[:7]
	}

	response := map[string]string{
		"version":         netcap.Version,
		"commit":          shortCommit,
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

// NetworkInterfaceInfo represents a network interface
type NetworkInterfaceInfo struct {
	Index        int      `json:"index"`
	Name         string   `json:"name"`
	Flags        string   `json:"flags"`
	HardwareAddr string   `json:"hardwareAddr"`
	MTU          int      `json:"mtu"`
	Addrs        []string `json:"addrs"`
}

// handleNetworkInterfaces returns list of available network interfaces
func (s *Server) handleNetworkInterfaces(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	interfaces, err := net.Interfaces()
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to get network interfaces: %v", err), http.StatusInternalServerError)
		return
	}

	result := make([]NetworkInterfaceInfo, 0, len(interfaces))
	for _, nic := range interfaces {
		// Get IP addresses for this interface
		addrs, err := nic.Addrs()
		var addrStrings []string
		if err == nil {
			for _, addr := range addrs {
				addrStrings = append(addrStrings, addr.String())
			}
		}

		result = append(result, NetworkInterfaceInfo{
			Index:        nic.Index,
			Name:         nic.Name,
			Flags:        nic.Flags.String(),
			HardwareAddr: nic.HardwareAddr.String(),
			MTU:          nic.MTU,
			Addrs:        addrStrings,
		})
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(result); err != nil {
		http.Error(w, fmt.Sprintf("Failed to encode response: %v", err), http.StatusInternalServerError)
	}
}

// DPIInfo represents DPI configuration and version information
type DPIInfo struct {
	Enabled              bool                `json:"enabled"`
	HasSupport           bool                `json:"hasSupport"`
	NDPIVersion          string              `json:"ndpiVersion"`
	LibprotoidentVersion string              `json:"libprotoidentVersion"`
	GoDPIVersion         string              `json:"goDpiVersion"`
	ActiveModules        []string            `json:"activeModules"`
	AvailableModules     []string            `json:"availableModules"`
	ModuleProtocols      map[string][]string `json:"moduleProtocols"` // New: protocols supported by each module
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

	// Use the configured DPI state (from -dpi flag) rather than runtime state
	// Runtime state may be false after processing completes and DPI is destroyed,
	// but we want to show whether DPI was used during processing
	s.mu.RLock()
	dpiConfigured := s.dpiConfigured
	s.mu.RUnlock()

	info := DPIInfo{
		Enabled:                   dpiConfigured,
		HasSupport:                dpi.HasDPISupport(),
		NDPIVersion:               dpi.NDPIVersion,
		LibprotoidentVersion:      dpi.LibprotoidentVersion,
		GoDPIVersion:              dpi.GoDPIVersion,
		AvailableModules:          []string{"ndpi", "lpi", "go"},
		ModuleProtocols:           dpi.GetModuleProtocols(), // New: fetch protocols from each module
		NDPIProtocolsURL:          "https://github.com/ntop/nDPI/wiki/Supported-Protocols",
		LibprotoidentProtocolsURL: "https://github.com/wanduow/libprotoident/wiki/SupportedProtocols",
	}

	// Determine active modules based on what's configured
	// Note: This reflects what was configured at startup via the -dpi flag
	if dpiConfigured {
		// When DPI was configured, all modules were active during processing
		info.ActiveModules = []string{"ndpi", "lpi", "go"}
	} else {
		info.ActiveModules = []string{}
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(info); err != nil {
		http.Error(w, fmt.Sprintf("Failed to encode response: %v", err), http.StatusInternalServerError)
	}
}

// handleDPIPreferences handles getting and setting DPI module preferences for the current user
func (s *Server) handleDPIPreferences(w http.ResponseWriter, r *http.Request) {
	userIP := s.getUserIP(r)

	switch r.Method {
	case http.MethodGet:
		// Get user's DPI preferences
		prefs := s.GetDPIPreferences(userIP)
		if prefs == nil {
			// Return default: all modules enabled if DPI was configured
			s.mu.RLock()
			dpiConfigured := s.dpiConfigured
			s.mu.RUnlock()

			defaultModules := []string{}
			if dpiConfigured {
				defaultModules = []string{"ndpi", "lpi", "go"}
			}
			prefs = &UserDPIPreferences{
				EnabledModules: defaultModules,
				LastUpdated:    time.Now(),
			}
		}

		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(prefs); err != nil {
			http.Error(w, fmt.Sprintf("Failed to encode response: %v", err), http.StatusInternalServerError)
		}

	case http.MethodPost:
		// Set user's DPI preferences
		var prefs UserDPIPreferences
		if err := json.NewDecoder(r.Body).Decode(&prefs); err != nil {
			http.Error(w, fmt.Sprintf("Invalid request body: %v", err), http.StatusBadRequest)
			return
		}

		// Validate that all specified modules are available
		availableModules := map[string]bool{"ndpi": true, "lpi": true, "go": true}
		for _, module := range prefs.EnabledModules {
			if !availableModules[module] {
				http.Error(w, fmt.Sprintf("Invalid module: %s", module), http.StatusBadRequest)
				return
			}
		}

		s.SetDPIPreferences(userIP, &prefs)

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": true,
			"message": "DPI preferences updated successfully",
		})

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
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

	// Check if we're in service mode with a current session
	var sessionConfig *SessionInfo
	sessionID := ""

	s.mu.RLock()
	if s.isServiceMode && s.currentSession != "" && s.sessionManager != nil {
		if session, ok := s.sessionManager.GetSession(s.currentSession); ok {
			sessionConfig = session
			sessionID = s.currentSession
		}
	}
	s.mu.RUnlock()

	// Configuration is always read-only in webUI
	// Pass session config if available for session-specific configuration
	config := s.getConfigOptions(sessionConfig)

	response := map[string]interface{}{
		"readOnly":      true,
		"isServiceMode": s.isServiceMode,
		"options":       config,
	}

	// Add session information if in service mode with active session
	if sessionID != "" {
		response["sessionId"] = sessionID
		response["sessionSpecific"] = true
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(response); err != nil {
		http.Error(w, fmt.Sprintf("Failed to encode response: %v", err), http.StatusInternalServerError)
	}
}

// getConfigOptions returns the current configuration options from capture package
// Note: This function uses the RuntimeConfig passed during server initialization to show actual values
// If sessionConfig is provided, it will use session-specific configuration values
func (s *Server) getConfigOptions(sessionConfig *SessionInfo) []ConfigOption {
	// Use runtime config values if available, otherwise fall back to defaults
	rc := s.runtimeConfig

	// Determine input and output based on session or global config
	inputValue := s.getInputValue()
	outputValue := s.outDir

	if sessionConfig != nil {
		inputValue = sessionConfig.InputFile
		outputValue = sessionConfig.OutputDir
	}

	// Get values from runtime config or use defaults
	// Note: Some defaults are hardcoded here as they're not defined in the defaults package
	compressValue := true // default compression enabled
	bufferValue := true   // default buffering enabled
	workersValue := runtime.NumCPU() * 2
	pbufValue := defaults.PacketBuffer
	membufValue := defaults.BufferSize
	ifaceValue := ""
	promiscValue := true // default promiscuous mode enabled
	snaplenValue := defaults.SnapLen
	baseLayerValue := "ethernet" // default base layer
	decodeOptsValue := "lazy"    // default decode options
	contextValue := true         // default context enabled
	macDBValue := true       // default mac database enabled
	ja3DBValue := true       // default ja3 database enabled
	serviceDBValue := true   // default service database enabled
	geoDBValue := false      // default geolocation disabled
	reverseDNSValue := false // default reverse DNS disabled
	localDNSValue := false   // default local DNS disabled
	reassembleValue := true  // default reassembly enabled
	flushEveryValue := defaults.FlushEvery
	checksumValue := defaults.Checksum
	noOptCheckValue := defaults.NoOptCheck
	ignoreFSMErrValue := defaults.IgnoreFSMErr
	allowMissingInitValue := defaults.AllowMissingInit
	closePendingTimeoutValue := defaults.ClosePendingTimeout.String()
	closeInactiveTimeoutValue := defaults.CloseInactiveTimeout.String()
	protoValue := true // default protobuf output enabled
	jsonValue := false // default JSON output disabled
	csvValue := false  // default CSV output disabled
	elasticValue := false
	elasticAddrsValue := ""
	elasticUserValue := ""
	ignoreUnknownValue := true // default ignore unknown packets
	freeOSMemValue := 0
	connFlushIntervalValue := defaults.ConnFlushInterval
	connTimeoutValue := defaults.ConnTimeOut.String()
	flowFlushIntervalValue := defaults.FlowFlushInterval
	flowTimeoutValue := defaults.FlowTimeOut.String()

	// Override with actual runtime values if available
	if rc != nil {
		compressValue = rc.Compress
		bufferValue = rc.Buffer
		if rc.Workers > 0 {
			workersValue = rc.Workers
		}
		if rc.PacketBuffer > 0 {
			pbufValue = rc.PacketBuffer
		}
		if rc.MemBufSize > 0 {
			membufValue = rc.MemBufSize
		}
		ifaceValue = rc.Interface
		promiscValue = rc.PromiscMode
		if rc.SnapLen > 0 {
			snaplenValue = rc.SnapLen
		}
		if rc.BaseLayer != "" {
			baseLayerValue = rc.BaseLayer
		}
		if rc.DecodeOptions != "" {
			decodeOptsValue = rc.DecodeOptions
		}
		contextValue = rc.Context
		macDBValue = rc.MacDB
		ja3DBValue = rc.Ja3DB
		serviceDBValue = rc.ServiceDB
		geoDBValue = rc.GeoDB
		reverseDNSValue = rc.ReverseDNS
		localDNSValue = rc.LocalDNS
		reassembleValue = rc.ReassembleConnections
		if rc.FlushEvery > 0 {
			flushEveryValue = rc.FlushEvery
		}
		checksumValue = rc.Checksum
		noOptCheckValue = rc.NoOptCheck
		ignoreFSMErrValue = rc.IgnoreFSMErr
		allowMissingInitValue = rc.AllowMissingInit
		if rc.ClosePendingTimeout > 0 {
			closePendingTimeoutValue = rc.ClosePendingTimeout.String()
		}
		if rc.CloseInactiveTimeout > 0 {
			closeInactiveTimeoutValue = rc.CloseInactiveTimeout.String()
		}
		protoValue = rc.Proto
		jsonValue = rc.JSON
		csvValue = rc.CSV
		elasticValue = rc.Elastic
		elasticAddrsValue = rc.ElasticAddrs
		elasticUserValue = rc.ElasticUser
		ignoreUnknownValue = rc.IgnoreUnknown
		freeOSMemValue = rc.FreeOSMemory
		if rc.ConnFlushInterval > 0 {
			connFlushIntervalValue = rc.ConnFlushInterval
		}
		if rc.ConnTimeout > 0 {
			connTimeoutValue = rc.ConnTimeout.String()
		}
		if rc.FlowFlushInterval > 0 {
			flowFlushIntervalValue = rc.FlowFlushInterval
		}
		if rc.FlowTimeout > 0 {
			flowTimeoutValue = rc.FlowTimeout.String()
		}
	}

	options := []ConfigOption{
		// Input/Output Configuration
		{
			Name:        "input",
			Value:       inputValue,
			Default:     "",
			Type:        "string",
			Description: "Read specified file, can either be a pcap or netcap audit record file",
			Category:    "Input/Output",
			IsEditable:  false,
		},
		{
			Name:        "out",
			Value:       outputValue,
			Default:     "",
			Type:        "string",
			Description: "Specify output directory, will be created if it does not exist",
			Category:    "Input/Output",
			IsEditable:  false,
		},
		{
			Name:        "compress",
			Value:       compressValue,
			Default:     true,
			Type:        "bool",
			Description: "Compress output with gzip",
			Category:    "Input/Output",
			IsEditable:  false,
		},

		// Performance Configuration
		{
			Name:        "workers",
			Value:       workersValue,
			Default:     runtime.NumCPU() * 2,
			Type:        "int",
			Description: "Number of workers",
			Category:    "Performance",
			IsEditable:  false,
		},
		{
			Name:        "pbuf",
			Value:       pbufValue,
			Default:     defaults.PacketBuffer,
			Type:        "int",
			Description: "Set packet buffer size, for channels that feed data to workers",
			Category:    "Performance",
			IsEditable:  false,
		},
		{
			Name:        "membuf-size",
			Value:       membufValue,
			Default:     defaults.BufferSize,
			Type:        "int",
			Description: "Set size for membuf",
			Category:    "Performance",
			IsEditable:  false,
		},

		// Network Capture Configuration
		{
			Name:        "bpf",
			Value:       s.getBPFValue(sessionConfig),
			Default:     "",
			Type:        "string",
			Description: "Supply a BPF filter to use prior to processing packets with netcap",
			Category:    "Network Capture",
			IsEditable:  false,
		},
		{
			Name:        "iface",
			Value:       ifaceValue,
			Default:     "",
			Type:        "string",
			Description: "Attach to network interface and capture in live mode",
			Category:    "Network Capture",
			IsEditable:  false,
		},
		{
			Name:        "promisc",
			Value:       promiscValue,
			Default:     true,
			Type:        "bool",
			Description: "Toggle promiscuous mode for live capture",
			Category:    "Network Capture",
			IsEditable:  false,
		},
		{
			Name:        "snaplen",
			Value:       snaplenValue,
			Default:     defaults.SnapLen,
			Type:        "int",
			Description: "Configure snaplen for live capture from interface",
			Category:    "Network Capture",
			IsEditable:  false,
		},

		// Decoder Configuration
		{
			Name:        "include",
			Value:       s.getIncludeDecodersValue(sessionConfig),
			Default:     "",
			Type:        "string",
			Description: "Include specific decoders (comma-separated)",
			Category:    "Decoders",
			IsEditable:  false,
		},
		{
			Name:        "exclude",
			Value:       s.getExcludeDecodersValue(sessionConfig),
			Default:     "",
			Type:        "string",
			Description: "Exclude specific decoders (comma-separated)",
			Category:    "Decoders",
			IsEditable:  false,
		},
		{
			Name:        "base",
			Value:       baseLayerValue,
			Default:     "ethernet",
			Type:        "string",
			Description: "Select base layer",
			Category:    "Decoders",
			IsEditable:  false,
		},
		{
			Name:        "opts",
			Value:       decodeOptsValue,
			Default:     "lazy",
			Type:        "string",
			Description: "Select decoding options",
			Category:    "Decoders",
			IsEditable:  false,
		},
		{
			Name:        "payload",
			Value:       s.GetPayloadCapture(),
			Default:     false,
			Type:        "bool",
			Description: "Capture payload for supported layers (can be toggled at runtime for future analysis)",
			Category:    "Decoders",
			IsEditable:  true,
		},
		{
			Name:        "context",
			Value:       contextValue,
			Default:     true,
			Type:        "bool",
			Description: "Add packet flow context to selected audit records",
			Category:    "Decoders",
			IsEditable:  false,
		},

		// Database and Enrichment
		{
			Name:        "macDB",
			Value:       macDBValue,
			Default:     true,
			Type:        "bool",
			Description: "Use mac to vendor database for device profiling",
			Category:    "Database",
			IsEditable:  false,
		},
		{
			Name:        "ja3DB",
			Value:       ja3DBValue,
			Default:     true,
			Type:        "bool",
			Description: "Use ja3 database for device profiling",
			Category:    "Database",
			IsEditable:  false,
		},
		{
			Name:        "serviceDB",
			Value:       serviceDBValue,
			Default:     true,
			Type:        "bool",
			Description: "Use serviceDB for device profiling",
			Category:    "Database",
			IsEditable:  false,
		},
		{
			Name:        "geoDB",
			Value:       geoDBValue,
			Default:     false,
			Type:        "bool",
			Description: "Use geolocation for device profiling",
			Category:    "Database",
			IsEditable:  false,
		},
		{
			Name:        "dpi",
			Value:       s.dpiConfigured,
			Default:     false,
			Type:        "bool",
			Description: "Use DPI libs to enrich IPProfile audit records",
			Category:    "Database",
			IsEditable:  false,
		},
		{
			Name:        "reverse-dns",
			Value:       reverseDNSValue,
			Default:     false,
			Type:        "bool",
			Description: "Resolve IPs to domains via the operating systems default DNS resolver",
			Category:    "Database",
			IsEditable:  false,
		},
		{
			Name:        "local-dns",
			Value:       localDNSValue,
			Default:     false,
			Type:        "bool",
			Description: "Resolve DNS locally via hosts file in the database dir",
			Category:    "Database",
			IsEditable:  false,
		},

		// TCP Reassembly Configuration
		{
			Name:        "reassemble-connections",
			Value:       reassembleValue,
			Default:     true,
			Type:        "bool",
			Description: "Reassemble TCP connections",
			Category:    "TCP Reassembly",
			IsEditable:  false,
		},
		{
			Name:        "flushevery",
			Value:       flushEveryValue,
			Default:     defaults.FlushEvery,
			Type:        "int",
			Description: "Flush assembler every N packets",
			Category:    "TCP Reassembly",
			IsEditable:  false,
		},
		{
			Name:        "checksum",
			Value:       checksumValue,
			Default:     defaults.Checksum,
			Type:        "bool",
			Description: "Check TCP checksum",
			Category:    "TCP Reassembly",
			IsEditable:  false,
		},
		{
			Name:        "nooptcheck",
			Value:       noOptCheckValue,
			Default:     defaults.NoOptCheck,
			Type:        "bool",
			Description: "Do not check TCP options (useful to ignore MSS on captures with TSO)",
			Category:    "TCP Reassembly",
			IsEditable:  false,
		},
		{
			Name:        "ignorefsmerr",
			Value:       ignoreFSMErrValue,
			Default:     defaults.IgnoreFSMErr,
			Type:        "bool",
			Description: "Ignore TCP FSM errors",
			Category:    "TCP Reassembly",
			IsEditable:  false,
		},
		{
			Name:        "allowmissinginit",
			Value:       allowMissingInitValue,
			Default:     defaults.AllowMissingInit,
			Type:        "bool",
			Description: "Support streams without SYN/SYN+ACK/ACK sequence",
			Category:    "TCP Reassembly",
			IsEditable:  false,
		},
		{
			Name:        "close-pending-timeout",
			Value:       closePendingTimeoutValue,
			Default:     defaults.ClosePendingTimeout.String(),
			Type:        "duration",
			Description: "Reassembly: close connections that have pending bytes",
			Category:    "TCP Reassembly",
			IsEditable:  false,
		},
		{
			Name:        "close-inactive-timeout",
			Value:       closeInactiveTimeoutValue,
			Default:     defaults.CloseInactiveTimeout.String(),
			Type:        "duration",
			Description: "Reassembly: close connections that are inactive",
			Category:    "TCP Reassembly",
			IsEditable:  false,
		},

		// Output Format Configuration
		{
			Name:        "proto",
			Value:       protoValue,
			Default:     true,
			Type:        "bool",
			Description: "Output data as protobuf",
			Category:    "Output Format",
			IsEditable:  false,
		},
		{
			Name:        "json",
			Value:       jsonValue,
			Default:     false,
			Type:        "bool",
			Description: "Output data as JSON",
			Category:    "Output Format",
			IsEditable:  false,
		},
		{
			Name:        "csv",
			Value:       csvValue,
			Default:     false,
			Type:        "bool",
			Description: "Output data as CSV",
			Category:    "Output Format",
			IsEditable:  false,
		},

		// Elastic Configuration
		{
			Name:        "elastic",
			Value:       elasticValue,
			Default:     false,
			Type:        "bool",
			Description: "Write data to elastic db",
			Category:    "Elastic",
			IsEditable:  false,
		},
		{
			Name:        "elastic-addrs",
			Value:       elasticAddrsValue,
			Default:     "",
			Type:        "string",
			Description: "Elastic db endpoints to write data to",
			Category:    "Elastic",
			IsEditable:  false,
		},
		{
			Name:        "elastic-user",
			Value:       elasticUserValue,
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
			Value:       bufferValue,
			Default:     true,
			Type:        "bool",
			Description: "Buffer data in memory before writing to disk",
			Category:    "Advanced",
			IsEditable:  false,
		},
		{
			Name:        "ignore-unknown",
			Value:       ignoreUnknownValue,
			Default:     true,
			Type:        "bool",
			Description: "Disable writing unknown packets into a pcap file",
			Category:    "Advanced",
			IsEditable:  false,
		},
		{
			Name:        "free-os-mem",
			Value:       freeOSMemValue,
			Default:     0,
			Type:        "int",
			Description: "Free OS memory every X minutes, disabled if set to 0",
			Category:    "Advanced",
			IsEditable:  false,
		},
		{
			Name:        "conn-flush-interval",
			Value:       connFlushIntervalValue,
			Default:     defaults.ConnFlushInterval,
			Type:        "int",
			Description: "Flush connections every X flows",
			Category:    "Advanced",
			IsEditable:  false,
		},
		{
			Name:        "conn-timeout",
			Value:       connTimeoutValue,
			Default:     defaults.ConnTimeOut.String(),
			Type:        "duration",
			Description: "Close connections older than X seconds",
			Category:    "Advanced",
			IsEditable:  false,
		},
		{
			Name:        "flow-flush-interval",
			Value:       flowFlushIntervalValue,
			Default:     defaults.FlowFlushInterval,
			Type:        "int",
			Description: "Flushes flows every X flows",
			Category:    "Advanced",
			IsEditable:  false,
		},
		{
			Name:        "flow-timeout",
			Value:       flowTimeoutValue,
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

// getBPFValue returns the BPF filter value, preferring session-specific value
func (s *Server) getBPFValue(sessionConfig *SessionInfo) string {
	if sessionConfig != nil && sessionConfig.BPFFilter != "" {
		return sessionConfig.BPFFilter
	}
	return ""
}

// getIncludeDecodersValue returns the include decoders value, preferring session-specific value
func (s *Server) getIncludeDecodersValue(sessionConfig *SessionInfo) string {
	if sessionConfig != nil && sessionConfig.IncludeDecoders != "" {
		return sessionConfig.IncludeDecoders
	}
	return ""
}

// getExcludeDecodersValue returns the exclude decoders value, preferring session-specific value
func (s *Server) getExcludeDecodersValue(sessionConfig *SessionInfo) string {
	if sessionConfig != nil && sessionConfig.ExcludeDecoders != "" {
		return sessionConfig.ExcludeDecoders
	}
	return ""
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

// handlePayloadToggle handles runtime payload capture toggle requests
func (s *Server) handlePayloadToggle(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		// Return current payload capture state
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"enabled": s.GetPayloadCapture(),
		})
		return
	}

	if r.Method == http.MethodPost {
		// Update payload capture state
		var req struct {
			Enabled bool `json:"enabled"`
		}

		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, fmt.Sprintf("Invalid request: %v", err), http.StatusBadRequest)
			return
		}

		s.SetPayloadCapture(req.Enabled)

		log.Printf("[WebUI] Payload capture %s (will apply to future analysis)", map[bool]string{true: "enabled", false: "disabled"}[req.Enabled])

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"enabled": req.Enabled,
			"message": fmt.Sprintf("Payload capture %s (will apply to future analysis)", map[bool]string{true: "enabled", false: "disabled"}[req.Enabled]),
		})
		return
	}

	http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
}

// handleStopCapture handles requests to stop the live capture
func (s *Server) handleStopCapture(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		s.mu.Lock()

		// Check if we're in live mode
		if !s.isLiveMode {
			s.mu.Unlock()
			http.Error(w, "Not in live capture mode", http.StatusBadRequest)
			return
		}

		// Check if we have a stop function
		if s.stopCapture == nil {
			s.mu.Unlock()
			http.Error(w, "Stop capture function not available", http.StatusInternalServerError)
			return
		}

		// Call the cancel function to stop the live capture
		log.Println("[WebUI] Stop capture requested via web UI")
		s.stopCapture()
		s.mu.Unlock()

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": true,
			"message": "Live capture stop requested",
		})
		return
	}

	http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
}

// handleUpload handles file uploads for analysis
func (s *Server) handleUpload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Parse multipart form
	// In service mode: 200MB + overhead
	// In local mode: allow larger files (10GB max for form parsing)
	maxMemory := int64(210 * 1024 * 1024) // 210MB for service mode
	if !s.isServiceMode {
		maxMemory = int64(10 * 1024 * 1024 * 1024) // 10GB for local mode
	}
	if err := r.ParseMultipartForm(maxMemory); err != nil {
		log.Printf("[WebUI] Failed to parse multipart form: %v", err)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"error":   "Failed to parse upload form",
			"success": false,
		})
		return
	}

	// Get the uploaded file
	file, header, err := r.FormFile("file")
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"error":   "No file provided",
			"success": false,
		})
		return
	}
	defer file.Close()

	// Validate file size (only in service mode; no limit in local mode)
	// Note: In local mode, users can upload files of any size
	if s.isServiceMode {
		maxSize := int64(200 * 1024 * 1024)
		if header.Size > maxSize {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"error":   fmt.Sprintf("File size (%d bytes) exceeds maximum allowed size (%d bytes)", header.Size, maxSize),
				"success": false,
			})
			return
		}
	}

	// Validate file extension
	filename := header.Filename
	ext := strings.ToLower(filepath.Ext(filename))
	if ext != ".pcap" && ext != ".pcapng" {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"error":   "Invalid file format. Only .pcap and .pcapng files are allowed",
			"success": false,
		})
		return
	}

	// Create uploads directory in output dir
	s.mu.RLock()
	outDir := s.outDir
	s.mu.RUnlock()

	if outDir == "" {
		var err error
		outDir, err = os.Getwd()
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"error":   "Failed to determine output directory",
				"success": false,
			})
			return
		}
	}

	uploadsDir := filepath.Join(outDir, "uploads")
	if err := os.MkdirAll(uploadsDir, 0755); err != nil {
		log.Printf("[WebUI] Failed to create uploads directory: %v", err)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"error":   "Failed to create uploads directory",
			"success": false,
		})
		return
	}

	// Save uploaded file
	var savedFilename string
	if s.isServiceMode {
		// Service mode: add timestamp prefix to avoid conflicts
		timestamp := time.Now().Format("20060102-150405")
		savedFilename = fmt.Sprintf("uploaded-%s-%s", timestamp, filepath.Base(filename))
	} else {
		// Local mode: use original filename
		savedFilename = filepath.Base(filename)
	}
	inputPath := filepath.Join(uploadsDir, savedFilename)

	outFile, err := os.Create(inputPath)
	if err != nil {
		log.Printf("[WebUI] Failed to create input file: %v", err)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"error":   "Failed to save uploaded file",
			"success": false,
		})
		return
	}
	defer outFile.Close()

	written, err := io.Copy(outFile, file)
	if err != nil {
		log.Printf("[WebUI] Failed to write input file: %v", err)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"error":   "Failed to save uploaded file",
			"success": false,
		})
		return
	}

	log.Printf("[WebUI] File uploaded successfully: %s (%d bytes)", inputPath, written)

	// Call the upload callback if provided (for backwards compatibility)
	s.mu.RLock()
	callback := s.uploadCallback
	s.mu.RUnlock()

	if callback != nil {
		go func() {
			if err := callback(inputPath); err != nil {
				log.Printf("[WebUI] Upload callback error: %v", err)
			}
		}()
	}

	// Queue analysis job for local mode
	if !s.isServiceMode && s.jobQueue != nil {
		// Create output directory based on original filename (without extension)
		// In local mode, savedFilename is the original filename without timestamp prefix
		baseFilename := filepath.Base(inputPath)
		// Remove extension to get directory name
		dirName := strings.TrimSuffix(baseFilename, filepath.Ext(baseFilename))

		// Create output directory in baseOutDir
		s.mu.RLock()
		baseOutDir := s.baseOutDir
		s.mu.RUnlock()

		if baseOutDir == "" {
			baseOutDir = outDir
		}

		outputDir := filepath.Join(baseOutDir, dirName)

		// Create the output directory
		if err := os.MkdirAll(outputDir, 0755); err != nil {
			log.Printf("[WebUI] Failed to create output directory %s: %v", outputDir, err)
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"error":   "Failed to create output directory for analysis",
				"success": false,
			})
			return
		}

		log.Printf("[WebUI] Created output directory for uploaded file: %s", outputDir)

		// Get DPI configuration from server
		s.mu.RLock()
		enableDPI := s.dpiConfigured
		s.mu.RUnlock()

		// Load BPF filter from saved configuration
		bpfConfig := s.loadBPFConfig()

		// Create analysis job
		job := &AnalysisJob{
			SessionID:       savedFilename, // Use filename as session ID in local mode
			InputFile:       inputPath,
			OutputDir:       outputDir,
			EnableDPI:       enableDPI,
			BPFFilter:       bpfConfig.Filter,
			IncludeDecoders: "",
			ExcludeDecoders: "",
		}

		// Queue the job
		log.Printf("[WebUI] Queueing analysis job for uploaded file: %s -> %s", inputPath, outputDir)
		select {
		case s.jobQueue <- job:
			atomic.AddInt64(&s.jobsScheduled, 1)
			log.Printf("[WebUI] Analysis job queued successfully")

			// Add the uploaded file to inputFiles so it appears in the UI
			s.mu.Lock()
			// Check if file is already in the list to avoid duplicates
			fileExists := false
			for _, existingFile := range s.inputFiles {
				if existingFile == inputPath {
					fileExists = true
					break
				}
			}
			if !fileExists {
				s.inputFiles = append(s.inputFiles, inputPath)
				log.Printf("[WebUI] Added uploaded file to inputFiles list: %s", inputPath)
			}
			s.mu.Unlock()
		default:
			log.Printf("[WebUI] Job queue is full, cannot queue analysis")
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"error":   "Analysis queue is full, please try again later",
				"success": false,
			})
			return
		}
	}

	// Calculate file ID (hash) for the uploaded file
	fileID := calculateFileHash(inputPath)
	if fileID == "" {
		// Fallback to basename if hash calculation fails
		fileID = filepath.Base(inputPath)
	}

	// Store the mapping from ID to path
	s.mu.Lock()
	s.fileIDToPath[fileID] = inputPath
	s.mu.Unlock()

	log.Printf("[WebUI] Generated file ID %s for uploaded file %s", fileID, inputPath)

	// Return success response
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success":  true,
		"message":  "File uploaded successfully and queued for analysis",
		"filename": savedFilename,
		"path":     inputPath,
		"size":     written,
		"id":       fileID, // Include file ID in response
	})
}

// calculateFileHash calculates the SHA256 hash of a file
func calculateFileHash(filePath string) string {
	file, err := os.Open(filePath)
	if err != nil {
		log.Printf("[WebUI] Failed to open file for hashing: %v", err)
		return ""
	}
	defer file.Close()

	hasher := sha256.New()
	if _, err := io.Copy(hasher, file); err != nil {
		log.Printf("[WebUI] Failed to calculate file hash: %v", err)
		return ""
	}

	return hex.EncodeToString(hasher.Sum(nil))
}

// ReportIssueRequest represents the request body for reporting an issue
type ReportIssueRequest struct {
	SessionID   string `json:"sessionId"`
	Description string `json:"description"`
}

// ReportIssueResponse represents the response for reporting an issue
type ReportIssueResponse struct {
	Success bool   `json:"success"`
	IssueID string `json:"issueId"`
	Message string `json:"message"`
}

// handleReportIssue handles issue reports for PCAP files
func (s *Server) handleReportIssue(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	clientIP := s.getUserIP(r)

	// Check rate limit for issue reports (only in service mode)
	if s.isServiceMode && s.sessionManager != nil {
		allowed, remaining := s.sessionManager.CheckIssueReportLimit(clientIP)
		if !allowed {
			RespondJSON(w, http.StatusTooManyRequests, map[string]interface{}{
				"error":     "Issue report rate limit exceeded",
				"message":   "You have reached the maximum number of issue reports per hour (3 per hour)",
				"remaining": remaining,
				"success":   false,
			})
			return
		}
	}

	// Parse request body
	var req ReportIssueRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		log.Printf("[WebUI] Failed to parse report issue request: %v", err)
		RespondJSON(w, http.StatusBadRequest, map[string]interface{}{
			"error":   "Invalid request body",
			"success": false,
		})
		return
	}

	// Validate input
	if req.SessionID == "" || req.Description == "" {
		RespondJSON(w, http.StatusBadRequest, map[string]interface{}{
			"error":   "SessionID and description are required",
			"success": false,
		})
		return
	}

	// Handle based on mode
	if s.isServiceMode && s.sessionManager != nil {
		s.handleServiceModeIssueReport(w, req, clientIP)
	} else {
		s.handleLocalModeIssueReport(w, req)
	}
}

// handleServiceModeIssueReport handles issue reports in service mode with full session data
func (s *Server) handleServiceModeIssueReport(w http.ResponseWriter, req ReportIssueRequest, clientIP string) {
	// Get session info
	session, exists := s.sessionManager.GetSession(req.SessionID)
	if !exists {
		RespondJSON(w, http.StatusNotFound, map[string]interface{}{
			"error":   "Session not found",
			"success": false,
		})
		return
	}

	// Check if issue was already reported for this session
	if session.HasReportedIssue {
		RespondJSON(w, http.StatusConflict, map[string]interface{}{
			"error":   "An issue has already been reported for this session",
			"success": false,
		})
		return
	}

	// Check if analysis is complete
	if session.Status != StatusCompleted {
		RespondJSON(w, http.StatusBadRequest, map[string]interface{}{
			"error":   "Analysis must be completed before reporting issues",
			"status":  string(session.Status),
			"success": false,
		})
		return
	}

	// Generate issue ID
	issueID := generateSessionID()

	// Create issues directory structure
	issuesBaseDir := filepath.Join(s.serviceConfig.DataDir, "issues")
	issueDir := filepath.Join(issuesBaseDir, issueID)

	if err := os.MkdirAll(issueDir, 0755); err != nil {
		log.Printf("[Service] Failed to create issue directory: %v", err)
		RespondJSON(w, http.StatusInternalServerError, map[string]interface{}{
			"error":   "Failed to create issue directory",
			"success": false,
		})
		return
	}

	// Save issue description as markdown file
	descriptionPath := filepath.Join(issueDir, "description.md")
	if err := os.WriteFile(descriptionPath, []byte(req.Description), 0644); err != nil {
		log.Printf("[Service] Failed to write issue description: %v", err)
		RespondJSON(w, http.StatusInternalServerError, map[string]interface{}{
			"error":   "Failed to save issue description",
			"success": false,
		})
		return
	}

	// Save metadata about the issue
	metadata := map[string]interface{}{
		"issueId":        issueID,
		"sessionId":      session.SessionID,
		"reportedBy":     clientIP,
		"reportTime":     time.Now().Unix(),
		"inputFilename":  session.InputFilename,
		"inputFileSize":  session.InputFileSize,
		"bpfFilter":      session.BPFFilter,
		"completionTime": session.CompletionTime.Unix(),
	}

	metadataJSON, err := json.MarshalIndent(metadata, "", "  ")
	if err != nil {
		log.Printf("[Service] Failed to marshal issue metadata: %v", err)
		RespondJSON(w, http.StatusInternalServerError, map[string]interface{}{
			"error":   "Failed to create issue metadata",
			"success": false,
		})
		return
	}

	metadataPath := filepath.Join(issueDir, "metadata.json")
	if err := os.WriteFile(metadataPath, metadataJSON, 0644); err != nil {
		log.Printf("[Service] Failed to write issue metadata: %v", err)
		RespondJSON(w, http.StatusInternalServerError, map[string]interface{}{
			"error":   "Failed to save issue metadata",
			"success": false,
		})
		return
	}

	// Copy PCAP file to issue directory
	pcapDestPath := filepath.Join(issueDir, filepath.Base(session.InputFile))
	if err := copyFile(session.InputFile, pcapDestPath); err != nil {
		log.Printf("[Service] Failed to copy PCAP file: %v", err)
		// Not fatal, continue
	}

	// Copy all netcap audit records from output directory to issue directory
	netcapDataDir := filepath.Join(issueDir, "netcap-data")
	if err := os.MkdirAll(netcapDataDir, 0755); err != nil {
		log.Printf("[Service] Failed to create netcap data directory: %v", err)
		// Not fatal, continue
	} else {
		// Copy all .ncap.gz files from session output directory
		err = filepath.Walk(session.OutputDir, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}

			if info.IsDir() {
				return nil
			}

			// Only copy .ncap.gz files
			if !strings.HasSuffix(info.Name(), ".ncap.gz") {
				return nil
			}

			destPath := filepath.Join(netcapDataDir, info.Name())
			return copyFile(path, destPath)
		})

		if err != nil {
			log.Printf("[Service] Warning: Failed to copy some netcap data: %v", err)
			// Not fatal, continue
		}
	}

	log.Printf("[Service] Issue report created: issueId=%s, sessionId=%s, reportedBy=%s", issueID, session.SessionID, clientIP)

	// Mark session as having reported issue
	s.sessionManager.MarkSessionIssueReported(session.SessionID)

	// Record issue report for rate limiting
	s.sessionManager.RecordIssueReport(clientIP)

	// Return success response
	RespondJSON(w, http.StatusOK, ReportIssueResponse{
		Success: true,
		IssueID: issueID,
		Message: "Issue report submitted successfully. Thank you for helping improve netcap!",
	})
}

// handleLocalModeIssueReport handles issue reports in local mode (simpler, no session data)
func (s *Server) handleLocalModeIssueReport(w http.ResponseWriter, req ReportIssueRequest) {
	// Find the file by sessionId (which is file path or basename in local mode)
	s.mu.RLock()
	inputFiles := s.inputFiles
	s.mu.RUnlock()

	var fileHash string
	var fileName string
	var filePath string

	for _, path := range inputFiles {
		// Try to match by basename or full path
		if strings.Contains(path, req.SessionID) || filepath.Base(path) == req.SessionID {
			fileHash = calculateFileHash(path)
			fileName = filepath.Base(path)
			filePath = path
			break
		}
	}

	if fileHash == "" {
		RespondJSON(w, http.StatusNotFound, map[string]interface{}{
			"error":   "File not found for the given session",
			"success": false,
		})
		return
	}

	// Check if issue has already been reported for this file
	s.mu.RLock()
	alreadyReported := s.reportedIssues[fileHash]
	s.mu.RUnlock()

	if alreadyReported {
		RespondJSON(w, http.StatusConflict, map[string]interface{}{
			"error":   "An issue has already been reported for this file",
			"success": false,
		})
		return
	}

	// Mark this file as having an issue reported
	s.mu.Lock()
	s.reportedIssues[fileHash] = true
	s.mu.Unlock()

	// Generate a unique issue ID
	issueID := fmt.Sprintf("issue-%s-%d", fileHash[:8], time.Now().Unix())

	// Try to create issues directory in output dir
	s.mu.RLock()
	outDir := s.outDir
	s.mu.RUnlock()

	issuesDir := filepath.Join(outDir, "issues")
	issueDir := filepath.Join(issuesDir, issueID)

	if err := os.MkdirAll(issueDir, 0755); err != nil {
		log.Printf("[WebUI] Warning: Failed to create issue directory: %v", err)
		// Continue anyway - we'll at least log it
	} else {
		// Save description
		descriptionPath := filepath.Join(issueDir, "description.md")
		if err := os.WriteFile(descriptionPath, []byte(req.Description), 0644); err != nil {
			log.Printf("[WebUI] Warning: Failed to write issue description: %v", err)
		}

		// Save metadata
		metadata := map[string]interface{}{
			"issueId":    issueID,
			"fileName":   fileName,
			"filePath":   filePath,
			"fileHash":   fileHash,
			"reportTime": time.Now().Unix(),
			"sessionId":  req.SessionID,
		}

		metadataJSON, err := json.MarshalIndent(metadata, "", "  ")
		if err == nil {
			metadataPath := filepath.Join(issueDir, "metadata.json")
			if err := os.WriteFile(metadataPath, metadataJSON, 0644); err != nil {
				log.Printf("[WebUI] Warning: Failed to write issue metadata: %v", err)
			}
		}
	}

	log.Printf("[WebUI] Issue report submitted: issueId=%s, file=%s, hash=%s", issueID, fileName, fileHash)

	// Return success response
	RespondJSON(w, http.StatusOK, ReportIssueResponse{
		Success: true,
		IssueID: issueID,
		Message: "Issue report submitted successfully. Thank you for helping improve netcap!",
	})
}

// handleExtractedFiles returns list of extracted files for the current capture
func (s *Server) handleExtractedFiles(w http.ResponseWriter, r *http.Request) {
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

	// Get the files directory within the output directory
	filesDir := filepath.Join(outDir, "files")

	// Check if files directory exists
	if _, err := os.Stat(filesDir); os.IsNotExist(err) {
		// Return empty list if directory doesn't exist
		RespondJSON(w, http.StatusOK, map[string]interface{}{
			"files":      []map[string]interface{}{},
			"totalCount": 0,
			"filesDir":   filesDir,
		})
		return
	}

	// Read File audit records to get hash information
	fileHashMap := make(map[string]string) // path -> hash
	fileAuditPath := filepath.Join(outDir, "File.ncap.gz")
	if _, err := os.Stat(fileAuditPath); err == nil {
		// File audit exists, read it to get hashes
		reader, err := netio.Open(fileAuditPath, defaults.BufferSize)
		if err == nil {
			var file types.File
			for {
				err := reader.Next(&file)
				if err != nil {
					if err != io.EOF {
						log.Printf("[WebUI] Error reading File audit record: %v", err)
					}
					break
				}
				// Map location (relative path) to hash
				if file.Location != "" && file.Hash != "" {
					fileHashMap[file.Location] = file.Hash
					//log.Printf("[WebUI] File audit record: Location=%s, Hash=%s", file.Location, file.Hash)
				}
			}
			reader.Close()
		}
		log.Printf("[WebUI] Loaded %d file hashes from File audit records", len(fileHashMap))
	}

	// Walk the files directory and collect file information
	var extractedFiles []map[string]interface{}
	err := filepath.Walk(filesDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			log.Printf("[WebUI] Error walking files directory: %v", err)
			return nil // Continue walking
		}

		// Skip directories
		if info.IsDir() {
			return nil
		}

		// Get relative path from files directory
		relPath, err := filepath.Rel(filesDir, path)
		if err != nil {
			log.Printf("[WebUI] Warning: filepath.Rel failed for path=%s, filesDir=%s, error=%v. Using filename only.", path, filesDir, err)
			relPath = info.Name()
		}

		// Determine MIME type from directory structure
		mimeType := ""
		pathParts := strings.Split(filepath.ToSlash(relPath), "/")
		if len(pathParts) >= 2 {
			mimeType = pathParts[0] + "/" + pathParts[1]
		}

		fileInfo := map[string]interface{}{
			"name":         info.Name(),
			"path":         relPath, // Relative path from files directory (used for downloads)
			"fullPath":     path,    // Absolute path (not used by frontend)
			"size":         info.Size(),
			"modifiedTime": info.ModTime().Unix(),
			"mimeType":     mimeType,
		}

		//log.Printf("[WebUI] Extracted file: name=%s, relPath=%s, mimeType=%s", info.Name(), relPath, mimeType)

		// Add hash if available
		if hash, ok := fileHashMap[relPath]; ok {
			fileInfo["hash"] = hash
		}

		extractedFiles = append(extractedFiles, fileInfo)
		return nil
	})

	if err != nil {
		log.Printf("[WebUI] Failed to read extracted files: %v", err)
		RespondJSON(w, http.StatusInternalServerError, map[string]interface{}{
			"error": fmt.Sprintf("Failed to read extracted files: %v", err),
		})
		return
	}

	// Sort by modified time (newest first)
	// Note: This is a simple sort, could be optimized if needed

	RespondJSON(w, http.StatusOK, map[string]interface{}{
		"files":      extractedFiles,
		"totalCount": len(extractedFiles),
		"filesDir":   filesDir,
	})
}

// handleDownloadExtractedFile serves individual extracted files for download
func (s *Server) handleDownloadExtractedFile(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Extract file path from URL: /api/extracted-files/download/{relativePath}
	encodedPath := strings.TrimPrefix(r.URL.Path, "/api/extracted-files/download/")
	if encodedPath == "" {
		http.Error(w, "File path required", http.StatusBadRequest)
		return
	}

	// URL-decode the path (frontend encodes it with encodeURIComponent)
	relativePath, err := url.PathUnescape(encodedPath)
	if err != nil {
		log.Printf("[WebUI] Failed to decode file path: %v", err)
		http.Error(w, "Invalid path encoding", http.StatusBadRequest)
		return
	}

	log.Printf("[WebUI] Download extracted file request: encodedPath=%s, decodedPath=%s", encodedPath, relativePath)

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
		http.Error(w, "No output directory selected", http.StatusServiceUnavailable)
		return
	}

	// Build full path to the file
	filesDir := filepath.Join(outDir, "files")
	fullPath := filepath.Join(filesDir, filepath.Clean(relativePath))

	log.Printf("[WebUI] File download: filesDir=%s, relativePath=%s, fullPath=%s", filesDir, relativePath, fullPath)

	// Security check: ensure the file is within the files directory
	if !strings.HasPrefix(fullPath, filesDir) {
		log.Printf("[WebUI] Security violation: attempt to access file outside files directory: %s", relativePath)
		http.Error(w, "Invalid file path", http.StatusForbidden)
		return
	}

	// Check if file exists
	fileInfo, err := os.Stat(fullPath)
	if err != nil {
		if os.IsNotExist(err) {
			log.Printf("[WebUI] File not found: %s (fullPath: %s)", relativePath, fullPath)
			http.Error(w, "File not found", http.StatusNotFound)
		} else {
			log.Printf("[WebUI] Error accessing file %s: %v", relativePath, err)
			http.Error(w, "Error accessing file", http.StatusInternalServerError)
		}
		return
	}

	// Ensure it's not a directory
	if fileInfo.IsDir() {
		http.Error(w, "Cannot download directory", http.StatusBadRequest)
		return
	}

	// Open the file
	file, err := os.Open(fullPath)
	if err != nil {
		log.Printf("[WebUI] Failed to open file %s: %v", relativePath, err)
		http.Error(w, "Failed to open file", http.StatusInternalServerError)
		return
	}
	defer file.Close()

	// Set headers for download
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s\"", fileInfo.Name()))
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Length", fmt.Sprintf("%d", fileInfo.Size()))

	// Security headers to prevent XSS and other attacks when files are previewed
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "SAMEORIGIN")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; img-src data: *;")

	// Stream the file to the response
	if _, err := io.Copy(w, file); err != nil {
		log.Printf("[WebUI] Error streaming file %s: %v", relativePath, err)
	}
}

// handleDownloadAllExtractedFiles creates a zip archive of all extracted files and streams it to the client
func (s *Server) handleDownloadAllExtractedFiles(w http.ResponseWriter, r *http.Request) {
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
		http.Error(w, "No output directory selected", http.StatusServiceUnavailable)
		return
	}

	// Get the files directory within the output directory
	filesDir := filepath.Join(outDir, "files")

	// Check if files directory exists
	if _, err := os.Stat(filesDir); os.IsNotExist(err) {
		http.Error(w, "No extracted files found", http.StatusNotFound)
		return
	}

	// Collect all files to zip
	var filesToZip []string
	err := filepath.Walk(filesDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			log.Printf("[WebUI] Error walking files directory: %v", err)
			return nil // Continue walking
		}

		// Skip directories
		if info.IsDir() {
			return nil
		}

		filesToZip = append(filesToZip, path)
		return nil
	})

	if err != nil {
		log.Printf("[WebUI] Failed to collect files for zip: %v", err)
		http.Error(w, "Failed to collect files", http.StatusInternalServerError)
		return
	}

	if len(filesToZip) == 0 {
		http.Error(w, "No files to download", http.StatusNotFound)
		return
	}

	// Generate filename based on current time and output directory name
	timestamp := time.Now().Format("20060102-150405")
	outputDirName := filepath.Base(outDir)
	zipFilename := fmt.Sprintf("extracted-files-%s-%s.zip", outputDirName, timestamp)

	// Set headers for download
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s\"", zipFilename))
	w.Header().Set("X-Content-Type-Options", "nosniff")

	// Create zip writer that streams to response
	zipWriter := zip.NewWriter(w)
	defer zipWriter.Close()

	// Add each file to the zip
	for _, filePath := range filesToZip {
		// Get relative path from files directory for zip entry
		relPath, err := filepath.Rel(filesDir, filePath)
		if err != nil {
			log.Printf("[WebUI] Failed to get relative path for %s: %v", filePath, err)
			continue
		}

		// Open source file
		file, err := os.Open(filePath)
		if err != nil {
			log.Printf("[WebUI] Failed to open file %s for zipping: %v", filePath, err)
			continue
		}

		// Get file info
		fileInfo, err := file.Stat()
		if err != nil {
			file.Close()
			log.Printf("[WebUI] Failed to stat file %s: %v", filePath, err)
			continue
		}

		// Create zip entry header
		header, err := zip.FileInfoHeader(fileInfo)
		if err != nil {
			file.Close()
			log.Printf("[WebUI] Failed to create zip header for %s: %v", filePath, err)
			continue
		}

		// Set the name to the relative path to preserve directory structure
		header.Name = relPath
		header.Method = zip.Deflate

		// Create zip entry
		writer, err := zipWriter.CreateHeader(header)
		if err != nil {
			file.Close()
			log.Printf("[WebUI] Failed to create zip entry for %s: %v", relPath, err)
			continue
		}

		// Copy file content to zip entry
		_, err = io.Copy(writer, file)
		file.Close()
		if err != nil {
			log.Printf("[WebUI] Error copying file %s to zip: %v", relPath, err)
			// Continue with other files
		}
	}

	log.Printf("[WebUI] Created zip archive with %d files: %s", len(filesToZip), zipFilename)
}

// handleDownloadInputFile serves PCAP input files for download
func (s *Server) handleDownloadInputFile(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Extract identifier from URL: /api/files/input/download/{identifier}
	// The identifier can be a sessionId (service mode) or file path (local mode)
	encodedIdentifier := strings.TrimPrefix(r.URL.Path, "/api/files/input/download/")
	if encodedIdentifier == "" {
		http.Error(w, "File identifier required", http.StatusBadRequest)
		return
	}

	// URL-decode the identifier (frontend encodes it with encodeURIComponent)
	identifier, err := url.PathUnescape(encodedIdentifier)
	if err != nil {
		log.Printf("[WebUI] Failed to decode identifier: %v", err)
		http.Error(w, "Invalid identifier encoding", http.StatusBadRequest)
		return
	}

	var filePath string
	var fileName string

	// In service mode, identifier is sessionId
	if s.isServiceMode && s.sessionManager != nil {
		session, ok := s.sessionManager.GetSession(identifier)
		if !ok {
			http.Error(w, "Session not found", http.StatusNotFound)
			return
		}

		// Check if user has access to this session
		clientIP := s.getUserIP(r)
		if !session.IsPreloaded && session.IP != clientIP {
			http.Error(w, "Access denied", http.StatusForbidden)
			return
		}

		filePath = session.InputFile
		fileName = session.InputFilename
	} else {
		// In local mode, identifier is the file path
		// Security: ensure the file is one of the registered input files
		s.mu.RLock()
		found := false
		for _, inputFile := range s.inputFiles {
			if inputFile == identifier {
				found = true
				filePath = identifier
				fileName = filepath.Base(identifier)
				break
			}
		}
		s.mu.RUnlock()

		if !found {
			http.Error(w, "File not found or access denied", http.StatusForbidden)
			return
		}
	}

	// Check if file exists
	fileInfo, err := os.Stat(filePath)
	if err != nil {
		if os.IsNotExist(err) {
			http.Error(w, "File not found", http.StatusNotFound)
		} else {
			log.Printf("[WebUI] Error accessing file %s: %v", filePath, err)
			http.Error(w, "Error accessing file", http.StatusInternalServerError)
		}
		return
	}

	// Ensure it's not a directory
	if fileInfo.IsDir() {
		http.Error(w, "Cannot download directory", http.StatusBadRequest)
		return
	}

	// Open the file
	file, err := os.Open(filePath)
	if err != nil {
		log.Printf("[WebUI] Failed to open file %s: %v", filePath, err)
		http.Error(w, "Failed to open file", http.StatusInternalServerError)
		return
	}
	defer file.Close()

	// Set headers for download
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s\"", fileName))
	w.Header().Set("Content-Type", "application/vnd.tcpdump.pcap")
	w.Header().Set("Content-Length", fmt.Sprintf("%d", fileInfo.Size()))

	// Security headers
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "SAMEORIGIN")

	// Stream the file to the response
	if _, err := io.Copy(w, file); err != nil {
		log.Printf("[WebUI] Error streaming file %s: %v", filePath, err)
	}
}

// handleDownloadAllAuditRecords creates a zip archive of all audit record files and streams it to the client
func (s *Server) handleDownloadAllAuditRecords(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	log.Printf("[WebUI] Download all audit records request received")

	// Extract identifier from URL: /api/download/{identifier}
	// The identifier can be a sessionId (service mode) or file path (local mode)
	encodedIdentifier := strings.TrimPrefix(r.URL.Path, "/api/download/")
	if encodedIdentifier == "" {
		log.Printf("[WebUI] No identifier provided for download")
		http.Error(w, "Identifier required", http.StatusBadRequest)
		return
	}

	// URL-decode the identifier (frontend encodes it with encodeURIComponent)
	identifier, err := url.PathUnescape(encodedIdentifier)
	if err != nil {
		log.Printf("[WebUI] Failed to decode identifier: %v", err)
		http.Error(w, "Invalid identifier encoding", http.StatusBadRequest)
		return
	}

	log.Printf("[WebUI] Download all audit records: identifier=%s", identifier)

	var outDir string
	var sessionId string

	// Determine output directory based on mode
	if s.isServiceMode && s.sessionManager != nil {
		// Try to use identifier as sessionId
		// This works for both preloaded pcaps and user-uploaded captures
		session, ok := s.sessionManager.GetSession(identifier)
		if !ok {
			log.Printf("[WebUI] Session not found: %s", identifier)
			http.Error(w, "Session not found", http.StatusNotFound)
			return
		}

		// Check if user has access to this session
		// Preloaded sessions (IsPreloaded=true) are accessible to all users
		// User sessions require IP match
		clientIP := s.getUserIP(r)
		if !session.IsPreloaded && session.IP != clientIP {
			log.Printf("[WebUI] Access denied for session %s: client IP %s != session IP %s", identifier, clientIP, session.IP)
			http.Error(w, "Access denied", http.StatusForbidden)
			return
		}

		outDir = session.OutputDir
		sessionId = session.SessionID
		log.Printf("[WebUI] Service mode: using session %s, outDir=%s", sessionId, outDir)
	} else {
		// Local mode: determine output directory from input file
		s.mu.RLock()

		// Check if identifier matches activeInputFile or any registered input file
		var matchedInputFile string
		if s.activeInputFile == identifier {
			matchedInputFile = s.activeInputFile
		} else {
			// Search through input files
			for _, inputFile := range s.inputFiles {
				if inputFile == identifier || filepath.Base(inputFile) == identifier {
					matchedInputFile = inputFile
					break
				}
			}
		}

		if matchedInputFile == "" {
			s.mu.RUnlock()
			log.Printf("[WebUI] Input file not found or not authorized: %s", identifier)
			http.Error(w, "File not found or access denied", http.StatusForbidden)
			return
		}

		// Get the output directory for this input file
		outDir = s.outDir
		s.mu.RUnlock()

		log.Printf("[WebUI] Local mode: using input file %s, outDir=%s", matchedInputFile, outDir)
	}

	if outDir == "" {
		log.Printf("[WebUI] No output directory available")
		http.Error(w, "No output directory selected", http.StatusServiceUnavailable)
		return
	}

	// Check if output directory exists
	if _, err := os.Stat(outDir); os.IsNotExist(err) {
		log.Printf("[WebUI] Output directory does not exist: %s", outDir)
		http.Error(w, "Output directory not found", http.StatusNotFound)
		return
	}

	// Collect all audit record files (*.ncap.gz)
	var auditFiles []string
	err = filepath.Walk(outDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			log.Printf("[WebUI] Error walking output directory: %v", err)
			return nil // Continue walking
		}

		// Skip directories
		if info.IsDir() {
			return nil
		}

		// Only include .ncap.gz files (audit record files)
		if strings.HasSuffix(info.Name(), ".ncap.gz") {
			auditFiles = append(auditFiles, path)
		}

		return nil
	})

	if err != nil {
		log.Printf("[WebUI] Failed to collect audit files: %v", err)
		http.Error(w, "Failed to collect audit files", http.StatusInternalServerError)
		return
	}

	if len(auditFiles) == 0 {
		log.Printf("[WebUI] No audit record files found in %s", outDir)
		http.Error(w, "No audit record files available", http.StatusNotFound)
		return
	}

	log.Printf("[WebUI] Found %d audit record files to download", len(auditFiles))

	// Generate filename based on current time and identifier
	timestamp := time.Now().Format("20060102-150405")
	var baseIdentifier string
	if sessionId != "" {
		baseIdentifier = sessionId
	} else {
		baseIdentifier = filepath.Base(identifier)
		// Remove file extension for cleaner name
		baseIdentifier = strings.TrimSuffix(baseIdentifier, filepath.Ext(baseIdentifier))
	}
	zipFilename := fmt.Sprintf("audit-records-%s-%s.zip", baseIdentifier, timestamp)

	log.Printf("[WebUI] Creating zip archive: %s", zipFilename)

	// Set headers for download
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s\"", zipFilename))
	w.Header().Set("X-Content-Type-Options", "nosniff")

	// Create zip writer that streams to response
	zipWriter := zip.NewWriter(w)
	defer zipWriter.Close()

	// Add each audit file to the zip
	for _, filePath := range auditFiles {
		// Get relative path from output directory for zip entry
		relPath, err := filepath.Rel(outDir, filePath)
		if err != nil {
			log.Printf("[WebUI] Failed to get relative path for %s: %v", filePath, err)
			continue
		}

		// Open source file
		file, err := os.Open(filePath)
		if err != nil {
			log.Printf("[WebUI] Failed to open file %s for zipping: %v", filePath, err)
			continue
		}

		// Get file info
		fileInfo, err := file.Stat()
		if err != nil {
			file.Close()
			log.Printf("[WebUI] Failed to stat file %s: %v", filePath, err)
			continue
		}

		// Create zip entry header
		header, err := zip.FileInfoHeader(fileInfo)
		if err != nil {
			file.Close()
			log.Printf("[WebUI] Failed to create zip header for %s: %v", filePath, err)
			continue
		}

		// Set the name to the relative path to preserve directory structure
		header.Name = relPath
		header.Method = zip.Deflate

		// Create zip entry
		writer, err := zipWriter.CreateHeader(header)
		if err != nil {
			file.Close()
			log.Printf("[WebUI] Failed to create zip entry for %s: %v", relPath, err)
			continue
		}

		// Copy file content to zip entry
		_, err = io.Copy(writer, file)
		file.Close()
		if err != nil {
			log.Printf("[WebUI] Error copying file %s to zip: %v", relPath, err)
			// Continue with other files
		}
	}

	log.Printf("[WebUI] Successfully created zip archive with %d audit record files: %s", len(auditFiles), zipFilename)
}

// handleErrorLogContent serves error log content for failed analyses
func (s *Server) handleErrorLogContent(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Extract session ID from URL path: /api/error-log/{sessionId}
	encodedSessionID := strings.TrimPrefix(r.URL.Path, "/api/error-log/")
	if encodedSessionID == "" {
		http.Error(w, "Session ID required", http.StatusBadRequest)
		return
	}

	// URL-decode the session ID
	sessionID, err := url.PathUnescape(encodedSessionID)
	if err != nil {
		log.Printf("[WebUI] Failed to decode session ID: %v", err)
		http.Error(w, "Invalid session ID encoding", http.StatusBadRequest)
		return
	}

	log.Printf("[WebUI] GET /api/error-log/%s", sessionID)

	// Service mode: Look up the session
	if s.isServiceMode && s.sessionManager != nil {
		session, exists := s.sessionManager.GetSession(sessionID)
		if !exists || session == nil {
			log.Printf("[WebUI] Session not found: %s", sessionID)
			http.Error(w, "Session not found", http.StatusNotFound)
			return
		}

		// Determine error log path
		// Priority 1: Use session.ErrorLogPath if set (for failed analyses)
		// Priority 2: Check for errors.log in output directory (for successful analyses with packet errors)
		errorLogPath := session.ErrorLogPath
		if errorLogPath == "" {
			// Try standard errors.log in output directory
			errorLogPath = filepath.Join(session.OutputDir, "errors.log")

			// Check if the file exists
			if _, err := os.Stat(errorLogPath); os.IsNotExist(err) {
				log.Printf("[WebUI] No error log found for session: %s (checked %s)", sessionID, errorLogPath)
				http.Error(w, "No error log available for this session", http.StatusNotFound)
				return
			}
		}

		log.Printf("[WebUI] Reading error log from: %s", errorLogPath)

		// Read the error log file
		content, err := os.ReadFile(errorLogPath)
		if err != nil {
			log.Printf("[WebUI] Failed to read error log for session %s: %v", sessionID, err)
			http.Error(w, fmt.Sprintf("Failed to read error log: %v", err), http.StatusInternalServerError)
			return
		}

		log.Printf("[WebUI] Successfully read error log for session %s (size: %d bytes)", sessionID, len(content))

		// Return raw log content as plain text
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		w.Write(content)
		return
	}

	// Local mode: sessionID is the file path or error log path
	s.mu.RLock()
	fileErrors := s.fileErrors
	s.mu.RUnlock()

	// Try to find the error log for this file
	var errorLogPath string
	for filePath, ferr := range fileErrors {
		// Match by file path or base name
		if filePath == sessionID || filepath.Base(filePath) == sessionID {
			if ferr.ErrorLogPath != "" {
				errorLogPath = ferr.ErrorLogPath
				break
			}
		}
	}

	if errorLogPath == "" {
		log.Printf("[WebUI] No error log found for: %s", sessionID)
		http.Error(w, "No error log available for this file", http.StatusNotFound)
		return
	}

	log.Printf("[WebUI] Reading error log from: %s", errorLogPath)

	// Read the error log file
	content, err := os.ReadFile(errorLogPath)
	if err != nil {
		log.Printf("[WebUI] Failed to read error log: %v", err)
		http.Error(w, fmt.Sprintf("Failed to read error log: %v", err), http.StatusInternalServerError)
		return
	}

	log.Printf("[WebUI] Successfully read error log (size: %d bytes)", len(content))

	// Return raw log content as plain text
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write(content)
}

// handleErrorLogFiles returns list of capture files with errors.log files
func (s *Server) handleErrorLogFiles(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Service mode
	if s.isServiceMode && s.sessionManager != nil {
		clientIP := s.getUserIP(r)
		sessions := s.sessionManager.GetSessionsForIP(clientIP)

		// Add preloaded sessions
		allSessions := s.sessionManager.GetAllSessions()
		for _, session := range allSessions {
			if session.IsPreloaded {
				sessions = append(sessions, session)
			}
		}

		type ErrorLogInfo struct {
			SessionID     string `json:"sessionId"`
			InputFilename string `json:"inputFilename"`
			InputFileSize int64  `json:"inputFileSize"`
			ErrorCount    int    `json:"errorCount"`
			ErrorLogPath  string `json:"errorLogPath"`
			OutputDir     string `json:"outputDir"`
		}

		var errorLogs []ErrorLogInfo

		for _, session := range sessions {
			// Check if session has errors.log
			errorLogPath := filepath.Join(session.OutputDir, "errors.log")
			if _, err := os.Stat(errorLogPath); os.IsNotExist(err) {
				continue
			}

			// Count errors in the log
			errorCount, err := countErrorsInLog(errorLogPath)
			if err != nil {
				log.Printf("[WebUI] Error counting errors in %s: %v", errorLogPath, err)
				continue
			}

			if errorCount > 0 {
				errorLogs = append(errorLogs, ErrorLogInfo{
					SessionID:     session.SessionID,
					InputFilename: session.InputFilename,
					InputFileSize: session.InputFileSize,
					ErrorCount:    errorCount,
					ErrorLogPath:  errorLogPath,
					OutputDir:     session.OutputDir,
				})
			}
		}

		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(errorLogs); err != nil {
			http.Error(w, fmt.Sprintf("Failed to encode response: %v", err), http.StatusInternalServerError)
		}
		return
	}

	// Local mode
	s.mu.RLock()
	inputFiles := s.inputFiles
	fileOutputDirs := make(map[string]string)
	for k, v := range s.fileOutputDirs {
		fileOutputDirs[k] = v
	}
	baseOutDir := s.baseOutDir
	s.mu.RUnlock()

	type ErrorLogInfo struct {
		InputFile     string `json:"inputFile"`
		InputFilename string `json:"inputFilename"`
		InputFileSize int64  `json:"inputFileSize"`
		ErrorCount    int    `json:"errorCount"`
		ErrorLogPath  string `json:"errorLogPath"`
		OutputDir     string `json:"outputDir"`
	}

	var errorLogs []ErrorLogInfo

	for _, inputFile := range inputFiles {
		// Get output directory for this file
		var outputDir string
		if dir, exists := fileOutputDirs[inputFile]; exists {
			outputDir = dir
		} else {
			// Calculate the subdirectory
			if len(inputFiles) == 1 {
				outputDir = baseOutDir
			} else {
				baseName := filepath.Base(inputFile)
				dirName := baseName
				for _, ext := range []string{".pcap", ".pcapng", ".cap", ".dmp"} {
					if strings.HasSuffix(dirName, ext) {
						dirName = strings.TrimSuffix(dirName, ext)
						break
					}
				}
				outputDir = filepath.Join(baseOutDir, dirName)
			}
		}

		// Check if errors.log exists
		errorLogPath := filepath.Join(outputDir, "errors.log")
		if _, err := os.Stat(errorLogPath); os.IsNotExist(err) {
			continue
		}

		// Count errors in the log
		errorCount, err := countErrorsInLog(errorLogPath)
		if err != nil {
			log.Printf("[WebUI] Error counting errors in %s: %v", errorLogPath, err)
			continue
		}

		if errorCount > 0 {
			// Get file info
			fileInfo, err := os.Stat(inputFile)
			if err != nil {
				continue
			}

			errorLogs = append(errorLogs, ErrorLogInfo{
				InputFile:     inputFile,
				InputFilename: filepath.Base(inputFile),
				InputFileSize: fileInfo.Size(),
				ErrorCount:    errorCount,
				ErrorLogPath:  errorLogPath,
				OutputDir:     outputDir,
			})
		}
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(errorLogs); err != nil {
		http.Error(w, fmt.Sprintf("Failed to encode response: %v", err), http.StatusInternalServerError)
	}
}

// countErrorsInLog counts the number of lines in an errors.log file
// Any line in the errors.log represents error information (timestamps, error messages, packet dumps, stack traces, etc.)
func countErrorsInLog(logPath string) (int, error) {
	file, err := os.Open(logPath)
	if err != nil {
		return 0, err
	}
	defer file.Close()

	count := 0
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		// Count all lines - every line in errors.log is part of error information
		count++
	}

	if err := scanner.Err(); err != nil {
		return 0, err
	}

	return count, nil
}

// AggregatedError represents an error message with its occurrence count
type AggregatedError struct {
	ErrorMessage string `json:"errorMessage"`
	Count        int    `json:"count"`
	FirstSeen    string `json:"firstSeen"`
}

// handleAggregatedErrors aggregates and deduplicates errors across all error logs
func (s *Server) handleAggregatedErrors(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	log.Printf("[WebUI] Aggregating errors across all captures")

	// Map to store aggregated errors: error message -> count
	errorCounts := make(map[string]int)
	errorFirstSeen := make(map[string]string)
	filesProcessed := 0
	filesWithErrors := 0

	// Service mode
	if s.isServiceMode && s.sessionManager != nil {
		clientIP := s.getUserIP(r)
		sessions := s.sessionManager.GetSessionsForIP(clientIP)

		// Add preloaded sessions
		allSessions := s.sessionManager.GetAllSessions()
		for _, session := range allSessions {
			if session.IsPreloaded {
				sessions = append(sessions, session)
			}
		}

		log.Printf("[WebUI] Checking %d sessions for error logs", len(sessions))

		for _, session := range sessions {
			errorLogPath := filepath.Join(session.OutputDir, "errors.log")

			// Check if file exists
			fileInfo, err := os.Stat(errorLogPath)
			if os.IsNotExist(err) {
				continue
			} else if err != nil {
				log.Printf("[WebUI] Error checking error log %s: %v", errorLogPath, err)
				continue
			}

			log.Printf("[WebUI] Processing error log: %s (size: %d bytes)", errorLogPath, fileInfo.Size())
			filesProcessed++

			// Parse errors from this file
			beforeCount := len(errorCounts)
			if err := aggregateErrorsFromFile(errorLogPath, errorCounts, errorFirstSeen); err != nil {
				log.Printf("[WebUI] Error parsing errors from %s: %v", errorLogPath, err)
			} else {
				afterCount := len(errorCounts)
				if afterCount > beforeCount {
					filesWithErrors++
					log.Printf("[WebUI] Found %d new unique error types in %s", afterCount-beforeCount, errorLogPath)
				}
			}
		}
	} else {
		// Local mode
		s.mu.RLock()
		inputFiles := s.inputFiles
		fileOutputDirs := make(map[string]string)
		for k, v := range s.fileOutputDirs {
			fileOutputDirs[k] = v
		}
		baseOutDir := s.baseOutDir
		s.mu.RUnlock()

		log.Printf("[WebUI] Checking %d input files for error logs", len(inputFiles))

		for _, inputFile := range inputFiles {
			// Get output directory for this file
			var outputDir string
			if dir, exists := fileOutputDirs[inputFile]; exists {
				outputDir = dir
			} else {
				if len(inputFiles) == 1 {
					outputDir = baseOutDir
				} else {
					baseName := filepath.Base(inputFile)
					dirName := baseName
					for _, ext := range []string{".pcap", ".pcapng", ".cap", ".dmp"} {
						if strings.HasSuffix(dirName, ext) {
							dirName = strings.TrimSuffix(dirName, ext)
							break
						}
					}
					outputDir = filepath.Join(baseOutDir, dirName)
				}
			}

			errorLogPath := filepath.Join(outputDir, "errors.log")

			// Check if file exists
			fileInfo, err := os.Stat(errorLogPath)
			if os.IsNotExist(err) {
				continue
			} else if err != nil {
				log.Printf("[WebUI] Error checking error log %s: %v", errorLogPath, err)
				continue
			}

			log.Printf("[WebUI] Processing error log: %s (size: %d bytes)", errorLogPath, fileInfo.Size())
			filesProcessed++

			// Parse errors from this file
			beforeCount := len(errorCounts)
			if err := aggregateErrorsFromFile(errorLogPath, errorCounts, errorFirstSeen); err != nil {
				log.Printf("[WebUI] Error parsing errors from %s: %v", errorLogPath, err)
			} else {
				afterCount := len(errorCounts)
				if afterCount > beforeCount {
					filesWithErrors++
					log.Printf("[WebUI] Found %d new unique error types in %s", afterCount-beforeCount, errorLogPath)
				}
			}
		}
	}

	// Convert map to sorted slice
	aggregated := make([]AggregatedError, 0, len(errorCounts))
	for errMsg, count := range errorCounts {
		aggregated = append(aggregated, AggregatedError{
			ErrorMessage: errMsg,
			Count:        count,
			FirstSeen:    errorFirstSeen[errMsg],
		})
	}

	// Sort by count (descending)
	sort.Slice(aggregated, func(i, j int) bool {
		return aggregated[i].Count > aggregated[j].Count
	})

	log.Printf("[WebUI] Aggregated %d unique error types from %d error log files (%d files processed)", len(aggregated), filesWithErrors, filesProcessed)

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(aggregated); err != nil {
		http.Error(w, fmt.Sprintf("Failed to encode response: %v", err), http.StatusInternalServerError)
	}
}

// aggregateErrorsFromFile parses an errors.log file and aggregates error messages
// Expected format: [count] error message
func aggregateErrorsFromFile(logPath string, errorCounts map[string]int, errorFirstSeen map[string]string) error {
	file, err := os.Open(logPath)
	if err != nil {
		return err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	var currentTimestamp string
	errorsFound := 0
	linesProcessed := 0

	for scanner.Scan() {
		linesProcessed++
		line := strings.TrimSpace(scanner.Text())

		// Skip empty lines
		if line == "" {
			continue
		}

		// Check if this is a timestamp line
		if strings.Contains(line, "UTC") {
			currentTimestamp = line
			continue
		}

		// Parse error lines in format: [count] error message
		// Example: [12] Unknown TLS handshake type
		if strings.HasPrefix(line, "[") {
			// Find the closing bracket
			closeBracketIdx := strings.Index(line, "]")
			if closeBracketIdx > 1 {
				// Extract count and error message
				countStr := line[1:closeBracketIdx]
				count := 0
				if _, err := fmt.Sscanf(countStr, "%d", &count); err == nil && count > 0 {
					// Extract error message after the bracket
					errorMsg := strings.TrimSpace(line[closeBracketIdx+1:])
					if errorMsg != "" {
						// Add the count to the total for this error message
						errorCounts[errorMsg] += count
						errorsFound++

						// Store first seen timestamp for this error
						if _, exists := errorFirstSeen[errorMsg]; !exists && currentTimestamp != "" {
							errorFirstSeen[errorMsg] = currentTimestamp
						}
					}
				}
			}
		}

		// Also support old format: Error: message
		if strings.HasPrefix(line, "Error:") {
			errorMsg := strings.TrimSpace(strings.TrimPrefix(line, "Error:"))
			if errorMsg != "" {
				errorCounts[errorMsg]++
				errorsFound++
				// Store first seen timestamp for this error
				if _, exists := errorFirstSeen[errorMsg]; !exists && currentTimestamp != "" {
					errorFirstSeen[errorMsg] = currentTimestamp
				}
			}
		}
	}

	if err := scanner.Err(); err != nil {
		log.Printf("[WebUI] Scanner error for %s: %v (processed %d lines, found %d errors)", logPath, err, linesProcessed, errorsFound)
		return err
	}

	log.Printf("[WebUI] Parsed %s: %d lines processed, %d error entries found", logPath, linesProcessed, errorsFound)
	return nil
}

// copyFile copies a file from src to dst
func copyFile(src, dst string) error {
	sourceFile, err := os.Open(src)
	if err != nil {
		return err
	}
	defer sourceFile.Close()

	destFile, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer destFile.Close()

	_, err = io.Copy(destFile, sourceFile)
	return err
}
