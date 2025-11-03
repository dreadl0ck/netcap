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
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/dreadl0ck/netcap"
	"github.com/dreadl0ck/netcap/dbs"
	"github.com/dreadl0ck/netcap/defaults"
	"github.com/dreadl0ck/netcap/dpi"
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

	response := StatusResponse{
		IsProcessing:    s.isProcessing,
		OutputDir:       s.outDir,
		InputFiles:      inputFiles,
		ServerStarted:   serverStartTime,
		ActiveInputFile: s.activeInputFile,
		IsMultiFile:     len(inputFiles) > 1,
		IsServiceMode:   s.isServiceMode,
		IsLiveMode:      s.isLiveMode,
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

		// Calculate file hash
		hash := calculateFileHash(path)

		fileInfo := FileInfo{
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
	if s.isServiceMode && s.sessionManager != nil {
		clientIP := s.getUserIP(r)

		// Search in user's sessions and preloaded sessions
		allSessions := s.sessionManager.GetAllSessions()
		var matchedSession *SessionInfo

		for _, session := range allSessions {
			// Match by input file path
			if session.InputFile == req.InputFile {
				// For preloaded sessions, any user can access
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
			Value:       s.dpiConfigured,
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

	// Parse multipart form (limit to 200MB + overhead)
	maxMemory := int64(210 * 1024 * 1024) // 210MB
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

	// Validate file size (200MB limit)
	maxSize := int64(200 * 1024 * 1024)
	if header.Size > maxSize {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"error":   fmt.Sprintf("File size (%d bytes) exceeds maximum allowed size (%d bytes)", header.Size, maxSize),
			"success": false,
		})
		return
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
	timestamp := time.Now().Format("20060102-150405")
	savedFilename := fmt.Sprintf("uploaded-%s-%s", timestamp, filepath.Base(filename))
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

	// Call the upload callback if provided (for processing)
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

	// Return success response
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success":  true,
		"message":  "File uploaded successfully",
		"filename": savedFilename,
		"path":     inputPath,
		"size":     written,
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

// handleErrorLogContent serves error log content for failed analyses
func (s *Server) handleErrorLogContent(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Extract session ID from URL path: /api/error-log/{sessionId}
	sessionID := strings.TrimPrefix(r.URL.Path, "/api/error-log/")
	if sessionID == "" {
		http.Error(w, "Session ID required", http.StatusBadRequest)
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

		// Check if session has an error log path
		if session.ErrorLogPath == "" {
			log.Printf("[WebUI] No error log path for session: %s", sessionID)
			http.Error(w, "No error log available for this session", http.StatusNotFound)
			return
		}

		log.Printf("[WebUI] Reading error log from: %s", session.ErrorLogPath)

		// Read the error log file
		content, err := os.ReadFile(session.ErrorLogPath)
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
