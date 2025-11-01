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

package service

import (
	"archive/tar"
	"compress/gzip"
	"crypto/rand"
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

	"github.com/dreadl0ck/netcap/cmd/capture/webui"

	"github.com/dreadl0ck/netcap"
	"github.com/dreadl0ck/netcap/decoder/packet"
	"github.com/dreadl0ck/netcap/decoder/stream"
	"github.com/dreadl0ck/netcap/dpi"
)

// handleUpload handles file uploads and queues them for analysis
func (s *Server) handleUpload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	clientIP := getClientIP(r)

	// Check rate limit
	allowed, remaining := s.sessionManager.CheckRateLimit(clientIP)
	if !allowed {
		respondJSON(w, http.StatusTooManyRequests, map[string]interface{}{
			"error":     "Rate limit exceeded",
			"message":   "You have reached the maximum number of analyses per hour",
			"remaining": 0,
		})
		return
	}

	// Parse multipart form (limit to max file size + some overhead)
	maxMemory := s.config.MaxFileSize + (10 * 1024 * 1024) // 10MB overhead
	if err := r.ParseMultipartForm(maxMemory); err != nil {
		log.Printf("[Service] Failed to parse multipart form: %v", err)
		respondJSON(w, http.StatusBadRequest, map[string]string{
			"error": "Failed to parse upload form",
		})
		return
	}

	// Get the uploaded file
	file, header, err := r.FormFile("file")
	if err != nil {
		respondJSON(w, http.StatusBadRequest, map[string]string{
			"error": "No file provided",
		})
		return
	}
	defer file.Close()

	// Validate file size
	if header.Size > s.config.MaxFileSize {
		respondJSON(w, http.StatusBadRequest, map[string]string{
			"error": fmt.Sprintf("File size (%d bytes) exceeds maximum allowed size (%d bytes)", header.Size, s.config.MaxFileSize),
		})
		return
	}

	// Check storage limit
	// Estimate total storage needed: uploaded file + ~2x for analysis results
	estimatedStorageNeeded := header.Size + (header.Size * 2)
	storageAllowed, currentUsage, maxStorage := s.CheckStorageLimit(estimatedStorageNeeded)
	if !storageAllowed {
		log.Printf("[Service] Storage limit exceeded: current=%d, max=%d, needed=%d", currentUsage, maxStorage, estimatedStorageNeeded)
		respondJSON(w, http.StatusInsufficientStorage, map[string]interface{}{
			"error":          "Storage limit exceeded",
			"message":        "The server has reached its storage capacity. Please try again later after cleanup frees up space.",
			"currentUsage":   currentUsage,
			"maxStorage":     maxStorage,
			"estimatedNeed":  estimatedStorageNeeded,
			"availableSpace": maxStorage - currentUsage,
		})
		return
	}

	// Validate file extension
	filename := header.Filename
	ext := strings.ToLower(filepath.Ext(filename))
	if ext != ".pcap" && ext != ".pcapng" {
		respondJSON(w, http.StatusBadRequest, map[string]string{
			"error": "Invalid file type. Only .pcap and .pcapng files are allowed",
		})
		return
	}

	// Validate file magic bytes (basic check)
	magicBytes := make([]byte, 4)
	if _, err := file.Read(magicBytes); err != nil {
		respondJSON(w, http.StatusBadRequest, map[string]string{
			"error": "Failed to read file",
		})
		return
	}
	if _, err := file.Seek(0, 0); err != nil {
		respondJSON(w, http.StatusInternalServerError, map[string]string{
			"error": "Failed to process file",
		})
		return
	}

	// Check for PCAP magic bytes (0xa1b2c3d4 or 0xd4c3b2a1 for standard, 0x0a0d0d0a for pcapng)
	isPcap := (magicBytes[0] == 0xa1 && magicBytes[1] == 0xb2 && magicBytes[2] == 0xc3 && magicBytes[3] == 0xd4) ||
		(magicBytes[0] == 0xd4 && magicBytes[1] == 0xc3 && magicBytes[2] == 0xb2 && magicBytes[3] == 0xa1) ||
		(magicBytes[0] == 0x0a && magicBytes[1] == 0x0d && magicBytes[2] == 0x0d && magicBytes[3] == 0x0a)

	if !isPcap {
		respondJSON(w, http.StatusBadRequest, map[string]string{
			"error": "File does not appear to be a valid PCAP or PCAPNG file",
		})
		return
	}

	// Generate session ID
	sessionID := generateSessionID()

	// Create session directories
	uploadDir := filepath.Join(s.config.DataDir, "uploads", sessionID)
	resultsDir := filepath.Join(s.config.DataDir, "results", sessionID)

	if err := os.MkdirAll(uploadDir, 0755); err != nil {
		log.Printf("[Service] Failed to create upload directory: %v", err)
		respondJSON(w, http.StatusInternalServerError, map[string]string{
			"error": "Failed to create upload directory",
		})
		return
	}

	if err := os.MkdirAll(resultsDir, 0755); err != nil {
		log.Printf("[Service] Failed to create results directory: %v", err)
		respondJSON(w, http.StatusInternalServerError, map[string]string{
			"error": "Failed to create results directory",
		})
		return
	}

	// Save uploaded file
	inputPath := filepath.Join(uploadDir, "input"+ext)
	outFile, err := os.Create(inputPath)
	if err != nil {
		log.Printf("[Service] Failed to create input file: %v", err)
		respondJSON(w, http.StatusInternalServerError, map[string]string{
			"error": "Failed to save uploaded file",
		})
		return
	}
	defer outFile.Close()

	if _, err := io.Copy(outFile, file); err != nil {
		log.Printf("[Service] Failed to write input file: %v", err)
		respondJSON(w, http.StatusInternalServerError, map[string]string{
			"error": "Failed to save uploaded file",
		})
		return
	}

	// Load current BPF and decoder config
	bpfConfig := s.loadBPFConfig()
	decoderConfig := s.loadDecoderConfig()

	// Create session info
	session := &SessionInfo{
		SessionID:       sessionID,
		IP:              clientIP,
		UploadTimestamp: time.Now(),
		InputFile:       inputPath,
		InputFilename:   filename,
		InputFileSize:   header.Size,
		OutputDir:       resultsDir,
		Status:          StatusQueued,
		ResultsReady:    false,
		BPFFilter:       bpfConfig.Filter,
		IncludeDecoders: decoderConfig.IncludeDecoders,
		ExcludeDecoders: decoderConfig.ExcludeDecoders,
	}

	// Add session to manager
	s.sessionManager.AddSession(session)

	// Queue analysis job
	job := &AnalysisJob{
		SessionID:       sessionID,
		InputFile:       inputPath,
		OutputDir:       resultsDir,
		EnableDPI:       s.enableDPI,
		BPFFilter:       bpfConfig.Filter,
		IncludeDecoders: decoderConfig.IncludeDecoders,
		ExcludeDecoders: decoderConfig.ExcludeDecoders,
	}

	s.jobQueue <- job

	log.Printf("[Service] Session %s created for %s (file: %s, size: %d bytes)", sessionID, clientIP, filename, header.Size)

	// Note: Don't auto-select session to support multiple file uploads
	// Users can select specific sessions from the "Your Recent Analyses" list

	// Generate shareable URL
	// Extract the protocol and host from the request
	protocol := "http"
	if r.TLS != nil {
		protocol = "https"
	}
	host := r.Host
	shareURL := fmt.Sprintf("%s://%s/view/%s", protocol, host, sessionID)

	// Respond with session ID and shareable URL
	respondJSON(w, http.StatusOK, map[string]interface{}{
		"sessionId": sessionID,
		"status":    "queued",
		"message":   "File uploaded successfully and queued for analysis",
		"remaining": remaining - 1,
		"shareUrl":  shareURL,
	})
}

// handleStatus returns the status of a specific session (for upload polling)
func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Extract session ID from URL (format: /api/status/{sessionID})
	path := strings.TrimPrefix(r.URL.Path, "/api/status/")
	if path == "" || path == r.URL.Path {
		// No session ID in path - this is likely from old upload UI
		// Return current session status
		session := s.GetCurrentSession()
		if session == nil {
			respondJSON(w, http.StatusOK, map[string]interface{}{
				"status":  "no_session",
				"message": "No active session",
			})
			return
		}
		respondJSON(w, http.StatusOK, session)
		return
	}

	sessionID := path

	// Get session info
	session, exists := s.sessionManager.GetSession(sessionID)
	if !exists {
		log.Printf("[Service] Session %s not found when checking status", sessionID)
		respondJSON(w, http.StatusNotFound, map[string]string{
			"error": "Session not found or expired",
		})
		return
	}

	log.Printf("[Service] Status check for session %s: status=%s, resultsReady=%v", sessionID, session.Status, session.ResultsReady)

	// Return session status
	respondJSON(w, http.StatusOK, session)
}

// handleDownload generates and streams a tar.gz archive of the results
func (s *Server) handleDownload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	clientIP := getClientIP(r)

	// Extract session ID from URL
	sessionID := strings.TrimPrefix(r.URL.Path, "/api/download/")
	if sessionID == "" {
		respondJSON(w, http.StatusBadRequest, map[string]string{
			"error": "Session ID required",
		})
		return
	}

	// Check if this is the current active session (shared session viewing)
	currentSession := s.GetCurrentSession()
	isCurrentSession := currentSession != nil && currentSession.SessionID == sessionID

	// Check if this is a public share link access (has 'share' query parameter)
	isPublicShare := r.URL.Query().Get("share") == "true"

	var session *SessionInfo
	var exists bool

	if isPublicShare || isCurrentSession {
		// Allow public access for shared links or current session - don't check IP
		session, exists = s.sessionManager.GetSession(sessionID)
		if !exists {
			respondJSON(w, http.StatusNotFound, map[string]string{
				"error": "Session not found or expired",
			})
			return
		}
	} else {
		// Get session and verify IP ownership for non-shared access
		session, exists = s.sessionManager.GetSessionForIP(sessionID, clientIP)
		if !exists {
			respondJSON(w, http.StatusNotFound, map[string]string{
				"error": "Session not found or access denied",
			})
			return
		}
	}

	// Check if analysis is complete
	if session.Status != StatusCompleted {
		respondJSON(w, http.StatusBadRequest, map[string]string{
			"error":  "Analysis not yet completed",
			"status": string(session.Status),
		})
		return
	}

	// Set headers for download
	filename := fmt.Sprintf("netcap-results-%s.tar.gz", sessionID[:8])
	w.Header().Set("Content-Type", "application/gzip")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%s", filename))

	// Create gzip writer
	gzWriter := gzip.NewWriter(w)
	defer gzWriter.Close()

	// Create tar writer
	tarWriter := tar.NewWriter(gzWriter)
	defer tarWriter.Close()

	// Add audit record files
	resultsDir := session.OutputDir
	err := filepath.Walk(resultsDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if info.IsDir() {
			return nil
		}

		// Only include audit records and log files
		// Include .ncap.gz files and all .log files
		if !(strings.HasSuffix(path, ".ncap.gz") || strings.HasSuffix(path, ".log")) {
			return nil
		}

		// Open file
		file, err := os.Open(path)
		if err != nil {
			log.Printf("[Service] Failed to open file %s: %v", path, err)
			return nil // Skip file
		}
		defer file.Close()

		// Create tar header
		header := &tar.Header{
			Name:    filepath.Base(path),
			Size:    info.Size(),
			Mode:    int64(info.Mode()),
			ModTime: info.ModTime(),
		}

		if err := tarWriter.WriteHeader(header); err != nil {
			return err
		}

		// Copy file content
		if _, err := io.Copy(tarWriter, file); err != nil {
			return err
		}

		return nil
	})

	if err != nil {
		log.Printf("[Service] Error creating archive for session %s: %v", sessionID, err)
		return
	}

	// Add metadata file
	metadata := map[string]interface{}{
		"sessionId":     session.SessionID,
		"inputFilename": session.InputFilename,
		"analysisTime":  session.CompletionTime.Sub(session.StartTime).String(),
		"timestamp":     session.CompletionTime.Unix(),
		"packetsTotal":  session.PacketsTotal,
	}

	metadataJSON, _ := json.MarshalIndent(metadata, "", "  ")
	metadataHeader := &tar.Header{
		Name:    "metadata.json",
		Size:    int64(len(metadataJSON)),
		Mode:    0644,
		ModTime: time.Now(),
	}

	if err := tarWriter.WriteHeader(metadataHeader); err == nil {
		tarWriter.Write(metadataJSON)
	}

	log.Printf("[Service] Results downloaded for session %s by %s", sessionID, clientIP)
}

// handleQuota returns the current quota status for the client IP
func (s *Server) handleQuota(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	clientIP := getClientIP(r)

	allowed, remaining := s.sessionManager.CheckRateLimit(clientIP)

	// Get storage information
	currentUsage := s.GetCurrentStorageUsage()
	maxStorage := s.config.MaxStorageBytes
	storagePercent := 0.0
	if maxStorage > 0 {
		storagePercent = float64(currentUsage) / float64(maxStorage) * 100.0
	}

	response := map[string]interface{}{
		"limit":     s.config.MaxAnalysisHour,
		"remaining": remaining,
		"allowed":   allowed,
		"storage": map[string]interface{}{
			"current":     currentUsage,
			"max":         maxStorage,
			"available":   maxStorage - currentUsage,
			"percentUsed": storagePercent,
			"unlimited":   maxStorage == 0,
		},
	}

	respondJSON(w, http.StatusOK, response)
}

// handleHealth returns the health status of the service
func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	respondJSON(w, http.StatusOK, map[string]interface{}{
		"status":    "healthy",
		"timestamp": time.Now().Unix(),
		"sessions":  len(s.sessionManager.GetAllSessions()),
		"queueSize": len(s.jobQueue),
	})
}

// respondJSON sends a JSON response
func respondJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

// generateSessionID generates a random session ID
func generateSessionID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		// Fallback to timestamp-based ID if random fails
		return fmt.Sprintf("%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(b)
}

// handleDatabaseInfo returns information about the currently loaded databases
func (s *Server) handleDatabaseInfo(w http.ResponseWriter, r *http.Request) {
	log.Printf("[Service] handleDatabaseInfo called: method=%s", r.Method)

	if r.Method != http.MethodGet {
		log.Printf("[Service] handleDatabaseInfo: method not allowed: %s", r.Method)
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Get config root path
	configRoot := os.Getenv("NC_CONFIG_ROOT")
	if configRoot == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			configRoot = filepath.Join("/usr", "local", "etc", "netcap")
		} else {
			configRoot = filepath.Join(home, ".config", "netcap")
		}
	}

	// Read database version
	versionFile := filepath.Join(configRoot, ".db-version")
	versionData, err := os.ReadFile(versionFile)
	version := "unknown"
	if err == nil {
		version = strings.TrimSpace(string(versionData))
		log.Printf("[Service] handleDatabaseInfo: version=%s", version)
	} else {
		log.Printf("[Service] handleDatabaseInfo: failed to read version file: %v", err)
	}

	// Get database folder path
	dbPath := filepath.Join(configRoot, "dbs")
	log.Printf("[Service] handleDatabaseInfo: dbPath=%s", dbPath)

	// Check if database directory exists
	if _, err := os.Stat(dbPath); err != nil {
		log.Printf("[Service] handleDatabaseInfo: database directory does not exist or is inaccessible: %v", err)
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
		log.Printf("[Service] handleDatabaseInfo: failed to read database directory: %v", err)
		// Continue with empty files list
	} else {
		log.Printf("[Service] handleDatabaseInfo: found %d entries in database directory", len(files))
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
					log.Printf("[Service] handleDatabaseInfo: failed to calculate directory size for %s: %v", name, err)
					continue
				}

				// Get directory modification time
				info, err := file.Info()
				if err != nil {
					log.Printf("[Service] handleDatabaseInfo: failed to get directory info for %s: %v", name, err)
					continue
				}
				modTime = info.ModTime()
			} else {
				// Regular file
				info, err := file.Info()
				if err != nil {
					log.Printf("[Service] handleDatabaseInfo: failed to get file info for %s: %v", name, err)
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
		log.Printf("[Service] handleDatabaseInfo: returning %d database files, total size: %d bytes", len(dbFiles), totalSize)
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
		log.Printf("[Service] handleDatabaseInfo: failed to encode response: %v", err)
		http.Error(w, fmt.Sprintf("Failed to encode response: %v", err), http.StatusInternalServerError)
		return
	}

	log.Printf("[Service] handleDatabaseInfo: response sent successfully")
}

// handleUpdateDatabases returns an error as database updates are disabled in try service
func (s *Server) handleUpdateDatabases(w http.ResponseWriter, r *http.Request) {
	log.Printf("[Service] handleUpdateDatabases called: method=%s (disabled)", r.Method)

	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Database updates are not allowed in try service mode
	response := map[string]interface{}{
		"success": false,
		"error":   "Database updates are disabled in try service mode",
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusForbidden)
	if err := json.NewEncoder(w).Encode(response); err != nil {
		log.Printf("[Service] handleUpdateDatabases: failed to encode response: %v", err)
		http.Error(w, fmt.Sprintf("Failed to encode response: %v", err), http.StatusInternalServerError)
		return
	}

	log.Printf("[Service] handleUpdateDatabases: disabled response sent")
}

// handleVersion returns version information
func (s *Server) handleVersion(w http.ResponseWriter, r *http.Request) {
	log.Printf("[Service] handleVersion called: method=%s", r.Method)

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
		log.Printf("[Service] handleVersion: failed to encode response: %v", err)
		http.Error(w, fmt.Sprintf("Failed to encode response: %v", err), http.StatusInternalServerError)
	}

	log.Printf("[Service] handleVersion: response sent successfully")
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
	log.Printf("[Service] handleDPIInfo called: method=%s", r.Method)

	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// In try service mode, use the server's configured DPI setting
	// rather than the runtime state (DPI is only initialized during analysis)
	info := DPIInfo{
		Enabled:                   s.enableDPI,
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
	// In try service mode, DPI is configured for all analysis runs
	if s.enableDPI {
		// When DPI is enabled, all modules will be used during analysis
		info.ActiveModules = []string{"ndpi", "lpi", "go"}
	} else {
		info.ActiveModules = []string{}
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(info); err != nil {
		log.Printf("[Service] handleDPIInfo: failed to encode response: %v", err)
		http.Error(w, fmt.Sprintf("Failed to encode response: %v", err), http.StatusInternalServerError)
		return
	}

	log.Printf("[Service] handleDPIInfo: response sent successfully")
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

// handleConfig returns the current configuration for try service
// Configuration is always read-only in try service
func (s *Server) handleConfig(w http.ResponseWriter, r *http.Request) {
	log.Printf("[Service] handleConfig called: method=%s", r.Method)

	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Build configuration options specific to try service
	options := []ConfigOption{
		// Try Service Configuration
		{
			Name:        "http",
			Value:       s.addr,
			Default:     "localhost:7070",
			Type:        "string",
			Description: "HTTP server address",
			Category:    "Try Service",
			IsEditable:  false,
		},
		{
			Name:        "data-dir",
			Value:       s.config.DataDir,
			Default:     getDefaultDataDir(),
			Type:        "string",
			Description: "Directory for uploads and results",
			Category:    "Try Service",
			IsEditable:  false,
		},
		{
			Name:        "dpi",
			Value:       s.enableDPI,
			Default:     true,
			Type:        "bool",
			Description: "Enable DPI analysis",
			Category:    "Try Service",
			IsEditable:  false,
		},
		{
			Name:        "max-file-size",
			Value:       s.config.MaxFileSize,
			Default:     100 * 1024 * 1024,
			Type:        "int64",
			Description: "Maximum upload file size in bytes (default: 100MB)",
			Category:    "Try Service",
			IsEditable:  false,
		},
		{
			Name:        "max-analysis-hour",
			Value:       s.config.MaxAnalysisHour,
			Default:     10,
			Type:        "int",
			Description: "Maximum number of analyses per IP per hour (default: 10)",
			Category:    "Try Service",
			IsEditable:  false,
		},
		{
			Name:        "session-expiry",
			Value:       s.config.SessionExpiry,
			Default:     60,
			Type:        "int",
			Description: "Session expiry time in minutes",
			Category:    "Try Service",
			IsEditable:  false,
		},
		{
			Name:        "cleanup-interval",
			Value:       s.config.CleanupInterval,
			Default:     10,
			Type:        "int",
			Description: "Cleanup check interval in minutes",
			Category:    "Try Service",
			IsEditable:  false,
		},
		{
			Name:        "max-storage",
			Value:       s.config.MaxStorageBytes,
			Default:     10 * 1024 * 1024 * 1024,
			Type:        "int64",
			Description: "Maximum total storage for uploads and results in bytes (default: 10GB, 0 = unlimited)",
			Category:    "Try Service",
			IsEditable:  false,
		},

		// Output Format Configuration
		{
			Name:        "compress",
			Value:       true,
			Default:     true,
			Type:        "bool",
			Description: "Compress output with gzip",
			Category:    "Output Format",
			IsEditable:  false,
		},
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
			Value:       100,
			Default:     100,
			Type:        "int",
			Description: "Packet buffer size, for channels that feed data to workers",
			Category:    "Performance",
			IsEditable:  false,
		},
		{
			Name:        "membuf-size",
			Value:       10485760,
			Default:     10485760,
			Type:        "int",
			Description: "Size for memory buffer (10MB)",
			Category:    "Performance",
			IsEditable:  false,
		},
		{
			Name:        "stream-buffer",
			Value:       10,
			Default:     10,
			Type:        "int",
			Description: "Input channel size for TCP / UDP stream processors",
			Category:    "Performance",
			IsEditable:  false,
		},
		{
			Name:        "stream-workers",
			Value:       "runtime.NumCPU()",
			Default:     "runtime.NumCPU()",
			Type:        "int",
			Description: "Number of TCP / UDP stream workers",
			Category:    "Performance",
			IsEditable:  false,
		},
		{
			Name:        "free-os-mem",
			Value:       0,
			Default:     0,
			Type:        "int",
			Description: "Free OS memory every X minutes (0 = disabled)",
			Category:    "Performance",
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
			Value:       100,
			Default:     100,
			Type:        "int",
			Description: "Flush assembler every N packets",
			Category:    "TCP Reassembly",
			IsEditable:  false,
		},
		{
			Name:        "checksum",
			Value:       false,
			Default:     false,
			Type:        "bool",
			Description: "Check TCP checksum",
			Category:    "TCP Reassembly",
			IsEditable:  false,
		},
		{
			Name:        "nooptcheck",
			Value:       true,
			Default:     true,
			Type:        "bool",
			Description: "Do not check TCP options (useful to ignore MSS on captures with TSO)",
			Category:    "TCP Reassembly",
			IsEditable:  false,
		},
		{
			Name:        "ignorefsmerr",
			Value:       true,
			Default:     true,
			Type:        "bool",
			Description: "Ignore TCP FSM errors",
			Category:    "TCP Reassembly",
			IsEditable:  false,
		},
		{
			Name:        "allowmissinginit",
			Value:       true,
			Default:     true,
			Type:        "bool",
			Description: "Support streams without SYN/SYN+ACK/ACK sequence",
			Category:    "TCP Reassembly",
			IsEditable:  false,
		},
		{
			Name:        "wait-conns",
			Value:       true,
			Default:     true,
			Type:        "bool",
			Description: "Wait for all connections to finish processing before cleanup",
			Category:    "TCP Reassembly",
			IsEditable:  false,
		},
		{
			Name:        "writeincomplete",
			Value:       false,
			Default:     false,
			Type:        "bool",
			Description: "Write incomplete response",
			Category:    "TCP Reassembly",
			IsEditable:  false,
		},
		{
			Name:        "sbuf-size",
			Value:       10,
			Default:     10,
			Type:        "int",
			Description: "Size for channel used to pass data to the stream decoders",
			Category:    "TCP Reassembly",
			IsEditable:  false,
		},
		{
			Name:        "max-stream-bytes",
			Value:       10485760,
			Default:     10485760,
			Type:        "int",
			Description: "Maximum number of bytes to reassemble per stream direction (0 = unlimited, default = 10MB)",
			Category:    "TCP Reassembly",
			IsEditable:  false,
		},
		{
			Name:        "max-buffered-pages-per-conn",
			Value:       0,
			Default:     0,
			Type:        "int",
			Description: "Maximum pages to buffer per connection for out-of-order packets (0 = unlimited, ~1900 bytes per page)",
			Category:    "TCP Reassembly",
			IsEditable:  false,
		},
		{
			Name:        "max-buffered-pages-total",
			Value:       0,
			Default:     0,
			Type:        "int",
			Description: "Maximum total pages to buffer across all connections (0 = unlimited, ~1900 bytes per page)",
			Category:    "TCP Reassembly",
			IsEditable:  false,
		},
		{
			Name:        "ip4defrag",
			Value:       true,
			Default:     true,
			Type:        "bool",
			Description: "Defragment IPv4 packets",
			Category:    "TCP Reassembly",
			IsEditable:  false,
		},
		{
			Name:        "remove-closed-streams",
			Value:       false,
			Default:     false,
			Type:        "bool",
			Description: "Remove TCP streams that receive a FIN or RST packet from the stream pool",
			Category:    "TCP Reassembly",
			IsEditable:  false,
		},

		// Flow and Connection Timeouts
		{
			Name:        "conn-flush-interval",
			Value:       10000,
			Default:     10000,
			Type:        "int",
			Description: "Flush connections every X flows",
			Category:    "Flow & Connection",
			IsEditable:  false,
		},
		{
			Name:        "conn-timeout",
			Value:       "10s",
			Default:     "10s",
			Type:        "duration",
			Description: "Close connections older than X seconds",
			Category:    "Flow & Connection",
			IsEditable:  false,
		},
		{
			Name:        "flow-flush-interval",
			Value:       2000,
			Default:     2000,
			Type:        "int",
			Description: "Flush flows every X flows",
			Category:    "Flow & Connection",
			IsEditable:  false,
		},
		{
			Name:        "flow-timeout",
			Value:       "10s",
			Default:     "10s",
			Type:        "duration",
			Description: "Close flows older than flow timeout",
			Category:    "Flow & Connection",
			IsEditable:  false,
		},
		{
			Name:        "close-pending-timeout",
			Value:       "5s",
			Default:     "5s",
			Type:        "duration",
			Description: "Reassembly: close connections that have pending bytes",
			Category:    "Flow & Connection",
			IsEditable:  false,
		},
		{
			Name:        "close-inactive-timeout",
			Value:       "24h0m0s",
			Default:     "24h0m0s",
			Type:        "duration",
			Description: "Reassembly: close connections that are inactive",
			Category:    "Flow & Connection",
			IsEditable:  false,
		},

		// Device Profiling & Enrichment
		{
			Name:        "macDB",
			Value:       true,
			Default:     true,
			Type:        "bool",
			Description: "Use MAC to vendor database for device profiling",
			Category:    "Device Profiling",
			IsEditable:  false,
		},
		{
			Name:        "ja3DB",
			Value:       true,
			Default:     true,
			Type:        "bool",
			Description: "Use JA3 database for device profiling",
			Category:    "Device Profiling",
			IsEditable:  false,
		},
		{
			Name:        "serviceDB",
			Value:       true,
			Default:     true,
			Type:        "bool",
			Description: "Use service database for device profiling",
			Category:    "Device Profiling",
			IsEditable:  false,
		},
		{
			Name:        "geoDB",
			Value:       false,
			Default:     false,
			Type:        "bool",
			Description: "Use geolocation for device profiling",
			Category:    "Device Profiling",
			IsEditable:  false,
		},
		{
			Name:        "reverse-dns",
			Value:       false,
			Default:     false,
			Type:        "bool",
			Description: "Resolve IPs to domains via the operating system's default DNS resolver",
			Category:    "Device Profiling",
			IsEditable:  false,
		},
		{
			Name:        "local-dns",
			Value:       false,
			Default:     false,
			Type:        "bool",
			Description: "Resolve DNS locally via hosts file in the database dir",
			Category:    "Device Profiling",
			IsEditable:  false,
		},

		// Packet Processing
		{
			Name:        "base",
			Value:       "ethernet",
			Default:     "ethernet",
			Type:        "string",
			Description: "Select base layer",
			Category:    "Packet Processing",
			IsEditable:  false,
		},
		{
			Name:        "opts",
			Value:       "lazy",
			Default:     "lazy",
			Type:        "string",
			Description: "Select decoding options",
			Category:    "Packet Processing",
			IsEditable:  false,
		},
		{
			Name:        "payload",
			Value:       false,
			Default:     false,
			Type:        "bool",
			Description: "Capture payload for supported layers",
			Category:    "Packet Processing",
			IsEditable:  false,
		},
		{
			Name:        "context",
			Value:       true,
			Default:     true,
			Type:        "bool",
			Description: "Add packet flow context to selected audit records",
			Category:    "Packet Processing",
			IsEditable:  false,
		},
		{
			Name:        "entropy",
			Value:       false,
			Default:     false,
			Type:        "bool",
			Description: "Enable entropy calculation for Eth, IP, TCP and UDP payloads",
			Category:    "Packet Processing",
			IsEditable:  false,
		},
		{
			Name:        "bpf",
			Value:       "",
			Default:     "",
			Type:        "string",
			Description: "Supply a BPF filter to use prior to processing packets",
			Category:    "Packet Processing",
			IsEditable:  false,
		},

		// Live Capture
		{
			Name:        "promisc",
			Value:       true,
			Default:     true,
			Type:        "bool",
			Description: "Toggle promiscuous mode for live capture",
			Category:    "Live Capture",
			IsEditable:  false,
		},
		{
			Name:        "snaplen",
			Value:       1514,
			Default:     1514,
			Type:        "int",
			Description: "Configure snaplen for live capture from interface",
			Category:    "Live Capture",
			IsEditable:  false,
		},
		{
			Name:        "timeout",
			Value:       "1s",
			Default:     "1s",
			Type:        "duration",
			Description: "Set timeout for live capture (0 = block forever)",
			Category:    "Live Capture",
			IsEditable:  false,
		},

		// Service Detection
		{
			Name:        "stop-after-harvester-match",
			Value:       true,
			Default:     true,
			Type:        "bool",
			Description: "Stop processing the conversation after the first credential harvester returned a result",
			Category:    "Service Detection",
			IsEditable:  false,
		},
		{
			Name:        "stop-after-service-match",
			Value:       true,
			Default:     true,
			Type:        "bool",
			Description: "Stop processing the conversation after the first service probe returned a result",
			Category:    "Service Detection",
			IsEditable:  false,
		},
		{
			Name:        "bsize",
			Value:       256,
			Default:     256,
			Type:        "int",
			Description: "Size of the stored service banners in bytes",
			Category:    "Service Detection",
			IsEditable:  false,
		},
		{
			Name:        "hbsize",
			Value:       256,
			Default:     256,
			Type:        "int",
			Description: "Size of the data passed to the credential harvesters in bytes",
			Category:    "Service Detection",
			IsEditable:  false,
		},

		// Compression
		{
			Name:        "compression-block-size",
			Value:       1048576,
			Default:     1048576,
			Type:        "int",
			Description: "Block size used for parallel compression (1MB)",
			Category:    "Compression",
			IsEditable:  false,
		},
		{
			Name:        "compression-level",
			Value:       "best-speed",
			Default:     "best-speed",
			Type:        "string",
			Description: "Level of compression",
			Category:    "Compression",
			IsEditable:  false,
		},

		// Visualization
		{
			Name:        "scatter",
			Value:       true,
			Default:     true,
			Type:        "bool",
			Description: "Generate a scatter plot for labeled audit records",
			Category:    "Visualization",
			IsEditable:  false,
		},
		{
			Name:        "scatter-duration",
			Value:       "5m0s",
			Default:     "5m0s",
			Type:        "duration",
			Description: "Interval for scatter chart",
			Category:    "Visualization",
			IsEditable:  false,
		},
		{
			Name:        "pps",
			Value:       false,
			Default:     false,
			Type:        "bool",
			Description: "Generate a line plot for throughput in packets per second",
			Category:    "Visualization",
			IsEditable:  false,
		},

		// Advanced Configuration
		{
			Name:        "debug",
			Value:       false,
			Default:     false,
			Type:        "bool",
			Description: "Debug logging (disabled in try service)",
			Category:    "Advanced",
			IsEditable:  false,
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
			Name:        "log-errors",
			Value:       false,
			Default:     false,
			Type:        "bool",
			Description: "Enable verbose packet decoding error logging",
			Category:    "Advanced",
			IsEditable:  false,
		},
		{
			Name:        "tcp-debug",
			Value:       false,
			Default:     false,
			Type:        "bool",
			Description: "Add debug output for TCP connections to debug.log",
			Category:    "Advanced",
			IsEditable:  false,
		},
		{
			Name:        "reassembly-debug",
			Value:       false,
			Default:     false,
			Type:        "bool",
			Description: "The reassembly will log verbose debugging information",
			Category:    "Advanced",
			IsEditable:  false,
		},
		{
			Name:        "hexdump",
			Value:       false,
			Default:     false,
			Type:        "bool",
			Description: "Dump packets used in stream reassembly as hex to the reassembly.log file",
			Category:    "Advanced",
			IsEditable:  false,
		},
		{
			Name:        "quiet",
			Value:       false,
			Default:     false,
			Type:        "bool",
			Description: "Don't print infos to stdout",
			Category:    "Advanced",
			IsEditable:  false,
		},
		{
			Name:        "time",
			Value:       false,
			Default:     false,
			Type:        "bool",
			Description: "Print processing time even in quiet mode",
			Category:    "Advanced",
			IsEditable:  false,
		},
		{
			Name:        "conns",
			Value:       false,
			Default:     false,
			Type:        "bool",
			Description: "Save raw TCP connections",
			Category:    "Advanced",
			IsEditable:  false,
		},
		{
			Name:        "encode",
			Value:       false,
			Default:     false,
			Type:        "bool",
			Description: "Encode data written into CSV file",
			Category:    "Advanced",
			IsEditable:  false,
		},
	}

	response := map[string]interface{}{
		"readOnly":      true,
		"isServiceMode": true,
		"options":       options,
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(response); err != nil {
		log.Printf("[Service] handleConfig: failed to encode response: %v", err)
		http.Error(w, fmt.Sprintf("Failed to encode response: %v", err), http.StatusInternalServerError)
		return
	}

	log.Printf("[Service] handleConfig: response sent successfully")
}

// DecoderInfo represents information about a decoder
type DecoderInfo struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Type        string `json:"type"`
	Layer       string `json:"layer,omitempty"`
	Port        int32  `json:"port,omitempty"`
	Enabled     bool   `json:"enabled"`
}

// DecodersResponse represents the response with all decoder information
type DecodersResponse struct {
	Packet   []DecoderInfo `json:"packet"`
	GoPacket []DecoderInfo `json:"gopacket"`
	Stream   []DecoderInfo `json:"stream"`
	Abstract []DecoderInfo `json:"abstract"`
}

// DecoderConfig represents the decoder configuration that can be saved
type DecoderConfig struct {
	IncludeDecoders string   `json:"includeDecoders"`
	ExcludeDecoders string   `json:"excludeDecoders"`
	EnabledDecoders []string `json:"enabledDecoders"`
}

// handleDecoders returns information about all available decoders
func (s *Server) handleDecoders(w http.ResponseWriter, r *http.Request) {
	log.Printf("[Service] handleDecoders called: method=%s", r.Method)

	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// For try service, decoders are read-only and we return default configuration
	// All decoders are enabled by default
	response := DecodersResponse{
		Packet:   make([]DecoderInfo, 0),
		GoPacket: make([]DecoderInfo, 0),
		Stream:   make([]DecoderInfo, 0),
		Abstract: make([]DecoderInfo, 0),
	}

	// Get packet decoders
	for _, d := range packet.GetPacketDecoders() {
		response.Packet = append(response.Packet, DecoderInfo{
			Name:        stripNCPrefix(d.GetName()),
			Description: d.GetDescription(),
			Type:        "packet",
			Enabled:     true, // All enabled in try service
		})
	}

	// Get gopacket decoders
	for _, d := range packet.GetGoPacketDecoders() {
		name := d.GetName()
		response.GoPacket = append(response.GoPacket, DecoderInfo{
			Name:        stripNCPrefix(name),
			Description: d.Description,
			Type:        "gopacket",
			Layer:       d.Layer.String(),
			Enabled:     true, // All enabled in try service
		})
	}

	// Get stream decoders
	for port, d := range stream.DefaultStreamDecoders {
		response.Stream = append(response.Stream, DecoderInfo{
			Name:        stripNCPrefix(d.GetName()),
			Description: d.GetDescription(),
			Type:        "stream",
			Port:        port,
			Enabled:     true, // All enabled in try service
		})
	}

	// Get abstract decoders
	for _, d := range stream.DefaultAbstractDecoders {
		response.Abstract = append(response.Abstract, DecoderInfo{
			Name:        stripNCPrefix(d.GetName()),
			Description: d.GetDescription(),
			Type:        "abstract",
			Enabled:     true, // All enabled in try service
		})
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(response); err != nil {
		log.Printf("[Service] handleDecoders: failed to encode response: %v", err)
		http.Error(w, fmt.Sprintf("Failed to encode response: %v", err), http.StatusInternalServerError)
		return
	}

	log.Printf("[Service] handleDecoders: response sent successfully")
}

// loadDecoderConfig returns the default decoder configuration (all decoders enabled)
func (s *Server) loadDecoderConfig() DecoderConfig {
	// In service mode, decoder config is read-only and returns default config
	return DecoderConfig{
		IncludeDecoders: "",
		ExcludeDecoders: "",
		EnabledDecoders: []string{},
	}
}

// handleDecoderConfig handles GET requests for decoder configuration (read-only in try service)
func (s *Server) handleDecoderConfig(w http.ResponseWriter, r *http.Request) {
	log.Printf("[Service] handleDecoderConfig called: method=%s", r.Method)

	if r.Method != http.MethodGet {
		// POST is not allowed in try service
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"error":   "Decoder configuration is read-only in try service mode",
		})
		return
	}

	// Return default configuration (all decoders enabled)
	config := s.loadDecoderConfig()

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(config); err != nil {
		log.Printf("[Service] handleDecoderConfig: failed to encode response: %v", err)
		http.Error(w, fmt.Sprintf("Failed to encode response: %v", err), http.StatusInternalServerError)
		return
	}

	log.Printf("[Service] handleDecoderConfig: response sent successfully")
}

// handleDecodersRouter routes decoder-related requests to the appropriate handler
func (s *Server) handleDecodersRouter(w http.ResponseWriter, r *http.Request) {
	log.Printf("[Service] Decoders router: path=%s", r.URL.Path)

	path := r.URL.Path

	// Check if this is a request for decoder config
	if path == "/api/decoders/config" {
		log.Printf("[Service] Routing to handleDecoderConfig")
		s.handleDecoderConfig(w, r)
		return
	}

	// Check if this is a request for ALL decoder fields: /api/decoders/fields
	if path == "/api/decoders/fields" {
		log.Printf("[Service] Routing to handleAllDecoderFields")
		s.handleAllDecoderFields(w, r)
		return
	}

	// Check if this is a request for specific decoder fields: /api/decoders/{name}/fields
	if strings.Contains(path, "/fields") && path != "/api/decoders" && path != "/api/decoders/" {
		log.Printf("[Service] Routing to handleDecoderFields")
		s.handleDecoderFields(w, r)
		return
	}

	// Otherwise, it's a list decoders request
	log.Printf("[Service] Routing to handleDecoders")
	s.handleDecoders(w, r)
}

// stripNCPrefix removes the "NC_" prefix from decoder names for display
func stripNCPrefix(name string) string {
	return strings.TrimPrefix(name, "NC_")
}

// FieldInfo represents information about a field in an audit record
type FieldInfo struct {
	Name string `json:"name"`
	Type string `json:"type"`
}

// DecoderFieldsResponse represents the response with field information for a decoder
type DecoderFieldsResponse struct {
	DecoderName string      `json:"decoderName"`
	Fields      []FieldInfo `json:"fields"`
}

// DecoderConfigFile represents metadata about a saved decoder configuration file
type DecoderConfigFile struct {
	Name         string `json:"name"`
	Path         string `json:"path"`
	ModifiedTime int64  `json:"modifiedTime"`
	Size         int64  `json:"size"`
}

// handleListDecoderConfigs returns a list of saved decoder configuration files
// In service mode, this returns predefined configurations only
func (s *Server) handleListDecoderConfigs(w http.ResponseWriter, r *http.Request) {
	log.Printf("[Service] handleListDecoderConfigs called: method=%s", r.Method)

	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// In service mode, we return empty list as configurations are read-only
	// Administrators can place predefined configs in the config directory if needed
	configFiles := make([]DecoderConfigFile, 0)

	// Optionally, check for predefined configs in the config directory
	configRoot := os.Getenv("NC_CONFIG_ROOT")
	if configRoot == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			configRoot = filepath.Join("/usr", "local", "etc", "netcap")
		} else {
			configRoot = filepath.Join(home, ".config", "netcap")
		}
	}
	configDir := filepath.Join(configRoot, "decoder-configs")

	// Try to read directory (but don't fail if it doesn't exist)
	files, err := os.ReadDir(configDir)
	if err == nil {
		for _, file := range files {
			// Only include .json files
			if file.IsDir() || !strings.HasSuffix(file.Name(), ".json") {
				continue
			}

			info, err := file.Info()
			if err != nil {
				continue
			}

			configFiles = append(configFiles, DecoderConfigFile{
				Name:         strings.TrimSuffix(file.Name(), ".json"),
				Path:         filepath.Join(configDir, file.Name()),
				ModifiedTime: info.ModTime().Unix(),
				Size:         info.Size(),
			})
		}
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(configFiles); err != nil {
		log.Printf("[Service] handleListDecoderConfigs: failed to encode response: %v", err)
		http.Error(w, fmt.Sprintf("Failed to encode response: %v", err), http.StatusInternalServerError)
		return
	}

	log.Printf("[Service] handleListDecoderConfigs: response sent successfully (%d configs)", len(configFiles))
}

// handleLoadDecoderConfig loads a decoder configuration from a predefined file
// In service mode, this is read-only and only loads from predefined configs
func (s *Server) handleLoadDecoderConfig(w http.ResponseWriter, r *http.Request) {
	log.Printf("[Service] handleLoadDecoderConfig called: method=%s", r.Method)

	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var request struct {
		Name string `json:"name"`
	}

	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		http.Error(w, fmt.Sprintf("Invalid request: %v", err), http.StatusBadRequest)
		return
	}

	if request.Name == "" {
		http.Error(w, "Configuration name is required", http.StatusBadRequest)
		return
	}

	configRoot := os.Getenv("NC_CONFIG_ROOT")
	if configRoot == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			configRoot = filepath.Join("/usr", "local", "etc", "netcap")
		} else {
			configRoot = filepath.Join(home, ".config", "netcap")
		}
	}
	configDir := filepath.Join(configRoot, "decoder-configs")
	configPath := filepath.Join(configDir, request.Name+".json")

	// Read the configuration file
	data, err := os.ReadFile(configPath)
	if err != nil {
		log.Printf("[Service] handleLoadDecoderConfig: failed to read config file: %v", err)
		http.Error(w, fmt.Sprintf("Failed to read configuration file: %v", err), http.StatusNotFound)
		return
	}

	var config DecoderConfig
	if err := json.Unmarshal(data, &config); err != nil {
		log.Printf("[Service] handleLoadDecoderConfig: failed to parse config file: %v", err)
		http.Error(w, fmt.Sprintf("Failed to parse configuration file: %v", err), http.StatusBadRequest)
		return
	}

	// Note: In service mode, we just return the config but don't apply it
	// since all capture configurations are set at server startup
	w.Header().Set("Content-Type", "application/json")
	response := map[string]interface{}{
		"success": true,
		"message": fmt.Sprintf("Configuration '%s' loaded (read-only in service mode)", request.Name),
		"config":  config,
		"warning": "Configuration changes are not applied in service mode. All captures use the default configuration.",
	}
	if err := json.NewEncoder(w).Encode(response); err != nil {
		log.Printf("[Service] handleLoadDecoderConfig: failed to encode response: %v", err)
		http.Error(w, fmt.Sprintf("Failed to encode response: %v", err), http.StatusInternalServerError)
		return
	}

	log.Printf("[Service] handleLoadDecoderConfig: response sent successfully")
}

// handleUploadDecoderConfig returns an error as decoder config uploads are disabled in service mode
func (s *Server) handleUploadDecoderConfig(w http.ResponseWriter, r *http.Request) {
	log.Printf("[Service] handleUploadDecoderConfig called: method=%s (disabled)", r.Method)

	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Decoder config uploads are not allowed in try service mode
	response := map[string]interface{}{
		"success": false,
		"error":   "Decoder configuration uploads are disabled in service mode",
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusForbidden)
	if err := json.NewEncoder(w).Encode(response); err != nil {
		log.Printf("[Service] handleUploadDecoderConfig: failed to encode response: %v", err)
		http.Error(w, fmt.Sprintf("Failed to encode response: %v", err), http.StatusInternalServerError)
		return
	}

	log.Printf("[Service] handleUploadDecoderConfig: disabled response sent")
}

// handleDeleteDecoderConfig returns an error as decoder config deletion is disabled in service mode
func (s *Server) handleDeleteDecoderConfig(w http.ResponseWriter, r *http.Request) {
	log.Printf("[Service] handleDeleteDecoderConfig called: method=%s (disabled)", r.Method)

	if r.Method != http.MethodDelete && r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Decoder config deletion is not allowed in try service mode
	response := map[string]interface{}{
		"success": false,
		"error":   "Decoder configuration deletion is disabled in service mode",
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusForbidden)
	if err := json.NewEncoder(w).Encode(response); err != nil {
		log.Printf("[Service] handleDeleteDecoderConfig: failed to encode response: %v", err)
		http.Error(w, fmt.Sprintf("Failed to encode response: %v", err), http.StatusInternalServerError)
		return
	}

	log.Printf("[Service] handleDeleteDecoderConfig: disabled response sent")
}

// handleSaveDecoderConfigAs returns an error as saving decoder configs is disabled in service mode
func (s *Server) handleSaveDecoderConfigAs(w http.ResponseWriter, r *http.Request) {
	log.Printf("[Service] handleSaveDecoderConfigAs called: method=%s (disabled)", r.Method)

	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Saving decoder configs is not allowed in try service mode
	response := map[string]interface{}{
		"success": false,
		"error":   "Saving decoder configurations is disabled in service mode",
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusForbidden)
	if err := json.NewEncoder(w).Encode(response); err != nil {
		log.Printf("[Service] handleSaveDecoderConfigAs: failed to encode response: %v", err)
		http.Error(w, fmt.Sprintf("Failed to encode response: %v", err), http.StatusInternalServerError)
		return
	}

	log.Printf("[Service] handleSaveDecoderConfigAs: disabled response sent")
}

// handleDecoderFields returns field information for a specific decoder
func (s *Server) handleDecoderFields(w http.ResponseWriter, r *http.Request) {
	log.Printf("[Service] handleDecoderFields called: path=%s", r.URL.Path)

	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Extract decoder name from URL path
	pathParts := strings.Split(strings.TrimPrefix(r.URL.Path, "/api/decoders/"), "/")

	if len(pathParts) < 2 || pathParts[1] != "fields" {
		http.Error(w, fmt.Sprintf("Invalid path format. Expected: /api/decoders/{name}/fields, got: %s", r.URL.Path), http.StatusBadRequest)
		return
	}

	decoderName := pathParts[0]
	if decoderName == "" {
		http.Error(w, "Decoder name is required", http.StatusBadRequest)
		return
	}

	// Try to get the audit record type for this decoder
	record := webui.InitRecordForDecoder(decoderName)
	if record == nil {
		http.Error(w, fmt.Sprintf("Unknown decoder: %s", decoderName), http.StatusNotFound)
		return
	}

	// Get field names and types
	fields := webui.GetRecordFields(record)

	response := DecoderFieldsResponse{
		DecoderName: decoderName,
		Fields:      convertFieldInfo(fields),
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(response); err != nil {
		http.Error(w, fmt.Sprintf("Failed to encode response: %v", err), http.StatusInternalServerError)
	}

	log.Printf("[Service] handleDecoderFields: response sent successfully for %s", decoderName)
}

// convertFieldInfo converts webui.FieldInfo to service FieldInfo
func convertFieldInfo(fields []webui.FieldInfo) []FieldInfo {
	result := make([]FieldInfo, len(fields))
	for i, f := range fields {
		result[i] = FieldInfo{
			Name: f.Name,
			Type: f.Type,
		}
	}
	return result
}

// handleAllDecoderFields returns field information for ALL decoders at once
func (s *Server) handleAllDecoderFields(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Build map of decoder name -> fields
	allFields := make(map[string][]FieldInfo)

	// Dynamically build list of decoder names from all available decoders
	var decoderNames []string

	// Add packet decoders
	for _, d := range packet.GetPacketDecoders() {
		decoderNames = append(decoderNames, d.GetName())
	}

	// Add gopacket decoders
	for _, d := range packet.GetGoPacketDecoders() {
		decoderNames = append(decoderNames, d.GetName())
	}

	// Add stream decoders
	for _, d := range stream.DefaultStreamDecoders {
		decoderNames = append(decoderNames, d.GetName())
	}

	// Add abstract decoders
	for _, d := range stream.DefaultAbstractDecoders {
		decoderNames = append(decoderNames, d.GetName())
	}

	log.Printf("[Service] handleAllDecoderFields: processing %d decoders", len(decoderNames))

	// Get fields for each decoder
	for _, name := range decoderNames {
		// Use recover to catch panics for invalid decoders
		func() {
			defer func() {
				if r := recover(); r != nil {
					log.Printf("[Service] Decoder %s caused panic: %v (skipping)", name, r)
				}
			}()

			record := webui.InitRecordForDecoder(name)
			if record == nil {
				log.Printf("[Service] Skipping decoder %s: InitRecord returned nil", name)
				return
			}

			fields := webui.GetRecordFields(record)
			if len(fields) > 0 {
				allFields[stripNCPrefix(name)] = convertFieldInfo(fields)
			}
		}()
	}

	log.Printf("[Service] handleAllDecoderFields: returning %d decoders with field info", len(allFields))

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(allFields); err != nil {
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
	log.Printf("[Service] handleSystemInfo called: method=%s", r.Method)

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
		log.Printf("[Service] handleSystemInfo: failed to encode response: %v", err)
		http.Error(w, fmt.Sprintf("Failed to encode response: %v", err), http.StatusInternalServerError)
		return
	}

	log.Printf("[Service] handleSystemInfo: response sent successfully")
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
	log.Printf("[Service] handleNetworkInterfaces called: method=%s", r.Method)

	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	interfaces, err := net.Interfaces()
	if err != nil {
		log.Printf("[Service] handleNetworkInterfaces: failed to get network interfaces: %v", err)
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
		log.Printf("[Service] handleNetworkInterfaces: failed to encode response: %v", err)
		http.Error(w, fmt.Sprintf("Failed to encode response: %v", err), http.StatusInternalServerError)
		return
	}

	log.Printf("[Service] handleNetworkInterfaces: response sent successfully")
}

// handleChartData proxies chart data requests to the webUI handler with current session
func (s *Server) handleChartData(w http.ResponseWriter, r *http.Request) {
	session := s.GetCurrentSession()
	if session == nil || session.Status != StatusCompleted {
		http.Error(w, "No active session or analysis not completed", http.StatusServiceUnavailable)
		return
	}

	// Proxy to webUI chart handler with session's output directory
	webui.HandleChartData(session.OutputDir)(w, r)
}

// handleChartFields proxies chart fields requests to the webUI handler with current session
func (s *Server) handleChartFields(w http.ResponseWriter, r *http.Request) {
	session := s.GetCurrentSession()
	if session == nil || session.Status != StatusCompleted {
		http.Error(w, "No active session or analysis not completed", http.StatusServiceUnavailable)
		return
	}

	// Proxy to webUI chart handler with session's output directory
	webui.HandleChartFields(session.OutputDir)(w, r)
}
