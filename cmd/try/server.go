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

package try

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/dreadl0ck/netcap/cmd/try/webui"
)

// AnalysisJob represents a job in the analysis queue
type AnalysisJob struct {
	SessionID string
	InputFile string
	OutputDir string
	EnableDPI bool
}

// Server represents the try service HTTP server
type Server struct {
	addr           string
	dataDir        string
	enableDPI      bool
	httpServer     *http.Server
	sessionManager *SessionManager
	jobQueue       chan *AnalysisJob
	shutdownChan   chan struct{}
	wg             sync.WaitGroup
	webUIServer    *webui.Server
	currentSession string // Currently active session for webUI viewing
	mu             sync.RWMutex
}

// NewServer creates a new try service server
func NewServer(addr, dataDir string, enableDPI bool) (*Server, error) {
	// Create data directory if it doesn't exist
	if err := os.MkdirAll(dataDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create data directory: %w", err)
	}

	// Create subdirectories
	uploadsDir := filepath.Join(dataDir, "uploads")
	resultsDir := filepath.Join(dataDir, "results")

	if err := os.MkdirAll(uploadsDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create uploads directory: %w", err)
	}

	if err := os.MkdirAll(resultsDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create results directory: %w", err)
	}

	server := &Server{
		addr:           addr,
		dataDir:        dataDir,
		enableDPI:      enableDPI,
		sessionManager: NewSessionManager(*flagMaxAnalysisHour, *flagSessionExpiry),
		jobQueue:       make(chan *AnalysisJob, 100),
		shutdownChan:   make(chan struct{}),
	}

	// Initialize webUI server
	server.webUIServer = webui.NewServer(server)

	return server, nil
}

// Start starts the HTTP server and background workers
func (s *Server) Start() error {
	mux := http.NewServeMux()

	// Try service API endpoints
	mux.HandleFunc("/api/upload", s.handleUpload)
	mux.HandleFunc("/api/status/", s.handleStatus) // Session-specific status for upload polling
	mux.HandleFunc("/api/try/sessions", s.handleListSessions)
	mux.HandleFunc("/api/try/session/", s.handleSessionSelect)
	mux.HandleFunc("/api/quota", s.handleQuota)
	mux.HandleFunc("/health", s.handleHealth)
	mux.HandleFunc("/view/", s.handleViewSession) // View specific session by ID (shareable link)

	// WebUI API endpoints (proxied to current session)
	mux.HandleFunc("/api/status", s.handleWebUIStatus)
	mux.HandleFunc("/api/stats", s.handleWebUIStats)
	mux.HandleFunc("/api/audit-stats", s.handleWebUIAuditStats)
	mux.HandleFunc("/api/files/input", s.handleWebUIInputFiles)
	mux.HandleFunc("/api/files/audit", s.handleWebUIAuditFiles)
	mux.HandleFunc("/api/files/logs", s.handleWebUILogFiles)
	mux.HandleFunc("/api/audit/", s.handleWebUIAuditRecords)
	mux.HandleFunc("/api/logs/", s.handleWebUILogContent)
	mux.HandleFunc("/api/set-directory", s.handleSetActiveDirectory)
	mux.HandleFunc("/api/dbs", s.handleDatabaseInfo)
	mux.HandleFunc("/api/dbs/update", s.handleUpdateDatabases)
	mux.HandleFunc("/api/version", s.handleVersion)
	mux.HandleFunc("/api/dpi", s.handleDPIInfo)
	mux.HandleFunc("/api/config", s.handleConfig)
	mux.HandleFunc("/api/decoders", s.handleDecoders)
	mux.HandleFunc("/api/decoders/config", s.handleDecoderConfig)
	mux.HandleFunc("/api/system-info", s.handleSystemInfo)

	// Download endpoint (updated path)
	mux.HandleFunc("/api/download/", s.handleDownload)

	// Static files - serve webUI (Next.js handles routing to upload page or dashboard)
	mux.Handle("/", s.webUIServer.HandleStatic(func() interface{} {
		// Always return current session if it exists
		// Frontend will handle routing based on session state
		return s.GetCurrentSession()
	}))

	s.httpServer = &http.Server{
		Addr:         s.addr,
		Handler:      s.corsMiddleware(mux),
		ReadTimeout:  60 * time.Second,
		WriteTimeout: 120 * time.Second,
		IdleTimeout:  180 * time.Second,
		// Increase max header size for file uploads
		MaxHeaderBytes: 1 << 20, // 1MB
	}

	// Start job processor
	s.wg.Add(1)
	go s.processJobs()

	// Start cleanup routine
	s.wg.Add(1)
	go s.cleanupRoutine()

	// Start HTTP server
	go func() {
		log.Printf("[TryService] Starting HTTP server on %s", s.addr)
		if err := s.httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Printf("[TryService] HTTP server error: %v", err)
		}
	}()

	return nil
}

// Stop gracefully stops the server
func (s *Server) Stop(ctx context.Context) error {
	log.Println("[TryService] Shutting down...")

	// Signal shutdown
	close(s.shutdownChan)

	// Stop HTTP server
	if err := s.httpServer.Shutdown(ctx); err != nil {
		log.Printf("[TryService] Error shutting down HTTP server: %v", err)
	}

	// Wait for background workers
	s.wg.Wait()

	log.Println("[TryService] Shutdown complete")
	return nil
}

// processJobs processes analysis jobs from the queue one at a time
func (s *Server) processJobs() {
	defer s.wg.Done()

	for {
		select {
		case job := <-s.jobQueue:
			s.runAnalysis(job)
		case <-s.shutdownChan:
			log.Println("[TryService] Job processor shutting down")
			return
		}
	}
}

// runAnalysis executes a netcap capture analysis
func (s *Server) runAnalysis(job *AnalysisJob) {
	log.Printf("[TryService] Starting analysis for session %s", job.SessionID)

	// Update status to processing
	s.sessionManager.UpdateSessionStatus(job.SessionID, StatusProcessing, "")

	// Build netcap capture command
	args := []string{
		"capture",
		"-read", job.InputFile,
		"-out", job.OutputDir,
		"-quiet",
		"-http", "", // Disable web UI server
	}

	if job.EnableDPI {
		args = append(args, "-dpi")
	}

	// Get the path to the current executable
	executable, err := os.Executable()
	if err != nil {
		log.Printf("[TryService] Failed to get executable path: %v", err)
		s.sessionManager.UpdateSessionStatus(job.SessionID, StatusFailed, "Internal error")
		return
	}

	// Run the capture command
	cmd := exec.Command(executable, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	startTime := time.Now()
	err = cmd.Run()
	duration := time.Since(startTime)

	if err != nil {
		log.Printf("[TryService] Analysis failed for session %s: %v (duration: %v)", job.SessionID, err, duration)
		s.sessionManager.UpdateSessionStatus(job.SessionID, StatusFailed, fmt.Sprintf("Analysis failed: %v", err))
		return
	}

	log.Printf("[TryService] Analysis completed for session %s (duration: %v)", job.SessionID, duration)
	s.sessionManager.UpdateSessionStatus(job.SessionID, StatusCompleted, "")
}

// cleanupRoutine periodically cleans up expired sessions
func (s *Server) cleanupRoutine() {
	defer s.wg.Done()

	ticker := time.NewTicker(time.Duration(*flagCleanupInterval) * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			s.performCleanup()
		case <-s.shutdownChan:
			log.Println("[TryService] Cleanup routine shutting down")
			return
		}
	}
}

// performCleanup removes expired sessions and their files
func (s *Server) performCleanup() {
	log.Println("[TryService] Running cleanup...")

	expiredSessions := s.sessionManager.CleanupExpiredSessions()

	for _, sessionID := range expiredSessions {
		log.Printf("[TryService] Cleaning up expired session: %s", sessionID)

		// Remove upload directory
		uploadDir := filepath.Join(s.dataDir, "uploads", sessionID)
		if err := os.RemoveAll(uploadDir); err != nil {
			log.Printf("[TryService] Error removing upload directory %s: %v", uploadDir, err)
		}

		// Remove results directory
		resultsDir := filepath.Join(s.dataDir, "results", sessionID)
		if err := os.RemoveAll(resultsDir); err != nil {
			log.Printf("[TryService] Error removing results directory %s: %v", resultsDir, err)
		}
	}

	if len(expiredSessions) > 0 {
		log.Printf("[TryService] Cleaned up %d expired session(s)", len(expiredSessions))
	}
}

// GetCurrentSession returns the currently selected session for webUI viewing
func (s *Server) GetCurrentSession() *SessionInfo {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.currentSession == "" {
		return nil
	}

	session, _ := s.sessionManager.GetSession(s.currentSession)
	return session
}

// SetCurrentSession sets the active session for webUI viewing
func (s *Server) SetCurrentSession(sessionID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.currentSession = sessionID
}

// WebUI proxy handlers - forward to webUI handlers with current session data

func (s *Server) handleWebUIStatus(w http.ResponseWriter, r *http.Request) {
	session := s.GetCurrentSession()

	response := map[string]interface{}{
		"isProcessing":  false,
		"isTryService":  true,
		"serverStarted": webui.GetServerStartTime().Unix(),
		"sessions":      len(s.sessionManager.GetAllSessions()),
	}

	if session != nil {
		response["outputDir"] = session.OutputDir
		response["inputFiles"] = []string{session.InputFilename}
		response["activeInputFile"] = session.InputFilename
		response["sessionId"] = session.SessionID
		response["status"] = string(session.Status)
		response["isProcessing"] = session.Status == StatusProcessing
	}

	respondJSON(w, http.StatusOK, response)
}

func (s *Server) handleWebUIStats(w http.ResponseWriter, r *http.Request) {
	session := s.GetCurrentSession()

	// Return empty stats if no session or not processing
	response := map[string]interface{}{
		"processingStats": map[string]interface{}{
			"currentFile":      "",
			"fileIndex":        0,
			"totalFiles":       0,
			"packetsProcessed": 0,
			"totalPackets":     0,
			"progressPercent":  0,
			"packetsPerSecond": 0,
			"profilesCount":    0,
			"servicesCount":    0,
			"lastUpdate":       0,
		},
		"fileErrors": map[string]interface{}{},
	}

	if session != nil && session.Status == StatusProcessing {
		// Show processing stats
		response["processingStats"] = map[string]interface{}{
			"currentFile":      session.InputFilename,
			"fileIndex":        1,
			"totalFiles":       1,
			"packetsProcessed": session.PacketsTotal,
			"totalPackets":     session.PacketsTotal,
			"progressPercent":  0, // We don't track this in real-time for try service
			"packetsPerSecond": 0,
			"profilesCount":    0,
			"servicesCount":    0,
			"lastUpdate":       time.Now().Unix(),
		}
	}

	respondJSON(w, http.StatusOK, response)
}

func (s *Server) handleWebUIInputFiles(w http.ResponseWriter, r *http.Request) {
	// Get client IP to retrieve all sessions for this user
	clientIP := getClientIP(r)

	// Get all sessions for this IP
	sessions := s.sessionManager.GetSessionsForIP(clientIP)

	files := []map[string]interface{}{}

	// Return files from all sessions for this user
	for _, session := range sessions {
		fileInfo := map[string]interface{}{
			"name":         session.InputFilename,
			"path":         session.InputFile,
			"size":         session.InputFileSize,
			"modifiedTime": session.UploadTimestamp.Unix(),
			"isCompleted":  session.Status == StatusCompleted,
			"sessionId":    session.SessionID, // Include session ID for reference
		}

		// Add error if failed
		if session.Status == StatusFailed && session.ErrorMessage != "" {
			fileInfo["error"] = session.ErrorMessage
		}

		files = append(files, fileInfo)
	}

	respondJSON(w, http.StatusOK, files)
}

func (s *Server) handleWebUIAuditFiles(w http.ResponseWriter, r *http.Request) {
	session := s.GetCurrentSession()
	if session == nil || session.Status != StatusCompleted {
		respondJSON(w, http.StatusOK, []interface{}{})
		return
	}

	webui.HandleAuditFiles(session.OutputDir)(w, r)
}

func (s *Server) handleWebUILogFiles(w http.ResponseWriter, r *http.Request) {
	session := s.GetCurrentSession()
	if session == nil || session.Status != StatusCompleted {
		respondJSON(w, http.StatusOK, []interface{}{})
		return
	}

	webui.HandleLogFiles(session.OutputDir)(w, r)
}

func (s *Server) handleWebUIAuditRecords(w http.ResponseWriter, r *http.Request) {
	session := s.GetCurrentSession()
	if session == nil || session.Status != StatusCompleted {
		respondJSON(w, http.StatusNotFound, map[string]string{
			"error": "No active session or analysis not completed",
		})
		return
	}

	webui.HandleAuditRecords(session.OutputDir)(w, r)
}

func (s *Server) handleWebUILogContent(w http.ResponseWriter, r *http.Request) {
	session := s.GetCurrentSession()
	if session == nil || session.Status != StatusCompleted {
		respondJSON(w, http.StatusNotFound, map[string]string{
			"error": "No active session or analysis not completed",
		})
		return
	}

	webui.HandleLogContent(session.OutputDir)(w, r)
}

func (s *Server) handleWebUIAuditStats(w http.ResponseWriter, r *http.Request) {
	session := s.GetCurrentSession()
	if session == nil || session.Status != StatusCompleted {
		// Return empty stats if no session or not completed
		respondJSON(w, http.StatusOK, map[string]interface{}{
			"totalRecords":       0,
			"exploitCount":       0,
			"vulnerabilityCount": 0,
			"credentialsCount":   0,
			"softwareCount":      0,
		})
		return
	}

	webui.HandleAuditStats(session.OutputDir)(w, r)
}

// handleSetActiveDirectory switches the active session based on input file
func (s *Server) handleSetActiveDirectory(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Parse request body
	var req struct {
		InputFile string `json:"inputFile"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondJSON(w, http.StatusBadRequest, map[string]string{
			"error": "Invalid request body",
		})
		return
	}

	// Get client IP to find sessions
	clientIP := getClientIP(r)
	sessions := s.sessionManager.GetSessionsForIP(clientIP)

	// Find the session that matches the input file
	var targetSession *SessionInfo
	for _, session := range sessions {
		// Match by input file path or filename
		if session.InputFile == req.InputFile || session.InputFilename == req.InputFile {
			targetSession = session
			break
		}
	}

	if targetSession == nil {
		respondJSON(w, http.StatusNotFound, map[string]string{
			"error": "Session not found for the specified input file",
		})
		return
	}

	// Set as current session
	s.SetCurrentSession(targetSession.SessionID)

	log.Printf("[TryService] Switched active session to %s (file: %s)", targetSession.SessionID, targetSession.InputFilename)

	respondJSON(w, http.StatusOK, map[string]interface{}{
		"success":         true,
		"outputDir":       targetSession.OutputDir,
		"activeInputFile": targetSession.InputFilename,
		"sessionId":       targetSession.SessionID,
	})
}

// corsMiddleware adds CORS headers and logs requests
func (s *Server) corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Log incoming request
		log.Printf("[TryService] %s %s from %s", r.Method, r.URL.Path, getClientIP(r))

		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// handleListSessions returns sessions for the client's IP with share URLs
func (s *Server) handleListSessions(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	clientIP := getClientIP(r)

	// Get sessions for this IP
	sessions := s.sessionManager.GetSessionsForIP(clientIP)

	// Generate share URLs and add to response
	protocol := "http"
	if r.TLS != nil {
		protocol = "https"
	}
	host := r.Host

	type SessionWithShare struct {
		*SessionInfo
		ShareURL string `json:"shareUrl"`
	}

	sessionsWithShare := make([]SessionWithShare, len(sessions))
	for i, session := range sessions {
		sessionsWithShare[i] = SessionWithShare{
			SessionInfo: session,
			ShareURL:    fmt.Sprintf("%s://%s/view/%s", protocol, host, session.SessionID),
		}
	}

	log.Printf("[TryService] Listing %d sessions for IP %s", len(sessionsWithShare), clientIP)
	respondJSON(w, http.StatusOK, sessionsWithShare)
}

// handleSessionSelect sets the active session for webUI viewing
func (s *Server) handleSessionSelect(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost && r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Extract session ID from URL
	sessionID := strings.TrimPrefix(r.URL.Path, "/api/try/session/")
	if sessionID == "" {
		respondJSON(w, http.StatusBadRequest, map[string]string{
			"error": "Session ID required",
		})
		return
	}

	// Verify session exists
	session, exists := s.sessionManager.GetSession(sessionID)
	if !exists {
		respondJSON(w, http.StatusNotFound, map[string]string{
			"error": "Session not found",
		})
		return
	}

	// Set as current session
	s.SetCurrentSession(sessionID)

	respondJSON(w, http.StatusOK, map[string]interface{}{
		"sessionId": sessionID,
		"status":    string(session.Status),
		"message":   "Session selected for viewing",
	})
}

// handleViewSession handles shareable URLs for viewing specific sessions
func (s *Server) handleViewSession(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Extract session ID from URL (format: /view/{sessionID})
	sessionID := strings.TrimPrefix(r.URL.Path, "/view/")
	if sessionID == "" {
		http.Error(w, "Session ID required", http.StatusBadRequest)
		return
	}

	// Verify session exists
	_, exists := s.sessionManager.GetSession(sessionID)
	if !exists {
		http.Error(w, "Session not found or expired", http.StatusNotFound)
		return
	}

	// Set as current session for viewing
	s.SetCurrentSession(sessionID)

	// Redirect to home page - the dashboard will show the session data
	// or redirect to upload page if still processing
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// getClientIP extracts the client IP from the request
func getClientIP(r *http.Request) string {
	// Check X-Forwarded-For header first (for proxies)
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		return xff
	}

	// Check X-Real-IP header
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return xri
	}

	// Fall back to RemoteAddr
	return r.RemoteAddr
}

// calculateDirectorySize calculates the total size of files in a directory recursively
func calculateDirectorySize(path string) (int64, error) {
	var size int64
	err := filepath.Walk(path, func(_ string, info os.FileInfo, err error) error {
		if err != nil {
			// Skip inaccessible files/dirs
			return nil
		}
		if !info.IsDir() {
			size += info.Size()
		}
		return nil
	})
	return size, err
}

// GetCurrentStorageUsage returns the current storage usage in bytes
func (s *Server) GetCurrentStorageUsage() int64 {
	uploadsDir := filepath.Join(s.dataDir, "uploads")
	resultsDir := filepath.Join(s.dataDir, "results")

	uploadsSize, _ := calculateDirectorySize(uploadsDir)
	resultsSize, _ := calculateDirectorySize(resultsDir)

	return uploadsSize + resultsSize
}

// CheckStorageLimit checks if adding a file of the given size would exceed the storage limit
// Returns true if storage is available, false if limit would be exceeded
func (s *Server) CheckStorageLimit(additionalBytes int64) (allowed bool, currentUsage int64, maxStorage int64) {
	// If max storage is 0, unlimited storage is allowed
	if *flagMaxStorageBytes == 0 {
		return true, 0, 0
	}

	currentUsage = s.GetCurrentStorageUsage()
	maxStorage = *flagMaxStorageBytes

	// Check if adding the new file would exceed the limit
	allowed = (currentUsage + additionalBytes) <= maxStorage

	return allowed, currentUsage, maxStorage
}
