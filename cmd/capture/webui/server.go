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
	"context"
	"fmt"
	stdio "io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/dreadl0ck/netcap/collector"
	"github.com/dreadl0ck/netcap/decoder/config"
	"github.com/dreadl0ck/netcap/defaults"
	"github.com/dreadl0ck/netcap/io"
	"github.com/dreadl0ck/netcap/resolvers"
	"github.com/dreadl0ck/netcap/utils"
)

// ProcessingStats represents live processing statistics
type ProcessingStats struct {
	CurrentFile      string  `json:"currentFile"`
	FileIndex        int     `json:"fileIndex"`
	TotalFiles       int     `json:"totalFiles"`
	PacketsProcessed int64   `json:"packetsProcessed"`
	TotalPackets     int64   `json:"totalPackets"`
	ProgressPercent  float64 `json:"progressPercent"`
	PacketsPerSecond int64   `json:"packetsPerSecond"`
	ProfilesCount    int     `json:"profilesCount"`
	ServicesCount    int     `json:"servicesCount"`
	LastUpdate       int64   `json:"lastUpdate"`
}

// FileError represents an error that occurred during file processing
type FileError struct {
	InputFile    string `json:"inputFile"`
	Error        string `json:"error"`
	Timestamp    int64  `json:"timestamp"`
	ErrorLogPath string `json:"errorLogPath,omitempty"` // Path to detailed error log file
}

// Server represents the web UI HTTP server
type Server struct {
	addr               string
	outDir             string
	baseOutDir         string // Original output directory for multi-file mode
	inputFiles         []string
	assetsPath         string
	httpServer         *http.Server
	mu                 sync.RWMutex
	isProcessing       bool
	isLiveMode         bool                           // Whether in live capture mode
	stopCapture        context.CancelFunc             // Function to stop live capture
	activeInputFile    string                         // Currently selected input file for viewing
	completedFiles     map[string]bool                // Tracks which files have completed processing
	processingStats    ProcessingStats                // Live processing statistics
	fileErrors         map[string]FileError           // Tracks errors for each file
	debugLogging       bool                           // Runtime debug logging state
	dpiConfigured      bool                           // Whether DPI was configured at startup (via -dpi flag)
	collector          CollectorInterface             // Reference to collector for runtime config changes
	uploadCallback     UploadCallbackFunc             // Function to call when files are uploaded
	fileBPFFilters     map[string]string              // Tracks BPF filter used for each file
	fileOutputDirs     map[string]string              // Tracks actual output directory for each file
	fileProcessingTime map[string]float64             // Tracks processing time in seconds for each file
	dpiPreferences     map[string]*UserDPIPreferences // DPI preferences per user IP
	reportedIssues     map[string]bool                // Tracks which file hashes have had issues reported

	// Service mode fields (nil in local mode)
	isServiceMode  bool              // Flag to differentiate modes
	sessionManager *SessionManager   // Session manager (nil in local mode)
	serviceConfig  *ServiceConfig    // Service configuration (nil in local mode)
	jobQueue       chan *AnalysisJob // Job queue (nil in local mode)
	shutdownChan   chan struct{}     // Shutdown channel for graceful shutdown
	wg             sync.WaitGroup    // Track background workers
	currentSession string            // Currently active session for webUI viewing (service mode only)
}

// UploadCallbackFunc is called when files are uploaded via the web UI
type UploadCallbackFunc func(filePath string) error

// CollectorInterface defines the methods we need from the Collector
type CollectorInterface interface {
	SetLogLevel(debug bool)
}

// NewServer creates a new web UI server
func NewServer(addr, outDir string, inputFiles []string, assetsPath string, debugLogging bool, dpiConfigured bool, isServiceMode bool, serviceConfig *ServiceConfig) *Server {
	log.Printf("[WebUI] NewServer called with outDir=%s, numInputFiles=%d", outDir, len(inputFiles))

	s := &Server{
		addr:               addr,
		outDir:             outDir,
		baseOutDir:         outDir,
		inputFiles:         inputFiles,
		assetsPath:         assetsPath,
		isProcessing:       true,
		dpiConfigured:      dpiConfigured,
		completedFiles:     make(map[string]bool),
		fileErrors:         make(map[string]FileError),
		fileBPFFilters:     make(map[string]string),
		fileOutputDirs:     make(map[string]string),
		fileProcessingTime: make(map[string]float64),
		dpiPreferences:     make(map[string]*UserDPIPreferences),
		reportedIssues:     make(map[string]bool),
		processingStats: ProcessingStats{
			TotalFiles: len(inputFiles),
		},
		debugLogging:  debugLogging,
		isServiceMode: isServiceMode,
		serviceConfig: serviceConfig,
	}

	log.Printf("[WebUI] Server initialized: outDir=%s, baseOutDir=%s", s.outDir, s.baseOutDir)

	// Initialize service mode components if enabled
	if isServiceMode && serviceConfig != nil {
		s.sessionManager = NewSessionManager(
			serviceConfig.MaxAnalysisHour,
			serviceConfig.SessionExpiry,
			serviceConfig.MaxIssueReportsPerDay,
		)
		s.jobQueue = make(chan *AnalysisJob, 100)
		s.shutdownChan = make(chan struct{})

		// In service mode, ensure data directory exists
		if err := os.MkdirAll(serviceConfig.DataDir, 0755); err != nil {
			log.Printf("[Server] Warning: Failed to create data directory: %v", err)
		}

		// Create subdirectories
		uploadsDir := filepath.Join(serviceConfig.DataDir, "uploads")
		resultsDir := filepath.Join(serviceConfig.DataDir, "results")

		if err := os.MkdirAll(uploadsDir, 0777); err != nil {
			log.Printf("[Server] Warning: Failed to create uploads directory: %v", err)
		}

		if err := os.MkdirAll(resultsDir, 0777); err != nil {
			log.Printf("[Server] Warning: Failed to create results directory: %v", err)
		}

		log.Printf("[Server] Service mode enabled with data directory: %s", serviceConfig.DataDir)
	}

	return s
}

// loadPreloadedPcaps scans the pcaps directory and queues preloaded pcap files for analysis
func (s *Server) loadPreloadedPcaps() {
	if !s.isServiceMode || s.serviceConfig == nil {
		return
	}

	pcapsDir := filepath.Join(s.serviceConfig.DataDir, "pcaps")

	// Check if pcaps directory exists
	if _, err := os.Stat(pcapsDir); os.IsNotExist(err) {
		log.Printf("[Server] Pcaps directory does not exist: %s (skipping preloaded pcaps)", pcapsDir)
		return
	}

	// Ensure results directory exists with proper permissions
	resultsBaseDir := filepath.Join(s.serviceConfig.DataDir, "results")
	if err := os.MkdirAll(resultsBaseDir, 0777); err != nil {
		log.Printf("[Server] Failed to ensure results directory exists: %v", err)
		return
	}

	// Read all files in the pcaps directory
	files, err := os.ReadDir(pcapsDir)
	if err != nil {
		log.Printf("[Server] Failed to read pcaps directory with initial pcaps: %v", err)
		return
	}

	// First pass: collect all valid pcap files with their sizes
	type pcapFileInfo struct {
		filename string
		path     string
		size     int64
		modTime  time.Time
	}
	var pcapFiles []pcapFileInfo

	for _, file := range files {
		if file.IsDir() {
			continue
		}

		filename := file.Name()
		ext := strings.ToLower(filepath.Ext(filename))

		// Only process .pcap and .pcapng files
		if ext != ".pcap" && ext != ".pcapng" {
			continue
		}

		inputPath := filepath.Join(pcapsDir, filename)

		// Get file info
		fileInfo, err := file.Info()
		if err != nil {
			log.Printf("[Server] Failed to get file info for %s: %v", filename, err)
			continue
		}

		pcapFiles = append(pcapFiles, pcapFileInfo{
			filename: filename,
			path:     inputPath,
			size:     fileInfo.Size(),
			modTime:  fileInfo.ModTime(),
		})
	}

	// Sort pcap files by size (smallest first) for faster initial results in UI
	sort.Slice(pcapFiles, func(i, j int) bool {
		return pcapFiles[i].size < pcapFiles[j].size
	})

	log.Printf("[Server] Found %d preloaded pcap files, processing smallest first for faster UI results", len(pcapFiles))

	// Second pass: process files in order of size (smallest first)
	preloadedCount := 0
	for _, pcapFile := range pcapFiles {
		// Generate session ID for this preloaded pcap
		sessionID := generateSessionID()

		// Create results directory for this preloaded pcap
		resultsDir := filepath.Join(s.serviceConfig.DataDir, "results", sessionID)
		if err := os.MkdirAll(resultsDir, 0777); err != nil {
			log.Printf("[Server] Failed to create results directory for preloaded pcap %s: %v (check permissions on %s)",
				pcapFile.filename, err, filepath.Join(s.serviceConfig.DataDir, "results"))
			continue
		}

		// Create session info
		shareURL := fmt.Sprintf("/view/%s", sessionID)
		session := &SessionInfo{
			SessionID:       sessionID,
			IP:              "system", // Special IP for preloaded pcaps
			UploadTimestamp: pcapFile.modTime,
			InputFile:       pcapFile.path,
			InputFilename:   pcapFile.filename,
			InputFileSize:   pcapFile.size,
			OutputDir:       resultsDir,
			Status:          StatusQueued,
			ResultsReady:    false,
			ShareUrl:        shareURL,
			IsPreloaded:     true,
			BPFFilter:       "", // No BPF filter for preloaded pcaps
			IncludeDecoders: "",
			ExcludeDecoders: "",
		}

		// Add session to manager (preloaded sessions don't count against IP limits)
		s.sessionManager.AddSession(session)

		// Queue analysis job
		job := &AnalysisJob{
			SessionID:       sessionID,
			InputFile:       pcapFile.path,
			OutputDir:       resultsDir,
			EnableDPI:       s.dpiConfigured,
			BPFFilter:       "",
			IncludeDecoders: "",
			ExcludeDecoders: "",
		}

		s.jobQueue <- job
		preloadedCount++

		log.Printf("[Server] Queued preloaded pcap: %s (session: %s, size: %d bytes)",
			pcapFile.filename, sessionID, pcapFile.size)
	}

	if preloadedCount > 0 {
		log.Printf("[Server] Queued %d preloaded pcap file(s) for analysis", preloadedCount)
	} else {
		log.Printf("[Server] No preloaded pcap files found in %s", pcapsDir)
	}
}

// Start starts the HTTP server in a goroutine
func (s *Server) Start() error {
	mux := http.NewServeMux()

	// API endpoints
	mux.HandleFunc("/api/status", s.handleStatus)
	mux.HandleFunc("/api/stats", s.handleStats)
	mux.HandleFunc("/api/audit-stats", s.handleAuditStats)
	mux.HandleFunc("/api/files/input", s.handleInputFiles)
	mux.HandleFunc("/api/files/audit", s.handleAuditFiles)
	mux.HandleFunc("/api/files/logs", s.handleLogFiles)
	mux.HandleFunc("/api/audit/", s.handleAuditRecords)
	mux.HandleFunc("/api/logs/", s.handleLogContent)
	mux.HandleFunc("/api/error-log/", s.handleErrorLogContent)
	mux.HandleFunc("/api/set-directory", s.handleSetDirectory)
	mux.HandleFunc("/api/dbs", s.handleDatabaseInfo)
	mux.HandleFunc("/api/dbs/update", s.handleUpdateDatabases)
	mux.HandleFunc("/api/version", s.handleVersion)
	mux.HandleFunc("/api/dpi", s.handleDPIInfo)
	mux.HandleFunc("/api/dpi/preferences", s.handleDPIPreferences)
	mux.HandleFunc("/api/config", s.handleConfig)
	mux.HandleFunc("/api/config/debug", s.handleDebugToggle)
	mux.HandleFunc("/api/config/bpf", s.handleBPFConfig)
	mux.HandleFunc("/api/decoders/config", s.handleDecoderConfig)
	mux.HandleFunc("/api/decoders/config/list", s.handleListDecoderConfigs)
	mux.HandleFunc("/api/decoders/config/load", s.handleLoadDecoderConfig)
	mux.HandleFunc("/api/decoders/config/upload", s.handleUploadDecoderConfig)
	mux.HandleFunc("/api/decoders/config/delete", s.handleDeleteDecoderConfig)
	mux.HandleFunc("/api/decoders/config/save-as", s.handleSaveDecoderConfigAs)
	mux.HandleFunc("/api/decoders/", s.handleDecodersRouter) // Custom router for decoder endpoints
	mux.HandleFunc("/api/decoders", s.handleDecoders)
	mux.HandleFunc("/api/system-info", s.handleSystemInfo)
	mux.HandleFunc("/api/network-interfaces", s.handleNetworkInterfaces)
	mux.HandleFunc("/api/stop-capture", s.handleStopCapture)

	// Upload handler: service mode vs local mode
	if s.isServiceMode {
		mux.HandleFunc("/api/upload", s.handleUploadServiceMode)
	} else {
		mux.HandleFunc("/api/upload", s.handleUpload)
	}

	mux.HandleFunc("/api/chart/data", s.handleChartData)
	mux.HandleFunc("/api/chart/fields", s.handleChartFields)
	mux.HandleFunc("/api/visualize/protocol-hierarchy", s.handleProtocolHierarchy)
	mux.HandleFunc("/api/visualize/treemap", s.handleVisualizeTreemap)
	mux.HandleFunc("/api/visualize/bar3d", s.handleVisualizeBar3D)
	mux.HandleFunc("/api/visualize/graph", s.handleVisualizeGraph)
	mux.HandleFunc("/api/report-issue", s.handleReportIssue)

	// Service-specific endpoints (only registered in service mode)
	if s.isServiceMode {
		mux.HandleFunc("/api/quota", s.handleQuota)
		mux.HandleFunc("/api/try/sessions", s.handleListSessions)
		mux.HandleFunc("/api/try/session/", s.handleSessionSelect)
		mux.HandleFunc("/api/status/", s.handleStatus) // Session-specific status for polling
		mux.HandleFunc("/view/", s.handleViewSession)
		mux.HandleFunc("/health", s.handleHealth)
	}

	// Static files
	mux.Handle("/", s.handleStatic())

	s.httpServer = &http.Server{
		Addr:         s.addr,
		Handler:      s.corsMiddleware(mux),
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	// Start background workers for service mode
	if s.isServiceMode && s.jobQueue != nil {
		// Start job processor
		s.wg.Add(1)
		go s.processJobs()
		log.Println("[WebUI] Started job processor for service mode")

		// Start cleanup routine
		s.wg.Add(1)
		go s.cleanupRoutine()
		log.Println("[WebUI] Started cleanup routine for service mode")

		// Load and queue preloaded pcaps
		s.loadPreloadedPcaps()
	}

	go func() {
		log.Printf("Web UI server starting on http://%s\n", s.addr)
		if err := s.httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Printf("Web UI server error: %v\n", err)
		}
	}()

	return nil
}

// handleDecodersRouter routes decoder-related requests to the appropriate handler
func (s *Server) handleDecodersRouter(w http.ResponseWriter, r *http.Request) {
	log.Printf("[WebUI] Decoders router: path=%s", r.URL.Path)

	// Check if this is a request for decoder fields
	if strings.HasSuffix(r.URL.Path, "/fields") && r.URL.Path != "/api/decoders/config" {
		s.handleDecoderFields(w, r)
		return
	}

	// Check if this is a request for decoder config
	if r.URL.Path == "/api/decoders/config" {
		s.handleDecoderConfig(w, r)
		return
	}

	// Otherwise, it's a list decoders request
	s.handleDecoders(w, r)
}

// Stop gracefully stops the HTTP server
func (s *Server) Stop(ctx context.Context) error {
	log.Println("[WebUI] Shutting down server...")

	// Signal shutdown to background workers (service mode)
	if s.isServiceMode && s.shutdownChan != nil {
		close(s.shutdownChan)
	}

	// Stop HTTP server
	if s.httpServer != nil {
		if err := s.httpServer.Shutdown(ctx); err != nil {
			log.Printf("[WebUI] Error shutting down HTTP server: %v", err)
		}
	}

	// Wait for background workers to finish (service mode)
	if s.isServiceMode {
		// Wait with timeout
		done := make(chan struct{})
		go func() {
			s.wg.Wait()
			close(done)
		}()

		select {
		case <-done:
			log.Println("[WebUI] All background workers stopped")
		case <-ctx.Done():
			log.Println("[WebUI] Shutdown timeout, forcing exit")
		}
	}

	log.Println("[WebUI] Shutdown complete")
	return nil
}

// SetProcessingComplete marks capture processing as complete
func (s *Server) SetProcessingComplete() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.isProcessing = false
}

// IsProcessing returns whether capture is still processing
func (s *Server) IsProcessing() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.isProcessing
}

// UpdateOutputDir updates the output directory (useful for multi-file processing)
func (s *Server) UpdateOutputDir(outDir string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.outDir = outDir
	log.Printf("[WebUI] Output directory updated: outDir=%s (baseOutDir=%s remains unchanged)", outDir, s.baseOutDir)
}

// SetFileOutputDir stores the actual output directory for a specific input file
func (s *Server) SetFileOutputDir(inputFile, outputDir string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.fileOutputDirs[inputFile] = outputDir
	log.Printf("[WebUI] Output directory set for %s: %s", inputFile, outputDir)
}

// GetFileOutputDir retrieves the output directory for a specific input file
func (s *Server) GetFileOutputDir(inputFile string) (string, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	dir, exists := s.fileOutputDirs[inputFile]
	return dir, exists
}

// MarkFileCompleted marks a specific input file as completed
func (s *Server) MarkFileCompleted(inputFile string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.completedFiles[inputFile] = true
	log.Printf("[WebUI] File marked as completed: %s", inputFile)
}

// SetFileBPFFilter stores the BPF filter used for a specific input file
func (s *Server) SetFileBPFFilter(inputFile, bpfFilter string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.fileBPFFilters[inputFile] = bpfFilter
	if bpfFilter != "" {
		log.Printf("[WebUI] BPF filter set for %s: %s", inputFile, bpfFilter)
	}
}

// SetFileProcessingTime stores the processing time for a specific input file
func (s *Server) SetFileProcessingTime(inputFile string, durationSeconds float64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.fileProcessingTime[inputFile] = durationSeconds
	log.Printf("[WebUI] Processing time set for %s: %.2f seconds", inputFile, durationSeconds)
}

// GetFileProcessingTime retrieves the processing time for a specific input file
func (s *Server) GetFileProcessingTime(inputFile string) (float64, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	time, exists := s.fileProcessingTime[inputFile]
	return time, exists
}

// IsFileCompleted checks if a file has completed processing
func (s *Server) IsFileCompleted(inputFile string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.completedFiles[inputFile]
}

// GetCompletedFiles returns a copy of the completed files map
func (s *Server) GetCompletedFiles() map[string]bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	completed := make(map[string]bool)
	for k, v := range s.completedFiles {
		completed[k] = v
	}
	return completed
}

// UpdateProcessingStats updates the live processing statistics
func (s *Server) UpdateProcessingStats(stats ProcessingStats) {
	s.mu.Lock()
	defer s.mu.Unlock()
	stats.LastUpdate = time.Now().Unix()
	s.processingStats = stats
}

// SetFileError records an error for a specific file
func (s *Server) SetFileError(inputFile, errorMsg, errorLogPath string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.fileErrors[inputFile] = FileError{
		InputFile:    inputFile,
		Error:        errorMsg,
		ErrorLogPath: errorLogPath,
		Timestamp:    time.Now().Unix(),
	}
	log.Printf("[WebUI] Error recorded for file %s: %s", inputFile, errorMsg)
	if errorLogPath != "" {
		log.Printf("[WebUI] Error log saved to: %s", errorLogPath)
	}
}

// GetFileError returns the error for a specific file, if any
func (s *Server) GetFileError(inputFile string) (FileError, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	err, exists := s.fileErrors[inputFile]
	return err, exists
}

// shouldLogRequest returns true if the request should be logged
func shouldLogRequest(path string) bool {
	// Skip logging for static assets
	if strings.HasPrefix(path, "/_next/static/") ||
		strings.HasPrefix(path, "/_next/image/") ||
		strings.HasPrefix(path, "/static/") ||
		path == "/favicon.ico" ||
		strings.HasSuffix(path, ".js") ||
		strings.HasSuffix(path, ".css") ||
		strings.HasSuffix(path, ".map") ||
		strings.HasSuffix(path, ".png") ||
		strings.HasSuffix(path, ".jpg") ||
		strings.HasSuffix(path, ".jpeg") ||
		strings.HasSuffix(path, ".gif") ||
		strings.HasSuffix(path, ".svg") ||
		strings.HasSuffix(path, ".ico") ||
		strings.HasSuffix(path, ".woff") ||
		strings.HasSuffix(path, ".woff2") ||
		strings.HasSuffix(path, ".ttf") ||
		strings.HasSuffix(path, ".eot") {
		return false
	}
	return true
}

// corsMiddleware adds CORS headers
func (s *Server) corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Log incoming request (skip static assets)
		if shouldLogRequest(r.URL.Path) {
			log.Printf("[WebUI] %s %s", r.Method, r.URL.Path)
		}

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

// GetURL returns the full URL of the web UI
func (s *Server) GetURL() string {
	return fmt.Sprintf("http://%s", s.addr)
}

// SetDebugLogging sets the debug logging state
func (s *Server) SetDebugLogging(enabled bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.debugLogging = enabled
}

// GetDebugLogging returns the current debug logging state
func (s *Server) GetDebugLogging() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.debugLogging
}

// SetCollector sets the collector reference for runtime configuration changes
func (s *Server) SetCollector(collector CollectorInterface) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.collector = collector
}

// SetLiveMode sets whether the server is in live capture mode
func (s *Server) SetLiveMode(isLive bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.isLiveMode = isLive
}

// IsLiveMode returns whether the server is in live capture mode
func (s *Server) IsLiveMode() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.isLiveMode
}

// SetStopCapture sets the cancel function for stopping live capture
func (s *Server) SetStopCapture(cancel context.CancelFunc) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.stopCapture = cancel
}

// SetUploadCallback sets the callback function for file uploads
func (s *Server) SetUploadCallback(callback UploadCallbackFunc) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.uploadCallback = callback
}

// GetUserIP extracts the user's IP address from the request
func (s *Server) getUserIP(r *http.Request) string {
	// Check X-Forwarded-For header first (for proxies)
	if forwarded := r.Header.Get("X-Forwarded-For"); forwarded != "" {
		// Take the first IP if there are multiple
		ips := strings.Split(forwarded, ",")
		if len(ips) > 0 {
			return strings.TrimSpace(ips[0])
		}
	}

	// Check X-Real-IP header
	if realIP := r.Header.Get("X-Real-IP"); realIP != "" {
		return realIP
	}

	// Fall back to RemoteAddr
	ip := r.RemoteAddr
	// Remove port if present
	if idx := strings.LastIndex(ip, ":"); idx != -1 {
		ip = ip[:idx]
	}
	return ip
}

// GetDPIPreferences retrieves DPI preferences for a user
func (s *Server) GetDPIPreferences(userIP string) *UserDPIPreferences {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if prefs, exists := s.dpiPreferences[userIP]; exists {
		return prefs
	}
	return nil
}

// SetDPIPreferences sets DPI preferences for a user
func (s *Server) SetDPIPreferences(userIP string, prefs *UserDPIPreferences) {
	s.mu.Lock()
	defer s.mu.Unlock()

	prefs.LastUpdated = time.Now()
	s.dpiPreferences[userIP] = prefs

	log.Printf("[WebUI] Updated DPI preferences for %s: %v", userIP, prefs.EnabledModules)
}

// processJobs processes analysis jobs from the queue one at a time (service mode only)
func (s *Server) processJobs() {
	defer s.wg.Done()

	for {
		select {
		case job := <-s.jobQueue:
			s.runAnalysisInProcess(job)
		case <-s.shutdownChan:
			log.Println("[WebUI] Job processor shutting down")
			return
		}
	}
}

// runAnalysisInProcess executes a netcap capture analysis in-process
func (s *Server) runAnalysisInProcess(job *AnalysisJob) {
	log.Printf("[WebUI] Starting in-process analysis for session %s", job.SessionID)

	// Update status to processing
	if s.sessionManager != nil {
		s.sessionManager.UpdateSessionStatus(job.SessionID, StatusProcessing, "", "")
	}

	startTime := time.Now()

	// Build collector configuration
	c := collector.New(collector.Config{
		Workers:               runtime.NumCPU() * 2,
		PacketBufferSize:      defaults.PacketBuffer,
		WriteUnknownPackets:   false,
		Promisc:               true,
		SnapLen:               defaults.SnapLen,
		BaseLayer:             utils.GetBaseLayer("ethernet"),
		DecodeOptions:         utils.GetDecodeOptions("datagrams"),
		DPI:                   job.EnableDPI,
		DPIModules:            "",
		ReassembleConnections: true,
		FreeOSMem:             0,
		LogErrors:             false,
		NoPrompt:              true,
		HTTPShutdownEndpoint:  false,
		Timeout:               1 * time.Second,
		Labels:                "",
		Scatter:               true,
		ScatterDuration:       5 * time.Minute,
		DecoderConfig: &config.Config{
			Quiet:                          true,
			PrintProgress:                  false,
			Buffer:                         true,
			MemBufferSize:                  defaults.BufferSize,
			Compression:                    true,
			CSV:                            false,
			UnixSocket:                     false,
			Encode:                         false,
			Label:                          false,
			Null:                           false,
			Elastic:                        false,
			ElasticConfig:                  io.ElasticConfig{},
			BulkSizeGoPacket:               2000,
			BulkSizeCustom:                 1000,
			IncludeDecoders:                job.IncludeDecoders,
			ExcludeDecoders:                job.ExcludeDecoders,
			Out:                            job.OutputDir,
			Proto:                          true,
			JSON:                           false,
			Chan:                           false,
			Source:                         job.InputFile,
			IncludePayloads:                false,
			ExportMetrics:                  false,
			AddContext:                     true,
			FlushEvery:                     defaults.FlushEvery,
			DefragIPv4:                     defaults.DefragIPv4,
			Checksum:                       defaults.Checksum,
			NoOptCheck:                     defaults.NoOptCheck,
			IgnoreFSMerr:                   defaults.IgnoreFSMErr,
			AllowMissingInit:               defaults.AllowMissingInit,
			Debug:                          false,
			HexDump:                        false,
			WaitForConnections:             true,
			WriteIncomplete:                false,
			MemProfile:                     "",
			ConnFlushInterval:              defaults.ConnFlushInterval,
			ConnTimeOut:                    defaults.ConnTimeOut,
			FlowFlushInterval:              defaults.FlowFlushInterval,
			FlowTimeOut:                    defaults.FlowTimeOut,
			CloseInactiveTimeOut:           defaults.CloseInactiveTimeout,
			ClosePendingTimeOut:            defaults.ClosePendingTimeout,
			FileStorage:                    "",
			CalculateEntropy:               false,
			SaveConns:                      false,
			TCPDebug:                       false,
			UseRE2:                         false,
			BannerSize:                     256,
			StreamDecoderBufSize:           10,
			HarvesterBannerSize:            256,
			StopAfterHarvesterMatch:        false,
			StopAfterServiceProbeMatch:     false,
			StopAfterServiceCategoryMiss:   false,
			CustomRegex:                    "",
			StreamBufferSize:               10,
			NumStreamWorkers:               runtime.NumCPU(),
			MaxStreamBytes:                 10485760,
			MaxBufferedPagesPerConnection:  0,
			MaxBufferedPagesTotal:          0,
			IgnoreDecoderInitErrors:        false,
			DisableGenericVersionHarvester: false,
			RemoveClosedStreams:            false,
			CompressionBlockSize:           defaults.CompressionBlockSize,
			CompressionLevel:               defaults.CompressionLevel,
		},
		ResolverConfig: resolvers.Config{
			ReverseDNS:    false,
			LocalDNS:      false,
			MACDB:         true,
			Ja3DB:         true,
			ServiceDB:     true,
			GeolocationDB: false,
		},
	})

	c.Bpf = job.BPFFilter
	c.InputFile = job.InputFile

	// Create error log file for capturing errors
	errorLogPath := filepath.Join(job.OutputDir, "analysis_error.log")
	errorLogFile, err := os.Create(errorLogPath)
	if err != nil {
		log.Printf("[WebUI] Failed to create error log file: %v", err)
		errorLogPath = ""
	}

	// Redirect log output to the error log file during analysis
	var originalLogOutput stdio.Writer
	if errorLogFile != nil {
		originalLogOutput = log.Writer()
		// Create a multi-writer to write to both the original output and the error log
		multiWriter := stdio.MultiWriter(originalLogOutput, errorLogFile)
		log.SetOutput(multiWriter)
	}

	// Execute collection
	var analysisErr error
	defer func() {
		// Restore original log output
		if originalLogOutput != nil {
			log.SetOutput(originalLogOutput)
		}

		if errorLogFile != nil {
			errorLogFile.Sync() // Flush before closing
			errorLogFile.Close()
		}

		// Clean up error log if analysis succeeded
		if analysisErr == nil && errorLogPath != "" {
			os.Remove(errorLogPath)
		}
	}()

	// Check if input is pcap or pcapng
	isPcap, err := collector.IsPcap(job.InputFile)
	if err != nil {
		analysisErr = fmt.Errorf("failed to check file type: %w", err)
		log.Printf("[WebUI] Analysis failed for session %s: %v", job.SessionID, analysisErr)

		if errorLogFile != nil {
			fmt.Fprintf(errorLogFile, "\n========================================\n")
			fmt.Fprintf(errorLogFile, "=== File Type Check Error ===\n")
			fmt.Fprintf(errorLogFile, "========================================\n\n")
			fmt.Fprintf(errorLogFile, "Session ID: %s\n", job.SessionID)
			fmt.Fprintf(errorLogFile, "Input File: %s\n", job.InputFile)
			fmt.Fprintf(errorLogFile, "\n--- Error Details ---\n")
			fmt.Fprintf(errorLogFile, "%s\n", analysisErr.Error())
			fmt.Fprintf(errorLogFile, "\n========================================\n")
			errorLogFile.Sync()
		}

		if s.sessionManager != nil {
			s.sessionManager.UpdateSessionStatus(job.SessionID, StatusFailed, fmt.Sprintf("Analysis failed: %v", analysisErr), errorLogPath)
		}
		return
	}

	// Execute collection based on file type
	if job.BPFFilter != "" {
		analysisErr = c.CollectBPF(job.InputFile, job.BPFFilter)
	} else if isPcap {
		analysisErr = c.CollectPcap(job.InputFile)
	} else {
		analysisErr = c.CollectPcapNG(job.InputFile)
	}

	duration := time.Since(startTime)

	if analysisErr != nil {
		log.Printf("[WebUI] Analysis failed for session %s: %v (duration: %v)", job.SessionID, analysisErr, duration)

		if errorLogFile != nil {
			// Write detailed error information
			fmt.Fprintf(errorLogFile, "\n========================================\n")
			fmt.Fprintf(errorLogFile, "=== Analysis Error Summary ===\n")
			fmt.Fprintf(errorLogFile, "========================================\n\n")
			fmt.Fprintf(errorLogFile, "Session ID: %s\n", job.SessionID)
			fmt.Fprintf(errorLogFile, "Input File: %s\n", job.InputFile)
			fmt.Fprintf(errorLogFile, "Output Directory: %s\n", job.OutputDir)
			fmt.Fprintf(errorLogFile, "Duration: %v\n", duration)
			fmt.Fprintf(errorLogFile, "\n--- Error Details ---\n")
			fmt.Fprintf(errorLogFile, "%s\n", analysisErr.Error())
			fmt.Fprintf(errorLogFile, "\n========================================\n")

			// Ensure it's written to disk
			errorLogFile.Sync()
		}

		if s.sessionManager != nil {
			s.sessionManager.UpdateSessionStatus(job.SessionID, StatusFailed, fmt.Sprintf("Analysis failed: %v", analysisErr), errorLogPath)
		}
		return
	}

	log.Printf("[WebUI] Analysis completed for session %s (duration: %v)", job.SessionID, duration)

	if s.sessionManager != nil {
		s.sessionManager.UpdateSessionProcessingTime(job.SessionID, duration.Seconds())
		// TODO: Extract packet count from collector if available
		s.sessionManager.UpdateSessionStatus(job.SessionID, StatusCompleted, "", "")
	}
}

// cleanupRoutine periodically cleans up expired sessions (service mode only)
func (s *Server) cleanupRoutine() {
	defer s.wg.Done()

	if s.serviceConfig == nil {
		return
	}

	ticker := time.NewTicker(time.Duration(s.serviceConfig.CleanupInterval) * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if s.sessionManager != nil {
				expiredSessions := s.sessionManager.CleanupExpiredSessions()
				if len(expiredSessions) > 0 {
					log.Printf("[WebUI] Cleaned up %d expired sessions", len(expiredSessions))

					// Remove session files from disk
					for _, sessionID := range expiredSessions {
						sessionDir := filepath.Join(s.serviceConfig.DataDir, "results", sessionID)
						if err := os.RemoveAll(sessionDir); err != nil {
							log.Printf("[WebUI] Error removing session directory %s: %v", sessionDir, err)
						}

						// Also remove upload file if it exists
						uploadFile := filepath.Join(s.serviceConfig.DataDir, "uploads", sessionID+".pcap")
						if err := os.Remove(uploadFile); err != nil && !os.IsNotExist(err) {
							log.Printf("[WebUI] Error removing upload file %s: %v", uploadFile, err)
						}
					}
				}
			}
		case <-s.shutdownChan:
			log.Println("[WebUI] Cleanup routine shutting down")
			return
		}
	}
}
