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
	"log"
	"net/http"
	"strings"
	"sync"
	"time"
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
	isLiveMode         bool                          // Whether in live capture mode
	stopCapture        context.CancelFunc            // Function to stop live capture
	activeInputFile    string                        // Currently selected input file for viewing
	completedFiles     map[string]bool               // Tracks which files have completed processing
	processingStats    ProcessingStats               // Live processing statistics
	fileErrors         map[string]FileError          // Tracks errors for each file
	debugLogging       bool                          // Runtime debug logging state
	collector          CollectorInterface            // Reference to collector for runtime config changes
	uploadCallback     UploadCallbackFunc            // Function to call when files are uploaded
	fileBPFFilters     map[string]string             // Tracks BPF filter used for each file
	fileOutputDirs     map[string]string             // Tracks actual output directory for each file
	fileProcessingTime map[string]float64            // Tracks processing time in seconds for each file
	dpiPreferences     map[string]*UserDPIPreferences // DPI preferences per user IP
	reportedIssues     map[string]bool               // Tracks which file hashes have had issues reported
}

// UploadCallbackFunc is called when files are uploaded via the web UI
type UploadCallbackFunc func(filePath string) error

// CollectorInterface defines the methods we need from the Collector
type CollectorInterface interface {
	SetLogLevel(debug bool)
}

// NewServer creates a new web UI server
func NewServer(addr, outDir string, inputFiles []string, assetsPath string, debugLogging bool) *Server {
	return &Server{
		addr:               addr,
		outDir:             outDir,
		baseOutDir:         outDir,
		inputFiles:         inputFiles,
		assetsPath:         assetsPath,
		isProcessing:       true,
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
		debugLogging: debugLogging,
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
	mux.HandleFunc("/api/upload", s.handleUpload)
	mux.HandleFunc("/api/chart/data", s.handleChartData)
	mux.HandleFunc("/api/chart/fields", s.handleChartFields)
	mux.HandleFunc("/api/visualize/protocol-hierarchy", s.handleProtocolHierarchy)
	mux.HandleFunc("/api/visualize/treemap", s.handleVisualizeTreemap)
	mux.HandleFunc("/api/visualize/bar3d", s.handleVisualizeBar3D)
	mux.HandleFunc("/api/visualize/graph", s.handleVisualizeGraph)
	mux.HandleFunc("/api/report-issue", s.handleReportIssue)

	// Static files
	mux.Handle("/", s.handleStatic())

	s.httpServer = &http.Server{
		Addr:         s.addr,
		Handler:      s.corsMiddleware(mux),
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  120 * time.Second,
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
	if s.httpServer != nil {
		return s.httpServer.Shutdown(ctx)
	}
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
	log.Printf("[WebUI] Output directory updated to: %s", outDir)
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
