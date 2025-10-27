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
	InputFile string `json:"inputFile"`
	Error     string `json:"error"`
	Timestamp int64  `json:"timestamp"`
}

// Server represents the web UI HTTP server
type Server struct {
	addr            string
	outDir          string
	baseOutDir      string // Original output directory for multi-file mode
	inputFiles      []string
	assetsPath      string
	httpServer      *http.Server
	mu              sync.RWMutex
	isProcessing    bool
	activeInputFile string               // Currently selected input file for viewing
	completedFiles  map[string]bool      // Tracks which files have completed processing
	processingStats ProcessingStats      // Live processing statistics
	fileErrors      map[string]FileError // Tracks errors for each file
	debugLogging    bool                 // Runtime debug logging state
	collector       CollectorInterface   // Reference to collector for runtime config changes
}

// CollectorInterface defines the methods we need from the Collector
type CollectorInterface interface {
	SetLogLevel(debug bool)
}

// NewServer creates a new web UI server
func NewServer(addr, outDir string, inputFiles []string, assetsPath string, debugLogging bool) *Server {
	return &Server{
		addr:           addr,
		outDir:         outDir,
		baseOutDir:     outDir,
		inputFiles:     inputFiles,
		assetsPath:     assetsPath,
		isProcessing:   true,
		completedFiles: make(map[string]bool),
		fileErrors:     make(map[string]FileError),
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
	mux.HandleFunc("/api/config", s.handleConfig)
	mux.HandleFunc("/api/config/debug", s.handleDebugToggle)
	mux.HandleFunc("/api/decoders", s.handleDecoders)
	mux.HandleFunc("/api/decoders/config", s.handleDecoderConfig)
	mux.HandleFunc("/api/system-info", s.handleSystemInfo)

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

// MarkFileCompleted marks a specific input file as completed
func (s *Server) MarkFileCompleted(inputFile string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.completedFiles[inputFile] = true
	log.Printf("[WebUI] File marked as completed: %s", inputFile)
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
func (s *Server) SetFileError(inputFile, errorMsg string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.fileErrors[inputFile] = FileError{
		InputFile: inputFile,
		Error:     errorMsg,
		Timestamp: time.Now().Unix(),
	}
	log.Printf("[WebUI] Error recorded for file %s: %s", inputFile, errorMsg)
}

// GetFileError returns the error for a specific file, if any
func (s *Server) GetFileError(inputFile string) (FileError, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	err, exists := s.fileErrors[inputFile]
	return err, exists
}

// corsMiddleware adds CORS headers to responses and logs requests
func (s *Server) corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Log incoming request
		log.Printf("[WebUI] %s %s", r.Method, r.URL.Path)

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
