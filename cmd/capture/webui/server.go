/*
 * NETCAP - Traffic Analysis Framework
 * Copyright (c) Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
 * License: GNU General Public License v3.0
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

package webui

import (
	"compress/gzip"
	"context"
	"fmt"
	stdio "io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/dreadl0ck/netcap/collector"
	"github.com/dreadl0ck/netcap/decoder/config"
	"github.com/dreadl0ck/netcap/decoder/packet"
	"github.com/dreadl0ck/netcap/decoder/stream/credentials"
	"github.com/dreadl0ck/netcap/decoder/stream/exploit"
	httpstream "github.com/dreadl0ck/netcap/decoder/stream/http"
	"github.com/dreadl0ck/netcap/decoder/stream/network"
	"github.com/dreadl0ck/netcap/decoder/stream/service"
	"github.com/dreadl0ck/netcap/decoder/stream/software"
	"github.com/dreadl0ck/netcap/decoder/stream/tcp"
	"github.com/dreadl0ck/netcap/decoder/stream/udp"
	streamutils "github.com/dreadl0ck/netcap/decoder/stream/utils"
	"github.com/dreadl0ck/netcap/decoder/stream/vulnerability"
	"github.com/dreadl0ck/netcap/defaults"
	"github.com/dreadl0ck/netcap/dpi"
	"github.com/dreadl0ck/netcap/io"
	"github.com/dreadl0ck/netcap/resolvers"
	"github.com/dreadl0ck/netcap/rules"
	"github.com/dreadl0ck/netcap/types"
	"github.com/dreadl0ck/netcap/utils"
	"github.com/dustin/go-humanize"
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

	// Service mode specific fields
	QueueLength   int   `json:"queueLength"`   // Number of jobs waiting in queue
	JobsScheduled int64 `json:"jobsScheduled"` // Total jobs scheduled
	JobsProcessed int64 `json:"jobsProcessed"` // Total jobs completed
}

// FileError represents an error that occurred during file processing
type FileError struct {
	InputFile    string `json:"inputFile"`
	Error        string `json:"error"`
	Timestamp    int64  `json:"timestamp"`
	ErrorLogPath string `json:"errorLogPath,omitempty"` // Path to detailed error log file
}

// RuntimeConfig holds the actual runtime configuration values passed from the capture package
// This allows the webUI to display the actual values the application was started with
type RuntimeConfig struct {
	// Branding
	LogoSubText string // Custom label shown below NETCAP logo (overrides LOCAL/SERVICE)

	// Input/Output
	Compress bool
	Buffer   bool

	// Performance
	Workers      int
	PacketBuffer int
	MemBufSize   int

	// Network Capture
	Interface   string
	PromiscMode bool
	SnapLen     int

	// Decoders
	BaseLayer     string
	DecodeOptions string
	Payload       bool
	Context       bool

	// Database/Enrichment
	MacDB      bool
	ServiceDB  bool
	GeoDB      bool
	ReverseDNS bool
	LocalDNS   bool

	// TCP Reassembly
	ReassembleConnections bool
	FlushEvery            int
	Checksum              bool
	NoOptCheck            bool
	IgnoreFSMErr          bool
	AllowMissingInit      bool
	ClosePendingTimeout   time.Duration
	CloseInactiveTimeout  time.Duration

	// Output Format
	Proto bool
	JSON  bool
	CSV   bool

	// Elastic
	Elastic      bool
	ElasticAddrs string
	ElasticUser  string

	// Advanced
	IgnoreUnknown     bool
	FreeOSMemory      int
	ConnFlushInterval int
	ConnTimeout       time.Duration
	FlowFlushInterval int
	FlowTimeout       time.Duration

	// Stream processing
	Entropy    bool
	TCPDebug   bool
	SaveConns  bool
	DefragIPv4 bool
	HexDump    bool
	BannerSize int
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
	payloadCapture     bool                           // Runtime payload capture state (default false)
	dpiConfigured      bool                           // Whether DPI was configured at startup (via -dpi flag)
	runtimeConfig      *RuntimeConfig                 // Actual runtime configuration values from flags
	collector          CollectorInterface             // Reference to collector for runtime config changes
	uploadCallback     UploadCallbackFunc             // Function to call when files are uploaded
	fileBPFFilters     map[string]string              // Tracks BPF filter used for each file
	fileOutputDirs     map[string]string              // Tracks actual output directory for each file
	fileProcessingTime map[string]float64             // Tracks processing time in seconds for each file
	dpiPreferences     map[string]*UserDPIPreferences // DPI preferences per user IP
	reportedIssues     map[string]bool                // Tracks which file hashes have had issues reported
	fileIDToPath       map[string]string              // Maps file IDs to file paths (local mode)
	devMode            bool                           // Development mode: use current binary instead of "net"

	// Rules cache
	rulesConfig      interface{} // Cached rules config (uses rules.Config type to avoid circular import)
	rulesConfigMutex sync.RWMutex

	// Service mode fields (nil in local mode)
	isServiceMode     bool              // Flag to differentiate modes
	sessionManager    *SessionManager   // Session manager (nil in local mode)
	serviceConfig     *ServiceConfig    // Service configuration (nil in local mode)
	jobQueue          chan *AnalysisJob // Job queue (nil in local mode)
	shutdownChan      chan struct{}     // Shutdown channel for graceful shutdown
	shutdownOnce      sync.Once         // Ensure shutdown channel is only closed once
	wg                sync.WaitGroup    // Track background workers
	currentSession    string            // Currently active session for webUI viewing (service mode only)
	jobsScheduled     int64             // Total number of jobs scheduled (atomic counter)
	jobsProcessed     int64             // Total number of jobs processed (atomic counter)
	currentJobMutex   sync.RWMutex      // Mutex for currentProcessingJob
	currentProcessing *AnalysisJob      // Currently processing job (service mode only)
	currentCmd        *exec.Cmd         // Currently running net capture command (for cleanup)
	currentCmdMutex   sync.RWMutex      // Mutex for currentCmd
}

// UploadCallbackFunc is called when files are uploaded via the web UI
type UploadCallbackFunc func(filePath string) error

// CollectorInterface defines the methods we need from the Collector
type CollectorInterface interface {
	SetLogLevel(debug bool)
	ReloadRulesEngine() error
	// Live statistics methods
	GetCurrentPacketCount() int64
	GetTotalPacketCount() int64
	GetPacketsPerSecond() int64
	GetProfilesCount() int
	GetServicesCount() int
}

// NewServer creates a new web UI server
func NewServer(addr, outDir string, inputFiles []string, assetsPath string, debugLogging bool, dpiConfigured bool, isServiceMode bool, serviceConfig *ServiceConfig, runtimeConfig *RuntimeConfig, devMode bool) *Server {
	log.Printf("[WebUI] NewServer called with outDir=%s, numInputFiles=%d, devMode=%v", outDir, len(inputFiles), devMode)

	s := &Server{
		addr:               addr,
		outDir:             outDir,
		baseOutDir:         outDir,
		inputFiles:         inputFiles,
		assetsPath:         assetsPath,
		isProcessing:       true,
		dpiConfigured:      dpiConfigured,
		runtimeConfig:      runtimeConfig,
		completedFiles:     make(map[string]bool),
		fileErrors:         make(map[string]FileError),
		fileBPFFilters:     make(map[string]string),
		fileOutputDirs:     make(map[string]string),
		fileProcessingTime: make(map[string]float64),
		dpiPreferences:     make(map[string]*UserDPIPreferences),
		reportedIssues:     make(map[string]bool),
		fileIDToPath:       make(map[string]string),
		processingStats: ProcessingStats{
			TotalFiles: len(inputFiles),
		},
		debugLogging:  debugLogging,
		isServiceMode: isServiceMode,
		serviceConfig: serviceConfig,
		devMode:       devMode,
	}

	log.Printf("[WebUI] Server initialized: outDir=%s, baseOutDir=%s", s.outDir, s.baseOutDir)

	// Initialize service mode components if enabled
	if isServiceMode && serviceConfig != nil {
		s.sessionManager = NewSessionManager(
			serviceConfig.MaxAnalysisHour,
			serviceConfig.SessionExpiry,
			serviceConfig.MaxIssueReportsPerDay,
		)
		s.jobQueue = make(chan *AnalysisJob, 1000)
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

		// Restore sessions from disk (persist sessions across restarts)
		// pcapsDir := filepath.Join(serviceConfig.DataDir, "pcaps")
		// if err := s.sessionManager.RestoreSessionsFromDisk(resultsDir, pcapsDir, uploadsDir); err != nil {
		// 	log.Printf("[Server] Warning: Failed to restore sessions from disk: %v", err)
		// }
	} else {
		// Initialize job queue for local mode as well (for upload processing)
		s.jobQueue = make(chan *AnalysisJob, 100)
		s.shutdownChan = make(chan struct{})
		log.Printf("[WebUI] Local mode: job queue initialized for upload processing")
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
	var skippedCount int

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

		// Check if file size exceeds the configured maximum (only if enforce flag is set)
		fileSize := fileInfo.Size()
		if s.serviceConfig.EnforceMaxSizePreload && s.serviceConfig.MaxFileSize > 0 && fileSize > s.serviceConfig.MaxFileSize {
			log.Printf("[Server] Skipping preloaded pcap %s: file size %d bytes exceeds maximum allowed size of %d bytes (%.2f MB > %.2f MB)",
				filename, fileSize, s.serviceConfig.MaxFileSize,
				float64(fileSize)/(1024*1024), float64(s.serviceConfig.MaxFileSize)/(1024*1024))
			skippedCount++
			continue
		}

		pcapFiles = append(pcapFiles, pcapFileInfo{
			filename: filename,
			path:     inputPath,
			size:     fileSize,
			modTime:  fileInfo.ModTime(),
		})
	}

	// Sort pcap files by size (largest first) to select the N largest
	sort.Slice(pcapFiles, func(i, j int) bool {
		return pcapFiles[i].size > pcapFiles[j].size
	})

	// If PreloadLargestN is set and > 0, keep only the N largest files
	originalCount := len(pcapFiles)
	if s.serviceConfig.PreloadLargestN > 0 && len(pcapFiles) > s.serviceConfig.PreloadLargestN {
		pcapFiles = pcapFiles[:s.serviceConfig.PreloadLargestN]
		log.Printf("[Server] Selected %d largest files from %d total files", s.serviceConfig.PreloadLargestN, originalCount)
	}

	// Now reverse the order to process smallest first (for faster initial results in UI)
	sort.Slice(pcapFiles, func(i, j int) bool {
		return pcapFiles[i].size < pcapFiles[j].size
	})

	if skippedCount > 0 {
		if s.serviceConfig.EnforceMaxSizePreload {
			log.Printf("[Server] Found %d preloaded pcap files (skipped %d files exceeding max size of %.2f MB), processing smallest first for faster UI results",
				len(pcapFiles), skippedCount, float64(s.serviceConfig.MaxFileSize)/(1024*1024))
		} else {
			log.Printf("[Server] Found %d preloaded pcap files, processing smallest first for faster UI results", len(pcapFiles))
		}
	} else {
		log.Printf("[Server] Found %d preloaded pcap files, processing smallest first for faster UI results", len(pcapFiles))
	}

	// Load BPF filter from saved configuration (shared across all preloaded pcaps)
	bpfConfig := s.loadBPFConfig()

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
			BPFFilter:       bpfConfig.Filter, // Store BPF filter in session
			IncludeDecoders: "",
			ExcludeDecoders: "",
		}

		// Add session to manager (preloaded sessions don't count against IP limits)
		s.sessionManager.AddSession(session)

		// Save session metadata to disk
		if err := s.sessionManager.SaveSessionMetadata(sessionID); err != nil {
			log.Printf("[Server] Warning: Failed to save session metadata for %s: %v", sessionID, err)
		}

		// Queue analysis job
		job := &AnalysisJob{
			SessionID:       sessionID,
			InputFile:       pcapFile.path,
			OutputDir:       resultsDir,
			EnableDPI:       s.dpiConfigured,
			BPFFilter:       bpfConfig.Filter,
			IncludeDecoders: "",
			ExcludeDecoders: "",
		}

		atomic.AddInt64(&s.jobsScheduled, 1)
		s.jobQueue <- job
		preloadedCount++

		//log.Printf("[Server] Queued preloaded pcap: %s (session: %s, size: %d bytes)", pcapFile.filename, sessionID, pcapFile.size)
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
	mux.HandleFunc("/api/menu-counts", s.handleMenuCounts)
	mux.HandleFunc("/api/files/input", s.handleInputFiles)
	mux.HandleFunc("/api/files/input/download/", s.handleDownloadInputFile)
	mux.HandleFunc("/api/files/audit", s.handleAuditFiles)
	mux.HandleFunc("/api/files/audit/filtered", s.handleAuditFilesFiltered)
	mux.HandleFunc("/api/files/logs", s.handleLogFiles)
	mux.HandleFunc("/api/download/", s.handleDownloadAllAuditRecords)
	mux.HandleFunc("/api/audit/", s.handleAuditRecords)
	mux.HandleFunc("/api/logs/", s.handleLogContent)
	mux.HandleFunc("/api/error-log/", s.handleErrorLogContent)
	mux.HandleFunc("/api/set-directory", s.handleSetDirectory)
	mux.HandleFunc("/api/reanalyze", s.handleReanalyze)
	mux.HandleFunc("/api/dbs", s.handleDatabaseInfo)
	mux.HandleFunc("/api/dbs/update", s.handleUpdateDatabases)
	mux.HandleFunc("/api/version", s.handleVersion)
	mux.HandleFunc("/api/dpi", s.handleDPIInfo)
	mux.HandleFunc("/api/dpi/preferences", s.handleDPIPreferences)
	mux.HandleFunc("/api/config", s.handleConfig)
	mux.HandleFunc("/api/config/debug", s.handleDebugToggle)
	mux.HandleFunc("/api/config/payload", s.handlePayloadToggle)
	mux.HandleFunc("/api/config/bpf", s.handleBPFConfig)
	mux.HandleFunc("/api/rules", s.handleRules)
	mux.HandleFunc("/api/rules/execute", s.handleExecuteRule)
	mux.HandleFunc("/api/rules/execute-all", s.handleExecuteAllRules)
	mux.HandleFunc("/api/rules/", s.handleRule)
	mux.HandleFunc("/api/rule-sets", s.handleRuleSets)
	mux.HandleFunc("/api/rule-sets/", s.handleRuleSet)
	mux.HandleFunc("/api/injection-rules", s.handleInjectionRules)
	mux.HandleFunc("/api/injection-rules/", s.handleInjectionRule)
	mux.HandleFunc("/api/injection-events", s.handleInjectionEvents)
	mux.HandleFunc("/api/injection-events/clear", s.handleInjectionEventsManage)
	mux.HandleFunc("/api/injection-stats", s.handleInjectionStats)
	mux.HandleFunc("/api/injection-actions", s.handleInjectionActions)
	mux.HandleFunc("/api/alerts", s.handleAlerts)
	mux.HandleFunc("/api/alerts/grouped", s.handleGroupedAlerts)
	mux.HandleFunc("/api/alerts/stats", s.handleAlertStats)
	mux.HandleFunc("/api/alerts/clear", s.handleClearAlerts)
	mux.HandleFunc("/api/alerts/resolve", s.handleResolveAlert)
	mux.HandleFunc("/api/alerts/unresolve", s.handleUnresolveAlert)
	mux.HandleFunc("/api/extracted-files", s.handleExtractedFiles)
	mux.HandleFunc("/api/extracted-files/download-all", s.handleDownloadAllExtractedFiles)
	mux.HandleFunc("/api/extracted-files/download/", s.handleDownloadExtractedFile)
	mux.HandleFunc("/api/extracted-files/content/", s.handleExtractedFileContent)
	mux.HandleFunc("/api/error-logs", s.handleErrorLogFiles)
	mux.HandleFunc("/api/error-logs/aggregated", s.handleAggregatedErrors)
	mux.HandleFunc("/api/decoders/config", s.handleDecoderConfig)
	mux.HandleFunc("/api/decoders/config/list", s.handleListDecoderConfigs)
	mux.HandleFunc("/api/decoders/config/load", s.handleLoadDecoderConfig)
	mux.HandleFunc("/api/decoders/config/upload", s.handleUploadDecoderConfig)
	mux.HandleFunc("/api/decoders/config/delete", s.handleDeleteDecoderConfig)
	mux.HandleFunc("/api/decoders/config/save-as", s.handleSaveDecoderConfigAs)
	mux.HandleFunc("/api/decoders/", s.handleDecodersRouter) // Custom router for decoder endpoints
	mux.HandleFunc("/api/decoders", s.handleDecoders)
	mux.HandleFunc("/api/harvesters", s.handleHarvesters)
	mux.HandleFunc("/api/harvesters/config", s.handleHarvestersConfig)
	mux.HandleFunc("/api/harvesters/presets", s.handleHarvestersPresets)
	mux.HandleFunc("/api/harvesters/presets/save", s.handleSaveHarvesterPreset)
	mux.HandleFunc("/api/harvesters/presets/load", s.handleLoadHarvesterPreset)
	mux.HandleFunc("/api/harvesters/presets/delete", s.handleDeleteHarvesterPreset)
	mux.HandleFunc("/api/harvesters/presets/upload", s.handleUploadHarvesterPreset)
	mux.HandleFunc("/api/harvesters/presets/download", s.handleDownloadHarvesterPreset)
	mux.HandleFunc("/api/service-probes", s.handleServiceProbes)
	mux.HandleFunc("/api/service-probes/", s.handleServiceProbeRouter)
	mux.HandleFunc("/api/service-probes/test", s.handleTestServiceProbe)
	mux.HandleFunc("/api/service-probes/export", s.handleExportServiceProbes)
	mux.HandleFunc("/api/service-probes/import", s.handleImportServiceProbes)
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
	mux.HandleFunc("/api/visualize/sankey", s.handleVisualizeSankey)
	mux.HandleFunc("/api/visualize/treemap", s.handleVisualizeTreemap)
	mux.HandleFunc("/api/visualize/bar3d", s.handleVisualizeBar3D)
	mux.HandleFunc("/api/visualize/graph", s.handleVisualizeGraph)
	mux.HandleFunc("/api/visualize/geo", s.handleVisualizeGeo)
	mux.HandleFunc("/api/visualize/geo-all", s.handleVisualizeGeoAll)
	mux.HandleFunc("/api/visualize/scatter3d", s.handleVisualizeScatter3D)
	mux.HandleFunc("/api/visualize/hosts-graph", s.handleVisualizeHostsGraph)
	mux.HandleFunc("/api/hosts", s.handleHosts)
	mux.HandleFunc("/api/hosts/download-pcap", s.handleHostDownloadPCAP)
	mux.HandleFunc("/api/hosts/top-talkers", s.handleHostsTopTalkers)
	mux.HandleFunc("/api/hosts/traffic-distribution", s.handleHostsTrafficDistribution)
	mux.HandleFunc("/api/hosts/applications", s.handleHostsApplications)
	mux.HandleFunc("/api/hosts/protocols", s.handleHostsProtocols)
	mux.HandleFunc("/api/devices", s.handleDevices)
	mux.HandleFunc("/api/devices/mac-vendors", s.handleDevicesMACVendors)
	mux.HandleFunc("/api/devices/hardware", s.handleDevicesHardware)
	mux.HandleFunc("/api/devices/operating-systems", s.handleDevicesOperatingSystems)
	mux.HandleFunc("/api/devices/applications", s.handleDevicesApplications)
	mux.HandleFunc("/api/devices/traffic-distribution", s.handleDevicesTrafficDistribution)
	mux.HandleFunc("/api/connections", s.handleConnections)
	mux.HandleFunc("/api/connections/conversation", s.handleConnectionConversation)
	mux.HandleFunc("/api/connections/network-conversation", s.handleNetworkConversation)
	mux.HandleFunc("/api/connections/download-pcap", s.handleConnectionDownloadPCAP)
	mux.HandleFunc("/api/connections/top-by-traffic", s.handleConnectionsTopByTraffic)
	mux.HandleFunc("/api/connections/protocols", s.handleConnectionsProtocols)
	mux.HandleFunc("/api/connections/applications", s.handleConnectionsApplications)
	mux.HandleFunc("/api/connections/duration", s.handleConnectionsDuration)
	mux.HandleFunc("/api/http", s.handleHTTP)
	mux.HandleFunc("/api/http/download-pcap", s.handleHTTPDownloadPCAP)
	mux.HandleFunc("/api/http/top-hosts", s.handleHTTPTopHosts)
	mux.HandleFunc("/api/http/status-codes", s.handleHTTPStatusCodes)
	mux.HandleFunc("/api/http/methods", s.handleHTTPMethods)
	mux.HandleFunc("/api/http/content-types", s.handleHTTPContentTypes)
	mux.HandleFunc("/api/certificates", s.handleCertificates)
	mux.HandleFunc("/api/certificates/download-pcap", s.handleCertificateDownloadPCAP)
	mux.HandleFunc("/api/certificates/top-issuers", s.handleCertificatesTopIssuers)
	mux.HandleFunc("/api/certificates/status-distribution", s.handleCertificatesStatusDistribution)
	mux.HandleFunc("/api/certificates/key-algorithms", s.handleCertificatesKeyAlgorithms)
	mux.HandleFunc("/api/certificates/expiration-timeline", s.handleCertificatesExpirationTimeline)
	mux.HandleFunc("/api/credentials", s.handleCredentials)
	mux.HandleFunc("/api/credentials/by-service", s.handleCredentialsByService)
	mux.HandleFunc("/api/credentials/timeline", s.handleCredentialsTimeline)
	mux.HandleFunc("/api/credentials/usernames", s.handleCredentialsUsernames)
	mux.HandleFunc("/api/credentials/flows", s.handleCredentialsFlows)
	mux.HandleFunc("/api/services", s.handleServices)
	mux.HandleFunc("/api/services/top-by-traffic", s.handleServicesTopByTraffic)
	mux.HandleFunc("/api/services/protocols", s.handleServicesProtocols)
	mux.HandleFunc("/api/services/top-ports", s.handleServicesTopPorts)
	mux.HandleFunc("/api/services/top-products", s.handleServicesTopProducts)
	mux.HandleFunc("/api/domains", s.handleDomains)
	mux.HandleFunc("/api/domains/top-by-queries", s.handleDomainsTopByQueries)
	mux.HandleFunc("/api/domains/tlds", s.handleDomainsTLDs)
	mux.HandleFunc("/api/domains/record-types", s.handleDomainsRecordTypes)
	mux.HandleFunc("/api/domains/subdomain-distribution", s.handleDomainsSubdomainDistribution)
	mux.HandleFunc("/api/fingerprints", s.handleFingerprints)
	mux.HandleFunc("/api/fingerprints/type-distribution", s.handleFingerprintsTypeDistribution)
	mux.HandleFunc("/api/fingerprints/top-ja4", s.handleFingerprintsTopJA4)
	mux.HandleFunc("/api/fingerprints/top-ja4ssh", s.handleFingerprintsTopJA4SSH)
	mux.HandleFunc("/api/fingerprints/hosts-per-fingerprint", s.handleFingerprintsHostsPerFingerprint)
	mux.HandleFunc("/api/software", s.handleSoftware)
	mux.HandleFunc("/api/software/top-products", s.handleSoftwareTopProducts)
	mux.HandleFunc("/api/software/vendors", s.handleSoftwareVendors)
	mux.HandleFunc("/api/software/operating-systems", s.handleSoftwareOperatingSystems)
	mux.HandleFunc("/api/software/versions", s.handleSoftwareVersions)
	mux.HandleFunc("/api/vulnerabilities", s.handleVulnerabilities)
	mux.HandleFunc("/api/vulnerabilities/severity", s.handleVulnerabilitiesSeverity)
	mux.HandleFunc("/api/vulnerabilities/top-vulnerable-software", s.handleVulnerabilitiesTopVulnerableSoftware)
	mux.HandleFunc("/api/vulnerabilities/access-vectors", s.handleVulnerabilitiesAccessVectors)
	mux.HandleFunc("/api/vulnerabilities/exploit-types", s.handleVulnerabilitiesExploitTypes)
	mux.HandleFunc("/api/vulnerabilities/top-affected-hosts", s.handleVulnerabilitiesTopAffectedHosts)
	mux.HandleFunc("/api/vulnerabilities/exploit-file", s.handleExploitFileContent)
	mux.HandleFunc("/api/report-issue", s.handleReportIssue)
	mux.HandleFunc("/api/progress/", s.handleProgress)

	// Service-specific endpoints (only registered in service mode)
	if s.isServiceMode {
		mux.HandleFunc("/api/quota", s.handleQuota)
		mux.HandleFunc("/api/try/sessions", s.handleListSessions)
		mux.HandleFunc("/api/try/session/", s.handleSessionSelect)
		mux.HandleFunc("/api/status/", s.handleStatus) // Session-specific status for polling
		mux.HandleFunc("/view/", s.handleViewSession)
		mux.HandleFunc("/health", s.handleHealth)
	}

	// Static files - echarts assets and frontend
	// Note: /static/ is served from Next.js public/ directory automatically
	mux.Handle("/", s.handleStatic())

	s.httpServer = &http.Server{
		Addr:         s.addr,
		Handler:      gzipMiddleware(s.corsMiddleware(mux)),
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	// Start background workers for service mode and local mode
	if s.jobQueue != nil {
		// Start job processor
		s.wg.Add(1)
		go s.processJobs()
		if s.isServiceMode {
			log.Println("[WebUI] Started job processor for service mode")
		} else {
			log.Println("[WebUI] Started job processor for local mode")
		}

		// Start cleanup routine (service mode only)
		if s.isServiceMode {
			s.wg.Add(1)
			go s.cleanupRoutine()
			log.Println("[WebUI] Started cleanup routine for service mode")
		}
	}

	// Start HTTP server first
	go func() {
		log.Printf("Web UI server starting on http://%s\n", s.addr)
		if err := s.httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Printf("Web UI server error: %v\n", err)
		}
	}()

	// Load and queue preloaded pcaps after server starts (in goroutine to avoid blocking)
	// This can take time with many files and the channel may block if queue is full
	if s.isServiceMode && s.jobQueue != nil {
		go s.loadPreloadedPcaps()
	}

	return nil
}

// handleDecodersRouter routes decoder-related requests to the appropriate handler
func (s *Server) handleDecodersRouter(w http.ResponseWriter, r *http.Request) {
	log.Printf("[WebUI] Decoders router: path=%s", r.URL.Path)

	// Check if this is a request for all decoder fields
	if r.URL.Path == "/api/decoders/fields" {
		s.handleAllDecoderFields(w, r)
		return
	}

	// Check if this is a request for specific decoder fields
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

	// Kill any running net capture process (both service and local mode)
	s.currentCmdMutex.Lock()
	if s.currentCmd != nil && s.currentCmd.Process != nil {
		log.Printf("[WebUI] Killing running net capture process (PID: %d)", s.currentCmd.Process.Pid)
		if err := s.currentCmd.Process.Kill(); err != nil {
			log.Printf("[WebUI] Error killing process: %v", err)
		} else {
			log.Println("[WebUI] Net capture process killed successfully")
		}
		s.currentCmd = nil
	}
	s.currentCmdMutex.Unlock()

	// Signal shutdown to background workers (only close once)
	if s.shutdownChan != nil {
		s.shutdownOnce.Do(func() {
			close(s.shutdownChan)
		})
	}

	// Stop HTTP server
	if s.httpServer != nil {
		if err := s.httpServer.Shutdown(ctx); err != nil {
			log.Printf("[WebUI] Error shutting down HTTP server: %v", err)
		}
	}

	// Wait for background workers to finish
	if s.isServiceMode || s.jobQueue != nil {
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

// AddInputFile adds a new input file to be processed (for "Open With" functionality on macOS)
// This creates a session and queues a job for the file
func (s *Server) AddInputFile(filePath string) {
	s.mu.Lock()
	// Check if file already exists in the list
	for _, f := range s.inputFiles {
		if f == filePath {
			log.Printf("[WebUI] Input file already exists: %s", filePath)
			s.mu.Unlock()
			return
		}
	}
	s.inputFiles = append(s.inputFiles, filePath)
	s.mu.Unlock()

	log.Printf("[WebUI] Added input file: %s", filePath)

	// Get file info
	fileInfo, err := os.Stat(filePath)
	if err != nil {
		log.Printf("[WebUI] Failed to stat input file %s: %v", filePath, err)
		return
	}

	// Check if job queue is available
	if s.jobQueue == nil {
		log.Printf("[WebUI] Job queue not available, cannot process file: %s", filePath)
		return
	}

	// Generate session ID for this file
	sessionID := generateSessionID()

	// Create results directory
	var resultsDir string
	if s.isServiceMode && s.serviceConfig != nil {
		resultsDir = filepath.Join(s.serviceConfig.DataDir, "results", sessionID)
	} else {
		resultsDir = filepath.Join(s.baseOutDir, sessionID)
	}

	if err := os.MkdirAll(resultsDir, 0755); err != nil {
		log.Printf("[WebUI] Failed to create results directory for %s: %v", filePath, err)
		return
	}

	// Load BPF filter from saved configuration
	bpfConfig := s.loadBPFConfig()

	// Create session info (only needed if session manager is available)
	if s.sessionManager != nil {
		filename := filepath.Base(filePath)
		shareURL := fmt.Sprintf("/view/%s", sessionID)
		session := &SessionInfo{
			SessionID:       sessionID,
			IP:              "desktop", // Special IP for desktop app opened files
			UploadTimestamp: time.Now(),
			InputFile:       filePath,
			InputFilename:   filename,
			InputFileSize:   fileInfo.Size(),
			OutputDir:       resultsDir,
			Status:          StatusQueued,
			ResultsReady:    false,
			ShareUrl:        shareURL,
			IsPreloaded:     false,
			BPFFilter:       bpfConfig.Filter,
			IncludeDecoders: "",
			ExcludeDecoders: "",
		}

		// Add session to manager
		s.sessionManager.AddSession(session)

		// Save session metadata to disk
		if err := s.sessionManager.SaveSessionMetadata(sessionID); err != nil {
			log.Printf("[WebUI] Warning: Failed to save session metadata for %s: %v", sessionID, err)
		}
	}

	// Queue analysis job
	job := &AnalysisJob{
		SessionID:       sessionID,
		InputFile:       filePath,
		OutputDir:       resultsDir,
		EnableDPI:       s.dpiConfigured,
		BPFFilter:       bpfConfig.Filter,
		IncludeDecoders: "",
		ExcludeDecoders: "",
	}

	atomic.AddInt64(&s.jobsScheduled, 1)
	s.jobQueue <- job

	log.Printf("[WebUI] Queued job for input file: %s (session: %s)", filePath, sessionID)
}

// GetOutputDir returns the current output directory
func (s *Server) GetOutputDir() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.outDir
}

// SetFileOutputDir stores the actual output directory for a specific input file
// and updates the active output directory to point to this location
func (s *Server) SetFileOutputDir(inputFile, outputDir string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.fileOutputDirs[inputFile] = outputDir
	// Also update the active output directory so API calls use the correct path immediately
	s.outDir = outputDir
	log.Printf("[WebUI] Output directory set for %s: %s (active outDir updated)", inputFile, outputDir)
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

	// TODO disable logging these requests for now
	return false

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
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// gzipResponseWriter wraps http.ResponseWriter to compress responses with gzip
type gzipResponseWriter struct {
	stdio.Writer
	http.ResponseWriter
	wroteHeader bool
}

func (w *gzipResponseWriter) WriteHeader(status int) {
	w.wroteHeader = true
	w.ResponseWriter.WriteHeader(status)
}

func (w *gzipResponseWriter) Write(b []byte) (int, error) {
	if !w.wroteHeader {
		w.WriteHeader(http.StatusOK)
	}
	return w.Writer.Write(b)
}

// gzipMiddleware compresses HTTP responses with gzip when supported by client
func gzipMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check if client accepts gzip encoding
		if !strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") {
			next.ServeHTTP(w, r)
			return
		}

		// Skip compression for SSE streams
		if strings.Contains(r.Header.Get("Accept"), "text/event-stream") {
			next.ServeHTTP(w, r)
			return
		}

		// Skip compression for file download endpoints
		// These handle Content-Length and streaming themselves
		path := r.URL.Path
		if strings.HasPrefix(path, "/api/files/input/download/") ||
			strings.HasPrefix(path, "/api/extracted-files/download") ||
			strings.HasPrefix(path, "/api/connections/download-pcap") ||
			strings.HasPrefix(path, "/api/hosts/download-pcap") ||
			strings.HasPrefix(path, "/api/chart/data") {
			next.ServeHTTP(w, r)
			return
		}

		// Don't compress certain file types that are already compressed
		if strings.HasSuffix(path, ".png") ||
			strings.HasSuffix(path, ".jpg") ||
			strings.HasSuffix(path, ".jpeg") ||
			strings.HasSuffix(path, ".gif") ||
			strings.HasSuffix(path, ".webp") ||
			strings.HasSuffix(path, ".woff") ||
			strings.HasSuffix(path, ".woff2") ||
			strings.HasSuffix(path, ".gz") ||
			strings.HasSuffix(path, ".zip") ||
			strings.HasSuffix(path, ".br") ||
			strings.HasSuffix(path, ".pcap") ||
			strings.HasSuffix(path, ".pcapng") {
			next.ServeHTTP(w, r)
			return
		}

		// Set headers for gzip compression
		w.Header().Set("Content-Encoding", "gzip")
		w.Header().Add("Vary", "Accept-Encoding")

		// Create gzip writer
		gz := gzip.NewWriter(w)
		defer gz.Close()

		// Wrap response writer
		gzw := &gzipResponseWriter{
			Writer:         gz,
			ResponseWriter: w,
		}

		next.ServeHTTP(gzw, r)
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

// SetPayloadCapture sets the payload capture state for future analysis
func (s *Server) SetPayloadCapture(enabled bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.payloadCapture = enabled
}

// GetPayloadCapture returns the current payload capture state
func (s *Server) GetPayloadCapture() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.payloadCapture
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
			// Set current processing job
			s.currentJobMutex.Lock()
			s.currentProcessing = job
			s.currentJobMutex.Unlock()

			// Increment processed counter and calculate position
			currentPos := atomic.AddInt64(&s.jobsProcessed, 1)
			totalScheduled := atomic.LoadInt64(&s.jobsScheduled)

			log.Printf("[WebUI] Job received from queue: processing job %d/%d, session=%s, file=%s",
				currentPos, totalScheduled, job.SessionID, job.InputFile)

			// Wrap job processing with panic recovery to prevent crashes from killing the service
			func() {
				defer func() {
					if r := recover(); r != nil {
						log.Printf("[WebUI] PANIC recovered in job processor for session %s: %v", job.SessionID, r)
						log.Printf("[WebUI] Stack trace:\n%s", debug.Stack())

						// Mark session as failed
						if s.sessionManager != nil {
							errorMsg := fmt.Sprintf("Analysis crashed: %v", r)
							s.sessionManager.UpdateSessionStatus(job.SessionID, StatusFailed, errorMsg, "")
						}
					}
				}()

				s.runAnalysis(job)
			}()

			// Clear current processing job
			s.currentJobMutex.Lock()
			s.currentProcessing = nil
			s.currentJobMutex.Unlock()

			log.Printf("[WebUI] Job processing completed: job %d/%d, session=%s", currentPos, totalScheduled, job.SessionID)
		case <-s.shutdownChan:
			log.Println("[WebUI] Job processor shutting down")
			return
		}
	}
}

// getExcludeDecoders returns the list of decoders to exclude for this job
// When DPI is disabled, automatically excludes DPI-dependent decoders to prevent crashes
func getExcludeDecoders(job *AnalysisJob) string {
	excludeDecoders := job.ExcludeDecoders

	// When DPI is disabled, exclude DPI-dependent decoders
	// These decoders can cause nil pointer crashes if DPI is not properly initialized
	if !job.EnableDPI {
		dpiDependentDecoders := "DeviceProfile,IPProfile,Connection"
		if excludeDecoders != "" {
			excludeDecoders += "," + dpiDependentDecoders
		} else {
			excludeDecoders = dpiDependentDecoders
		}
	}

	return excludeDecoders
}

// runAnalysis executes a netcap capture analysis
func (s *Server) runAnalysis(job *AnalysisJob) {
	if s.isServiceMode {
		log.Printf("[Service] Starting analysis for session %s", job.SessionID)
	} else {
		log.Printf("[WebUI] Starting analysis for uploaded file: %s", job.InputFile)
	}

	// Update status to processing (service mode only)
	if s.sessionManager != nil {
		s.sessionManager.UpdateSessionStatus(job.SessionID, StatusProcessing, "", "")
	}

	// Enable file extraction - create files directory within the output directory
	// Note: FileStorage must be a RELATIVE path since it gets joined with Out directory
	fileStorageRelPath := "files"
	filesDir := filepath.Join(job.OutputDir, fileStorageRelPath)
	if err := os.MkdirAll(filesDir, 0755); err != nil {
		log.Printf("[Service] Warning: Failed to create files directory: %v", err)
		fileStorageRelPath = "" // Disable file storage if we can't create the directory
	} else {
		log.Printf("[Service] File extraction enabled for session %s: %s", job.SessionID, filesDir)
	}

	// Build netcap capture command
	args := []string{
		"capture",
		"-read", job.InputFile,
		"-out", job.OutputDir,
		"-quiet",
		"-y",        // Force overwrite without prompting (required for non-interactive mode)
		"-http", "", // Disable web UI server
	}

	// Add critical stream processing flags to ensure SSH records are created
	args = append(args,
		"-reassemble-connections=true", // REQUIRED for SSH and all stream-based decoders
		"-writeincomplete=true",        // Write incomplete streams immediately
		"-ignorefsmerr=true",           // Ignore FSM errors for better reliability
		"-allowmissinginit=true",       // Allow streams without handshake
		"-conns",                       // Save raw conversation data to tcp/udp folders (corresponds to SaveConns config)
	)

	// Add file extraction flag if directory was created successfully (use relative path!)
	if fileStorageRelPath != "" {
		args = append(args, "-fileStorage", fileStorageRelPath)
	}

	if job.EnableDPI {
		args = append(args, "-dpi")
	}

	// Add payload capture flag if enabled
	if s.GetPayloadCapture() {
		args = append(args, "-payload")
		log.Printf("[Service] Payload capture enabled for session %s", job.SessionID)
	}

	// Apply BPF filter if set
	if job.BPFFilter != "" {
		args = append(args, "-bpf", job.BPFFilter)
		log.Printf("[Service] Applying BPF filter for session %s: %s", job.SessionID, job.BPFFilter)
	}

	// Apply decoder config if set
	if job.IncludeDecoders != "" {
		args = append(args, "-include", job.IncludeDecoders)
		log.Printf("[Service] Including decoders for session %s: %s", job.SessionID, job.IncludeDecoders)
	}

	// Build exclude decoders list
	excludeDecoders := job.ExcludeDecoders

	// When DPI is disabled or to prevent crashes, exclude DPI-dependent decoders
	// These decoders can cause nil pointer crashes if DPI is not properly initialized
	if !job.EnableDPI {
		dpiDependentDecoders := "DeviceProfile,IPProfile,Connection"
		if excludeDecoders != "" {
			excludeDecoders += "," + dpiDependentDecoders
		} else {
			excludeDecoders = dpiDependentDecoders
		}
		log.Printf("[Service] DPI disabled - excluding DPI-dependent decoders for session %s", job.SessionID)
	}

	if excludeDecoders != "" {
		args = append(args, "-exclude", excludeDecoders)
		log.Printf("[Service] Excluding decoders for session %s: %s", job.SessionID, excludeDecoders)
	}

	// Determine executable for job execution
	// In dev mode, use the current binary; otherwise use the system "net" binary
	var executable string
	if s.devMode {
		// Dev mode: use the current executable (e.g., ./tmp/main when running with air)
		execPath, err := os.Executable()
		if err != nil {
			log.Printf("[Service] Failed to get current executable path: %v, falling back to 'net'", err)
			executable = "net"
		} else {
			executable = execPath
			log.Printf("[Service] Dev mode: using current executable: %s", executable)
		}
	} else {
		// Production mode: use the system "net" binary
		executable = "net"
	}

	// Create error log file for capturing stdout/stderr
	errorLogPath := filepath.Join(job.OutputDir, "analysis_error.log")
	errorLogFile, err := os.Create(errorLogPath)
	if err != nil {
		log.Printf("[Service] Failed to create error log file: %v", err)
		// Continue without error log file
		errorLogPath = ""
	}

	// Log the exact command being executed for debugging
	log.Printf("[Service] Executing command: %s %s", executable, strings.Join(args, " "))

	// Run the capture command
	cmd := exec.Command(executable, args...)

	// If we have an error log file, capture output there; otherwise use standard output
	if errorLogFile != nil {
		cmd.Stdout = errorLogFile
		cmd.Stderr = errorLogFile
		defer errorLogFile.Close()
	} else {
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
	}

	// Store the command for potential cleanup during shutdown
	s.currentCmdMutex.Lock()
	s.currentCmd = cmd
	s.currentCmdMutex.Unlock()

	// Ensure command reference is cleared when done
	defer func() {
		s.currentCmdMutex.Lock()
		s.currentCmd = nil
		s.currentCmdMutex.Unlock()
	}()

	// Start the command
	startTime := time.Now()
	err = cmd.Start()
	if err != nil {
		log.Printf("[Service] Failed to start command for session %s: %v", job.SessionID, err)
		if s.sessionManager != nil {
			s.sessionManager.UpdateSessionStatus(job.SessionID, StatusFailed, fmt.Sprintf("Failed to start analysis: %v", err), "")
		} else {
			s.SetFileError(job.InputFile, fmt.Sprintf("Failed to start analysis: %v", err), "")
		}
		return
	}

	// Wait for command to complete
	err = cmd.Wait()
	duration := time.Since(startTime)

	if err != nil {
		if s.isServiceMode {
			log.Printf("[Service] Analysis failed for session %s: %v (duration: %v)", job.SessionID, err, duration)
		} else {
			log.Printf("[WebUI] Analysis failed for uploaded file %s: %v (duration: %v)", job.InputFile, err, duration)
		}

		// Write additional error context to log file
		if errorLogFile != nil {
			fmt.Fprintf(errorLogFile, "\n\n=== Analysis Error Summary ===\n")
			if s.isServiceMode {
				fmt.Fprintf(errorLogFile, "Session ID: %s\n", job.SessionID)
			}
			fmt.Fprintf(errorLogFile, "Input File: %s\n", job.InputFile)
			fmt.Fprintf(errorLogFile, "Output Directory: %s\n", job.OutputDir)
			fmt.Fprintf(errorLogFile, "Duration: %v\n", duration)
			fmt.Fprintf(errorLogFile, "Error: %v\n", err)
			fmt.Fprintf(errorLogFile, "Command: %s %s\n", executable, strings.Join(args, " "))
			errorLogFile.Close()
		}

		if s.sessionManager != nil {
			log.Printf("[Service] Setting error log path for session %s: %s", job.SessionID, errorLogPath)
			s.sessionManager.UpdateSessionStatus(job.SessionID, StatusFailed, fmt.Sprintf("Analysis failed: %v", err), errorLogPath)
		} else {
			// Local mode: track error in fileErrors map
			s.SetFileError(job.InputFile, fmt.Sprintf("Analysis failed: %v", err), errorLogPath)
		}
		return
	}

	// Close and remove error log file if analysis succeeded (it would be empty or just normal output)
	if errorLogFile != nil {
		errorLogFile.Close()
		os.Remove(errorLogPath)
	}

	if s.isServiceMode {
		log.Printf("[Service] Analysis completed for session %s (duration: %v)", job.SessionID, duration)
	} else {
		log.Printf("[WebUI] Analysis completed for uploaded file %s (duration: %v)", job.InputFile, duration)
	}

	// List audit record files created
	files, err := os.ReadDir(job.OutputDir)
	if err == nil {
		log.Printf("[Service] Files created in %s:", job.OutputDir)
		for _, file := range files {
			if strings.HasSuffix(file.Name(), ".ncap") || strings.HasSuffix(file.Name(), ".ncap.gz") {
				info, _ := file.Info()
				log.Printf("[Service]   - %s (size: %d bytes)", file.Name(), info.Size())
			}
		}
	}

	// Count and log extracted files
	fileCount := s.countExtractedFiles(filesDir)
	if fileCount > 0 {
		if s.isServiceMode {
			log.Printf("[Service] Extracted %d file(s) for session %s", fileCount, job.SessionID)
		} else {
			log.Printf("[WebUI] Extracted %d file(s) from %s", fileCount, job.InputFile)
		}
	}

	if s.sessionManager != nil {
		s.sessionManager.UpdateSessionStatus(job.SessionID, StatusCompleted, "", "")
		// Store the processing time
		s.sessionManager.UpdateSessionProcessingTime(job.SessionID, duration.Seconds())

		// Auto-select this file if no active file is currently set (service mode only)
		// This makes the first completed capture immediately available for viewing
		s.mu.Lock()
		if s.activeInputFile == "" {
			// Get session info to set as active
			if session, ok := s.sessionManager.GetSession(job.SessionID); ok {
				s.currentSession = job.SessionID
				s.outDir = job.OutputDir
				s.activeInputFile = session.InputFile
				log.Printf("[Service] Auto-selected first completed capture: session=%s, file=%s",
					job.SessionID, session.InputFilename)
			}
		}
		s.mu.Unlock()
	} else {
		// Local mode: track completion
		s.MarkFileCompleted(job.InputFile)
		s.SetFileProcessingTime(job.InputFile, duration.Seconds())
		s.SetFileOutputDir(job.InputFile, job.OutputDir)
		s.SetFileBPFFilter(job.InputFile, job.BPFFilter)
	}

	// Execute rules automatically after successful analysis (async to not block next job)
	go s.executeRulesForJob(job)
}

// countExtractedFiles counts the number of files in the files directory
func (s *Server) countExtractedFiles(filesDir string) int {
	if filesDir == "" {
		return 0
	}

	// Check if directory exists
	if _, err := os.Stat(filesDir); os.IsNotExist(err) {
		return 0
	}

	count := 0
	filepath.Walk(filesDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil // Continue walking
		}
		// Count only files, not directories
		if !info.IsDir() {
			count++
		}
		return nil
	})

	return count
}

// executeRulesForJob executes all enabled rules for a completed analysis job
func (s *Server) executeRulesForJob(job *AnalysisJob) {
	mode := "[Service]"
	if !s.isServiceMode {
		mode = "[WebUI]"
	}
	log.Printf("%s Starting rule execution for session %s", mode, job.SessionID)

	// Load rules config
	config, err := s.loadRulesConfig()
	if err != nil {
		log.Printf("%s Failed to load rules config for session %s: %v", mode, job.SessionID, err)
		return
	}

	// Filter for enabled rules only
	enabledRules := make([]*rules.Rule, 0)
	for _, rule := range config.Rules {
		if rule.Enabled {
			enabledRules = append(enabledRules, rule)
		}
	}

	if len(enabledRules) == 0 {
		log.Printf("%s No enabled rules found for session %s, skipping rule execution", mode, job.SessionID)
		return
	}

	log.Printf("%s Executing %d enabled rules for session %s", mode, len(enabledRules), job.SessionID)

	// Execute all enabled rules
	startTime := time.Now()
	totalAlerts := 0
	totalRecords := 0
	totalRulesProcessed := 0

	// Create a single alert writer for the entire job
	// This ensures we read existing alerts once and write all new alerts at the end
	alertWriter, err := rules.NewFileAlertWriter(job.OutputDir)
	if err != nil {
		log.Printf("%s Failed to create alert writer for session %s: %v", mode, job.SessionID, err)
		return
	}
	defer alertWriter.Close()

	// Group rules by type to minimize file reads
	// We want to read each audit file (e.g. TCP.ncap.gz) only once
	rulesByType := make(map[string][]*rules.Rule)
	for _, rule := range enabledRules {
		rulesByType[rule.Type] = append(rulesByType[rule.Type], rule)
	}

	for typeStr, typeRules := range rulesByType {
		// Skip if no rules for this type
		if len(typeRules) == 0 {
			continue
		}

		// Check if audit file exists for this type
		auditFile := filepath.Join(job.OutputDir, typeStr+".ncap.gz")
		if _, err := os.Stat(auditFile); os.IsNotExist(err) {
			// Try without extension just in case (though ncap usually produces .ncap.gz or .ncap)
			auditFile = filepath.Join(job.OutputDir, typeStr+".ncap")
			if _, err := os.Stat(auditFile); os.IsNotExist(err) {
				continue
			}
		}

		// Create a temporary config with rules for this type
		typeConfig := &rules.Config{
			Rules: typeRules,
		}

		// Create engine with these rules
		engine, err := rules.NewEngineFromConfig(typeConfig, alertWriter)
		if err != nil {
			log.Printf("%s Failed to create rules engine for type %s: %v", mode, typeStr, err)
			continue
		}

		// Open audit record reader
		reader, err := NewAuditRecordReader(auditFile)
		if err != nil {
			log.Printf("%s Failed to open audit file %s: %v", mode, auditFile, err)
			continue
		}

		// Read header
		if _, err := reader.ReadHeader(); err != nil {
			reader.Close()
			log.Printf("%s Failed to read header for %s: %v", mode, auditFile, err)
			continue
		}

		// Process records
		batchStart := time.Now()
		batchRecords := 0
		batchAlerts := 0

		for {
			record, err := reader.NextRecord()
			if err != nil {
				if err == stdio.EOF {
					break
				}
				log.Printf("%s Error reading record from %s: %v", mode, auditFile, err)
				break
			}

			batchRecords++

			// Type assert to AuditRecord
			auditRecord, ok := record.(types.AuditRecord)
			if !ok {
				continue
			}

			// Evaluate
			alerts, err := engine.Evaluate(auditRecord)
			if err != nil {
				// Log error but continue
				// log.Printf("%s Error evaluating record: %v", mode, err)
				continue
			}
			batchAlerts += alerts
		}

		reader.Close()

		totalAlerts += batchAlerts
		totalRecords += batchRecords
		totalRulesProcessed += len(typeRules)

		log.Printf("%s Processed %s: %d rules, %d records, %d alerts (took %v)",
			mode, typeStr, len(typeRules), batchRecords, batchAlerts, time.Since(batchStart))
	}

	executionTime := time.Since(startTime)

	log.Printf("%s Rule execution completed for session %s: %d rules processed, %d total alerts from %d total records (took %v)",
		mode, job.SessionID, totalRulesProcessed, totalAlerts, totalRecords, executionTime)
}

// runAnalysisInProcess executes a netcap capture analysis in-process
// TODO: nDPI or libprotoident seem to be leaking memory, causing virtual memory usage to grow unbounded.
// Needs more debugging.
func (s *Server) runAnalysisInProcess(job *AnalysisJob) {
	log.Printf("[WebUI] Starting in-process analysis for session %s", job.SessionID)

	// Add panic recovery as defense in depth
	defer func() {
		if r := recover(); r != nil {
			log.Printf("[WebUI] PANIC recovered in runAnalysisInProcess for session %s: %v", job.SessionID, r)
			log.Printf("[WebUI] Stack trace:\n%s", debug.Stack())

			// Mark session as failed
			if s.sessionManager != nil {
				errorMsg := fmt.Sprintf("Analysis crashed during execution: %v", r)
				s.sessionManager.UpdateSessionStatus(job.SessionID, StatusFailed, errorMsg, "")
			}
		}
	}()

	// Update status to processing
	if s.sessionManager != nil {
		s.sessionManager.UpdateSessionStatus(job.SessionID, StatusProcessing, "", "")
	}

	// Report memory usage before analysis
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	numGoroutines := runtime.NumGoroutine()
	log.Printf("[WebUI] Memory before analysis (session %s): Heap Alloc=%s, Heap Sys=%s, Goroutines=%d",
		job.SessionID, humanize.Bytes(m.HeapAlloc), humanize.Bytes(m.HeapSys), numGoroutines)

	startTime := time.Now()

	// Enable file extraction - create files directory within the output directory
	// Note: FileStorage must be a RELATIVE path since it gets joined with Out directory in SaveFile()
	fileStorageRelPath := "files"
	filesDir := filepath.Join(job.OutputDir, fileStorageRelPath)
	if err := os.MkdirAll(filesDir, 0755); err != nil {
		log.Printf("[WebUI] Warning: Failed to create files directory: %v", err)
		fileStorageRelPath = "" // Disable file storage if we can't create the directory
	} else {
		log.Printf("[WebUI] File extraction enabled for session %s: %s", job.SessionID, filesDir)
	}

	// Build collector configuration
	c := collector.New(collector.Config{
		Workers:               runtime.NumCPU() * 2,
		PacketBufferSize:      defaults.PacketBuffer,
		WriteUnknownPackets:   false,
		Promisc:               true,
		SnapLen:               defaults.SnapLen,
		BaseLayer:             utils.GetBaseLayer("ethernet"),
		DecodeOptions:         utils.GetDecodeOptions("default"),
		DPI:                   job.EnableDPI,
		DPIModules:            "",
		ReassembleConnections: true,
		FreeOSMem:             0,
		LogErrors:             false,
		NoPrompt:              true,
		HTTPShutdownEndpoint:  false,
		NoSignalHandling:      true, // Disable signal handling in service mode
		Timeout:               1 * time.Second,
		Labels:                "",
		Scatter:               true,
		ScatterDuration:       5 * time.Minute,
		DecoderConfig: &config.Config{
			Quiet:            true,
			PrintProgress:    false,
			Buffer:           true,
			MemBufferSize:    defaults.BufferSize,
			Compression:      true,
			CSV:              false,
			UnixSocket:       false,
			Encode:           false,
			Label:            false,
			Null:             false,
			Elastic:          false,
			ElasticConfig:    io.ElasticConfig{},
			BulkSizeGoPacket: 2000,
			BulkSizeCustom:   1000,
			IncludeDecoders:  job.IncludeDecoders,
			ExcludeDecoders:  getExcludeDecoders(job),
			Out:              job.OutputDir,
			Proto:            true,
			JSON:             false,
			Chan:             false,
			Source:           job.InputFile,
			IncludePayloads:  s.GetPayloadCapture(),
			ExportMetrics:    false,
			AddContext:       true,
			FlushEvery:       defaults.FlushEvery,
			DefragIPv4:       defaults.DefragIPv4,
			Checksum:         defaults.Checksum,
			NoOptCheck:       defaults.NoOptCheck,
			IgnoreFSMerr:     true, // Ignore FSM errors for better reliability
			AllowMissingInit: true, // Allow streams without handshake
			Debug:            false,
			HexDump:          false,
			WriteIncomplete:  true, // Write incomplete streams immediately
			MemProfile:       "",
			// NOTE: Use default timeout values - aggressive timeouts cause streams to close prematurely!
			// For offline pcap analysis, timeouts are based on packet timestamps, not wall time.
			// Default values (24 hours for timeouts) work correctly for both online and offline captures.
			FileStorage:                    fileStorageRelPath,
			CalculateEntropy:               false,
			SaveConns:                      true, // Enable saving raw conversation data to tcp/udp folders
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
			ReverseDNS: false,
			LocalDNS:   false,
			MACDB:      true,

			ServiceDB:     true,
			GeolocationDB: true,
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

	// Count and log extracted files
	fileCount := s.countExtractedFiles(filesDir)
	if fileCount > 0 {
		log.Printf("[WebUI] Extracted %d file(s) for session %s", fileCount, job.SessionID)
	}

	if s.sessionManager != nil {
		s.sessionManager.UpdateSessionProcessingTime(job.SessionID, duration.Seconds())
		// TODO: Extract packet count from collector if available
		s.sessionManager.UpdateSessionStatus(job.SessionID, StatusCompleted, "", "")

		// Auto-select this file if no active file is currently set (service mode only)
		// This makes the first completed capture immediately available for viewing
		s.mu.Lock()
		if s.activeInputFile == "" {
			// Get session info to set as active
			if session, ok := s.sessionManager.GetSession(job.SessionID); ok {
				s.currentSession = job.SessionID
				s.outDir = job.OutputDir
				s.activeInputFile = session.InputFile
				log.Printf("[WebUI] Auto-selected first completed capture: session=%s, file=%s",
					job.SessionID, session.InputFilename)
			}
		}
		s.mu.Unlock()
	}

	// Execute rules automatically after successful analysis
	s.executeRulesForJob(job)

	// ==================================================================================
	// CRITICAL: Memory cleanup after each job to prevent OOM in long-running service
	// Same cleanup logic as used in multi-file processing to release accumulated state
	// ==================================================================================
	log.Printf("[WebUI] Starting memory cleanup for session %s...", job.SessionID)

	// Step 1: Reset packet-level state (lightweight, no heavy allocations)
	packet.ResetDeviceProfiles()
	packet.ResetIPProfiles()
	packet.ResetConnections()

	// Step 2: Reset stream-level state (lightweight)
	service.ResetStore()
	service.ResetProbeEnums()
	udp.ResetStreams()
	network.ResetStreams()
	httpstream.ResetHTTPStore()
	streamutils.ResetStats()

	// Step 2a: Reset global caches that accumulate unbounded
	// UserAgentCache and Software Store accumulate across all files
	software.ResetCaches()

	// Step 2b: Reset deduplication stores
	// These accumulate ALL unique credentials/exploits/vulns across files
	credentials.ResetCredStore()
	exploit.ResetExploitStore()
	vulnerability.ResetVulnStore()

	// Step 3: Flush all assemblers to release pageCaches
	// THE ROOT CAUSE: Assembler.pageCache grows unbounded and NEVER SHRINKS
	// Each page holds AssemblerContext which references packet data
	// pageCaches can grow to GB of memory and are NOT released on collector cleanup
	// NOTE: cleanup() is already called at the end of CollectPcap(), which stops all goroutines
	// including workers, TCP stream readers, and freeOSMemory goroutine
	if c != nil {
		log.Printf("[WebUI] Flushing assemblers to release pageCaches for session %s...", job.SessionID)
		c.FlushAssemblers()
	}

	// Step 4: Nil out collector to release all references
	// This breaks the reference chain: collector -> assemblers -> pageCaches -> packets
	c = nil

	// Step 5: Force GC to clear assemblers, pageCaches, and packet data
	// we must GC everything before resetting the TCP factory
	runtime.GC()

	// Step 6: Ensure ALL TCP stream reader goroutines are stopped
	// Even though cleanup() was called at the end of CollectPcap(), we need to
	// ensure goroutines have fully exited before resetting the factory
	// Use quiet version since log files for previous file are already closed
	log.Printf("[WebUI] Ensuring TCP stream readers are stopped for session %s...", job.SessionID)
	tcp.CloseStreamReaderChannelsAndWaitQuiet()

	// Step 7: NOW reset TCP factory - old StreamPool can be GC'd
	// Because assemblers, pageCaches, and stream readers are gone, old pool has no references
	tcp.ResetStreamFactory()

	// Step 8: Reset DPI flow tracker if DPI is enabled
	if job.EnableDPI && dpi.HasDPISupport() {
		log.Printf("[WebUI] Resetting DPI for session %s...", job.SessionID)
		dpi.Reset("") // Service mode uses all modules
	}

	// Step 9: Final GC and OS memory release
	runtime.GC()
	debug.FreeOSMemory()

	// Report memory usage after cleanup
	runtime.ReadMemStats(&m)
	numGoroutines = runtime.NumGoroutine()
	log.Printf("[WebUI] Memory after cleanup (session %s): Heap Alloc=%s, Heap Sys=%s, Goroutines=%d",
		job.SessionID, humanize.Bytes(m.HeapAlloc), humanize.Bytes(m.HeapSys), numGoroutines)
	log.Printf("[WebUI] Memory cleanup completed for session %s", job.SessionID)
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
				// 1. Clean up expired sessions tracked in memory
				expiredSessions := s.sessionManager.CleanupExpiredSessions()
				if len(expiredSessions) > 0 {
					log.Printf("[WebUI] Cleaned up %d expired sessions from memory", len(expiredSessions))

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

				// 2. Clean up orphaned directories on disk (not tracked in memory)
				orphanedCount := s.cleanupOrphanedResultDirectories()
				if orphanedCount > 0 {
					log.Printf("[WebUI] Cleaned up %d orphaned result directories from disk", orphanedCount)
				}
			}
		case <-s.shutdownChan:
			log.Println("[WebUI] Cleanup routine shutting down")
			return
		}
	}
}

// cleanupOrphanedResultDirectories scans the results directory and removes expired
// session directories that are not tracked in memory (e.g., from previous server runs)
func (s *Server) cleanupOrphanedResultDirectories() int {
	resultsDir := filepath.Join(s.serviceConfig.DataDir, "results")

	entries, err := os.ReadDir(resultsDir)
	if err != nil {
		log.Printf("[WebUI] Failed to read results directory for orphan cleanup: %v", err)
		return 0
	}

	expiryTime := time.Now().Add(-time.Duration(s.serviceConfig.SessionExpiry) * time.Minute)
	cleanedCount := 0

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		sessionID := entry.Name()

		// Skip if this session is currently tracked in memory (already handled above)
		if _, exists := s.sessionManager.GetSession(sessionID); exists {
			continue
		}

		sessionDir := filepath.Join(resultsDir, sessionID)
		metadataPath := filepath.Join(sessionDir, "session.json")

		// Try to load session metadata from disk
		session, err := loadSessionMetadata(metadataPath)
		if err != nil {
			// No valid metadata - check directory modification time instead
			info, err := entry.Info()
			if err != nil {
				continue
			}
			// If directory is old enough, remove it
			if info.ModTime().Before(expiryTime) {
				if err := os.RemoveAll(sessionDir); err != nil {
					log.Printf("[WebUI] Error removing orphaned directory %s: %v", sessionID, err)
				} else {
					cleanedCount++
				}
			}
			continue
		}

		// Check if this session is expired based on its upload timestamp
		if session.UploadTimestamp.Before(expiryTime) {
			if err := os.RemoveAll(sessionDir); err != nil {
				log.Printf("[WebUI] Error removing expired orphaned session %s: %v", sessionID, err)
			} else {
				cleanedCount++
				// Also try to remove upload file if it exists
				uploadFile := filepath.Join(s.serviceConfig.DataDir, "uploads", sessionID+".pcap")
				_ = os.Remove(uploadFile) // Ignore error if doesn't exist
			}
		}
	}

	return cleanedCount
}
