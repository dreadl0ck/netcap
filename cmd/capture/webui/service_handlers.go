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
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"
)

// Service-specific handlers (only active in service mode)

// handleHealth returns the health status of the service
func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	if !s.isServiceMode {
		http.Error(w, "Not available in local mode", http.StatusNotFound)
		return
	}

	queueSize := 0
	if s.jobQueue != nil {
		queueSize = len(s.jobQueue)
	}

	sessions := 0
	if s.sessionManager != nil {
		sessions = len(s.sessionManager.GetAllSessions())
	}

	respondJSON(w, http.StatusOK, map[string]interface{}{
		"status":    "healthy",
		"timestamp": time.Now().Unix(),
		"sessions":  sessions,
		"queueSize": queueSize,
	})
}

// handleQuota returns rate limit information for the client
func (s *Server) handleQuota(w http.ResponseWriter, r *http.Request) {
	if !s.isServiceMode {
		http.Error(w, "Not available in local mode", http.StatusNotFound)
		return
	}

	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	clientIP := s.getUserIP(r)

	// Check rate limit
	allowed, remaining := s.sessionManager.CheckRateLimit(clientIP)

	// Calculate storage usage for this IP
	currentStorage := s.sessionManager.GetStorageUsageForIP(clientIP)
	maxStorage := s.serviceConfig.MaxStorageBytes
	availableStorage := maxStorage - currentStorage
	if availableStorage < 0 {
		availableStorage = 0
	}
	percentUsed := float64(0)
	unlimited := maxStorage == 0
	if maxStorage > 0 {
		percentUsed = (float64(currentStorage) / float64(maxStorage)) * 100
	}

	respondJSON(w, http.StatusOK, map[string]interface{}{
		"allowed":   allowed,
		"remaining": remaining,
		"limit":     s.serviceConfig.MaxAnalysisHour,
		"storage": map[string]interface{}{
			"current":     currentStorage,
			"max":         maxStorage,
			"available":   availableStorage,
			"percentUsed": percentUsed,
			"unlimited":   unlimited,
		},
	})
}

// handleListSessions returns all sessions for the requesting IP
func (s *Server) handleListSessions(w http.ResponseWriter, r *http.Request) {
	if !s.isServiceMode {
		http.Error(w, "Not available in local mode", http.StatusNotFound)
		return
	}

	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	clientIP := s.getUserIP(r)
	sessions := s.sessionManager.GetSessionsForIP(clientIP)

	respondJSON(w, http.StatusOK, map[string]interface{}{
		"sessions": sessions,
	})
}

// handleSessionSelect allows selecting a session for viewing
func (s *Server) handleSessionSelect(w http.ResponseWriter, r *http.Request) {
	if !s.isServiceMode {
		http.Error(w, "Not available in local mode", http.StatusNotFound)
		return
	}

	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Extract session ID from URL path
	sessionID := strings.TrimPrefix(r.URL.Path, "/api/try/session/")
	if sessionID == "" {
		respondJSON(w, http.StatusBadRequest, map[string]string{
			"error": "Session ID required",
		})
		return
	}

	clientIP := s.getUserIP(r)

	// Verify session belongs to this IP
	session, ok := s.sessionManager.GetSessionForIP(sessionID, clientIP)
	if !ok {
		respondJSON(w, http.StatusNotFound, map[string]string{
			"error": "Session not found or access denied",
		})
		return
	}

	// Set active output directory to the session's output directory
	s.mu.Lock()
	s.currentSession = sessionID
	s.outDir = session.OutputDir
	s.mu.Unlock()

	respondJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"session": session,
	})
}

// handleViewSession handles shareable session view links
func (s *Server) handleViewSession(w http.ResponseWriter, r *http.Request) {
	if !s.isServiceMode {
		http.Error(w, "Not available in local mode", http.StatusNotFound)
		return
	}

	// Extract session ID from URL path
	sessionID := strings.TrimPrefix(r.URL.Path, "/view/")

	if sessionID == "" {
		http.Error(w, "Session ID required", http.StatusBadRequest)
		return
	}

	// Get session info
	_, ok := s.sessionManager.GetSession(sessionID)
	if !ok {
		http.Error(w, "Session not found", http.StatusNotFound)
		return
	}

	// TODO: Serve a special HTML page for viewing the session
	// For now, redirect to the main UI with session parameter
	http.Redirect(w, r, fmt.Sprintf("/?session=%s", sessionID), http.StatusFound)
}

// handleUploadServiceMode handles file uploads in service mode
func (s *Server) handleUploadServiceMode(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	clientIP := s.getUserIP(r)

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
	maxMemory := s.serviceConfig.MaxFileSize + (10 * 1024 * 1024) // 10MB overhead
	if err := r.ParseMultipartForm(maxMemory); err != nil {
		log.Printf("[WebUI] Failed to parse multipart form: %v", err)
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
	if header.Size > s.serviceConfig.MaxFileSize {
		respondJSON(w, http.StatusBadRequest, map[string]string{
			"error": fmt.Sprintf("File size (%d bytes) exceeds maximum allowed size (%d bytes)", header.Size, s.serviceConfig.MaxFileSize),
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

	// Check for PCAP magic bytes
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
	uploadDir := filepath.Join(s.serviceConfig.DataDir, "uploads", sessionID)
	resultsDir := filepath.Join(s.serviceConfig.DataDir, "results", sessionID)

	if err := os.MkdirAll(uploadDir, 0755); err != nil {
		log.Printf("[WebUI] Failed to create upload directory: %v", err)
		respondJSON(w, http.StatusInternalServerError, map[string]string{
			"error": "Failed to create upload directory",
		})
		return
	}

	if err := os.MkdirAll(resultsDir, 0755); err != nil {
		log.Printf("[WebUI] Failed to create results directory: %v", err)
		respondJSON(w, http.StatusInternalServerError, map[string]string{
			"error": "Failed to create results directory",
		})
		return
	}

	// Save uploaded file
	inputPath := filepath.Join(uploadDir, "input"+ext)
	outFile, err := os.Create(inputPath)
	if err != nil {
		log.Printf("[WebUI] Failed to create input file: %v", err)
		respondJSON(w, http.StatusInternalServerError, map[string]string{
			"error": "Failed to save uploaded file",
		})
		return
	}
	defer outFile.Close()

	if _, err := io.Copy(outFile, file); err != nil {
		log.Printf("[WebUI] Failed to write input file: %v", err)
		respondJSON(w, http.StatusInternalServerError, map[string]string{
			"error": "Failed to save uploaded file",
		})
		return
	}

	// Create session info
	shareURL := fmt.Sprintf("/view/%s", sessionID)
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
		ShareUrl:        shareURL,
	}

	// Add session to manager
	s.sessionManager.AddSession(session)

	// Create analysis job
	job := &AnalysisJob{
		SessionID:       sessionID,
		InputFile:       inputPath,
		OutputDir:       resultsDir,
		EnableDPI:       s.dpiConfigured,
		BPFFilter:       "",       // TODO: Get from request if provided
		IncludeDecoders: "",       // TODO: Get from request if provided
		ExcludeDecoders: "",       // TODO: Get from request if provided
	}

	// Queue the job
	atomic.AddInt64(&s.jobsScheduled, 1)
	s.jobQueue <- job

	log.Printf("[WebUI] Uploaded file %s for session %s, queued for analysis", filename, sessionID)

	// Return response
	respondJSON(w, http.StatusOK, map[string]interface{}{
		"success":   true,
		"sessionId": sessionID,
		"shareUrl":  shareURL,
		"message":   "File uploaded successfully and queued for analysis",
		"remaining": remaining - 1,
	})
}

// Helper functions

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

