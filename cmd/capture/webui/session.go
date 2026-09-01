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
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"
)

// SessionStatus represents the current status of an analysis session
type SessionStatus string

const (
	StatusQueued     SessionStatus = "queued"
	StatusProcessing SessionStatus = "processing"
	StatusCompleted  SessionStatus = "completed"
	StatusFailed     SessionStatus = "failed"
)

// SessionInfo tracks information about an upload and analysis session
type SessionInfo struct {
	SessionID        string        `json:"sessionId"`
	IP               string        `json:"ip"`
	UploadTimestamp  time.Time     `json:"uploadTimestamp"`
	InputFile        string        `json:"inputFile"`
	InputFilename    string        `json:"inputFilename"`
	InputFileSize    int64         `json:"inputFileSize"`
	OutputDir        string        `json:"outputDir"`
	Status           SessionStatus `json:"status"`
	ErrorMessage     string        `json:"errorMessage,omitempty"`
	ErrorLogPath     string        `json:"errorLogPath,omitempty"` // Path to detailed error log file
	StartTime        time.Time     `json:"startTime"`
	CompletionTime   time.Time     `json:"completionTime"`
	ProcessingTime   float64       `json:"processingTime,omitempty"` // Processing duration in seconds
	PacketsTotal     int64         `json:"packetsTotal,omitempty"`
	ResultsReady     bool          `json:"resultsReady"`
	ShareUrl         string        `json:"shareUrl"`         // Shareable URL for viewing this session
	IsPreloaded      bool          `json:"isPreloaded"`      // True if this is a preloaded system pcap
	BPFFilter        string        `json:"bpfFilter"`        // BPF filter applied during capture
	IncludeDecoders  string        `json:"includeDecoders"`  // Decoders included during capture
	ExcludeDecoders  string        `json:"excludeDecoders"`  // Decoders excluded during capture
	HasReportedIssue bool          `json:"hasReportedIssue"` // True if an issue has been reported for this session
}

// IPTracker tracks analysis attempts per IP for rate limiting
type IPTracker struct {
	IP               string
	AnalysisTimes    []time.Time
	Sessions         []string    // Session IDs
	IssueReportTimes []time.Time // Timestamps of issue reports for rate limiting
}

// SessionManager manages all active sessions and IP tracking
type SessionManager struct {
	sessions              map[string]*SessionInfo // sessionID -> SessionInfo
	ipTrackers            map[string]*IPTracker   // IP -> IPTracker
	mu                    sync.RWMutex
	maxAnalysisHour       int
	sessionExpiryMin      int
	maxIssueReportsPerDay int
}

// NewSessionManager creates a new session manager
func NewSessionManager(maxAnalysisHour, sessionExpiryMin, maxIssueReportsPerDay int) *SessionManager {
	return &SessionManager{
		sessions:              make(map[string]*SessionInfo),
		ipTrackers:            make(map[string]*IPTracker),
		maxAnalysisHour:       maxAnalysisHour,
		sessionExpiryMin:      sessionExpiryMin,
		maxIssueReportsPerDay: maxIssueReportsPerDay,
	}
}

// CheckRateLimit checks if an IP has exceeded the rate limit
func (sm *SessionManager) CheckRateLimit(ip string) (allowed bool, remaining int) {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	tracker, exists := sm.ipTrackers[ip]
	if !exists {
		return true, sm.maxAnalysisHour
	}

	// Count analyses in the last hour
	oneHourAgo := time.Now().Add(-1 * time.Hour)
	recentCount := 0
	for _, t := range tracker.AnalysisTimes {
		if t.After(oneHourAgo) {
			recentCount++
		}
	}

	remaining = max(sm.maxAnalysisHour-recentCount, 0)

	return recentCount < sm.maxAnalysisHour, remaining
}

// AddSession adds a new session and tracks it for the IP
func (sm *SessionManager) AddSession(session *SessionInfo) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	sm.sessions[session.SessionID] = session

	// Update IP tracker
	tracker, exists := sm.ipTrackers[session.IP]
	if !exists {
		tracker = &IPTracker{
			IP:               session.IP,
			AnalysisTimes:    []time.Time{},
			Sessions:         []string{},
			IssueReportTimes: []time.Time{},
		}
		sm.ipTrackers[session.IP] = tracker
	}

	tracker.AnalysisTimes = append(tracker.AnalysisTimes, session.UploadTimestamp)
	tracker.Sessions = append(tracker.Sessions, session.SessionID)
}

// GetSession retrieves a session by ID
func (sm *SessionManager) GetSession(sessionID string) (*SessionInfo, bool) {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	session, exists := sm.sessions[sessionID]
	return session, exists
}

// GetSessionForIP checks if a session belongs to a specific IP
func (sm *SessionManager) GetSessionForIP(sessionID, ip string) (*SessionInfo, bool) {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	session, exists := sm.sessions[sessionID]
	if !exists || session.IP != ip {
		return nil, false
	}

	return session, true
}

// UpdateSessionStatus updates the status of a session
func (sm *SessionManager) UpdateSessionStatus(sessionID string, status SessionStatus, errorMsg string, errorLogPath string) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	if session, exists := sm.sessions[sessionID]; exists {
		log.Printf("[SessionManager] Updating session %s status: %s -> %s", sessionID, session.Status, status)
		session.Status = status
		session.ErrorMessage = errorMsg
		if errorLogPath != "" {
			log.Printf("[SessionManager] Setting errorLogPath for session %s: %s", sessionID, errorLogPath)
			session.ErrorLogPath = errorLogPath
		} else if status == StatusFailed {
			log.Printf("[SessionManager] WARNING: Session %s failed but no errorLogPath provided", sessionID)
		}

		if status == StatusProcessing && session.StartTime.IsZero() {
			session.StartTime = time.Now()
		} else if status == StatusCompleted || status == StatusFailed {
			session.CompletionTime = time.Now()
			if status == StatusCompleted {
				session.ResultsReady = true
				log.Printf("[SessionManager] Session %s marked as completed and ready", sessionID)
			} else if status == StatusFailed {
				log.Printf("[SessionManager] Session %s marked as failed (errorMsg: %s, errorLogPath: %s)",
					sessionID, errorMsg, session.ErrorLogPath)
			}
		}

		// Save session metadata to disk after status update
		go func() {
			metadataPath := filepath.Join(session.OutputDir, "session.json")
			if err := saveSessionMetadata(metadataPath, session); err != nil {
				log.Printf("[SessionManager] Warning: Failed to save session metadata for %s: %v", sessionID, err)
			}
		}()
	} else {
		log.Printf("[SessionManager] WARNING: Attempted to update non-existent session %s to status %s", sessionID, status)
	}
}

// UpdateSessionPacketCount updates the packet count for a session
func (sm *SessionManager) UpdateSessionPacketCount(sessionID string, count int64) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	if session, exists := sm.sessions[sessionID]; exists {
		session.PacketsTotal = count
	}
}

// UpdateSessionProcessingTime updates the processing time for a session
func (sm *SessionManager) UpdateSessionProcessingTime(sessionID string, durationSeconds float64) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	if session, exists := sm.sessions[sessionID]; exists {
		session.ProcessingTime = durationSeconds
		log.Printf("[SessionManager] Session %s processing time: %.2f seconds", sessionID, durationSeconds)
	}
}

// CleanupExpiredSessions removes expired sessions and their data
func (sm *SessionManager) CleanupExpiredSessions() []string {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	expiryTime := time.Now().Add(-time.Duration(sm.sessionExpiryMin) * time.Minute)
	expiredSessions := []string{}

	// Find expired sessions
	for sessionID, session := range sm.sessions {
		// Skip preloaded system pcaps - they should never expire
		if session.IsPreloaded {
			continue
		}

		if session.UploadTimestamp.Before(expiryTime) {
			expiredSessions = append(expiredSessions, sessionID)
			delete(sm.sessions, sessionID)
		}
	}

	// Clean up IP trackers
	for ip, tracker := range sm.ipTrackers {
		// Remove expired analysis times
		validTimes := []time.Time{}
		for _, t := range tracker.AnalysisTimes {
			if t.After(expiryTime) {
				validTimes = append(validTimes, t)
			}
		}
		tracker.AnalysisTimes = validTimes

		// Remove expired session references
		validSessions := []string{}
		for _, sid := range tracker.Sessions {
			found := slices.Contains(expiredSessions, sid)
			if !found {
				validSessions = append(validSessions, sid)
			}
		}
		tracker.Sessions = validSessions

		// Remove IP tracker if no recent activity
		if len(tracker.AnalysisTimes) == 0 {
			delete(sm.ipTrackers, ip)
		}
	}

	return expiredSessions
}

// DeleteSession removes one session from the manager and (optionally)
// from the IP tracker. Returns the removed *SessionInfo or nil if the
// id wasn't found. Caller is responsible for removing on-disk artefacts
// (uploads/<sid>, results/<sid>); see Server.deleteSessionArtefacts.
func (sm *SessionManager) DeleteSession(sessionID string) *SessionInfo {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	session, ok := sm.sessions[sessionID]
	if !ok {
		return nil
	}
	delete(sm.sessions, sessionID)
	if tracker, ok := sm.ipTrackers[session.IP]; ok {
		kept := tracker.Sessions[:0]
		for _, sid := range tracker.Sessions {
			if sid != sessionID {
				kept = append(kept, sid)
			}
		}
		tracker.Sessions = kept
	}
	return session
}

// GetAllSessions returns all sessions (for debugging/monitoring)
func (sm *SessionManager) GetAllSessions() []*SessionInfo {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	sessions := make([]*SessionInfo, 0, len(sm.sessions))
	for _, session := range sm.sessions {
		sessions = append(sessions, session)
	}
	return sessions
}

// GetSessionsForIP returns all sessions for a specific IP
func (sm *SessionManager) GetSessionsForIP(ip string) []*SessionInfo {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	sessions := make([]*SessionInfo, 0)
	for _, session := range sm.sessions {
		if session.IP == ip {
			sessions = append(sessions, session)
		}
	}
	return sessions
}

// GetAccessibleSessions returns the sessions a given client may read: its own,
// plus the preloaded system pcaps that are published to everyone.
//
// Use this, not GetAllSessions, for anything that serves data derived from
// capture files. GetAllSessions ignores ownership, and in service mode the
// uploads it exposes belong to other visitors -- netcap extracts credentials,
// DNS queries, certificates and files out of them. Two aggregation paths (the
// dashboard's "All PCAPs" chart scope and the global geolocation chart) used
// GetAllSessions and so mixed every visitor's capture into one view.
//
// The ownership test is the same one handleListInputFiles applies: match on IP,
// or accept the session if it is flagged preloaded.
func (sm *SessionManager) GetAccessibleSessions(ip string) []*SessionInfo {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	sessions := make([]*SessionInfo, 0)

	for _, session := range sm.sessions {
		if session.IsPreloaded || session.IP == ip {
			sessions = append(sessions, session)
		}
	}

	return sessions
}

// CheckIssueReportLimit checks if an IP has exceeded the issue report rate limit (3 per hour)
func (sm *SessionManager) CheckIssueReportLimit(ip string) (allowed bool, remaining int) {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	tracker, exists := sm.ipTrackers[ip]
	if !exists {
		return true, 3 // Allow 3 reports per hour
	}

	// Count issue reports in the last hour
	oneHourAgo := time.Now().Add(-1 * time.Hour)
	recentCount := 0
	for _, t := range tracker.IssueReportTimes {
		if t.After(oneHourAgo) {
			recentCount++
		}
	}

	remaining = max(
		// 3 reports per hour
		3-recentCount, 0)

	return recentCount < 3, remaining
}

// RecordIssueReport records an issue report for an IP
func (sm *SessionManager) RecordIssueReport(ip string) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	tracker, exists := sm.ipTrackers[ip]
	if !exists {
		tracker = &IPTracker{
			IP:               ip,
			AnalysisTimes:    []time.Time{},
			Sessions:         []string{},
			IssueReportTimes: []time.Time{},
		}
		sm.ipTrackers[ip] = tracker
	}

	tracker.IssueReportTimes = append(tracker.IssueReportTimes, time.Now())
	log.Printf("[SessionManager] Issue report recorded for IP %s (total in last hour: %d)", ip, len(tracker.IssueReportTimes))
}

// MarkSessionIssueReported marks a session as having an issue reported
func (sm *SessionManager) MarkSessionIssueReported(sessionID string) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	if session, exists := sm.sessions[sessionID]; exists {
		session.HasReportedIssue = true
		log.Printf("[SessionManager] Session %s marked as having reported issue", sessionID)
	}
}

// GetStorageUsageForIP calculates storage usage for a specific IP
// This includes both the user's own sessions and preloaded/system pcaps
func (sm *SessionManager) GetStorageUsageForIP(ip string) int64 {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	var totalSize int64 = 0
	for _, session := range sm.sessions {
		// Include sessions belonging to this IP OR preloaded system pcaps
		// Preloaded pcaps (IP="system") count towards all users' storage limits
		// since they consume shared server resources
		if session.IP == ip || session.IP == "system" {
			// Calculate results directory size (contains all audit records)
			resultsDirSize, err := calculateDirectorySize(session.OutputDir)
			if err != nil {
				log.Printf("[SessionManager] Error calculating results directory size for session %s: %v", session.SessionID, err)
			} else {
				totalSize += resultsDirSize
			}

			// Add input file size (the uploaded PCAP file stored in uploads directory)
			// This is stored separately from the results directory
			totalSize += session.InputFileSize
		}
	}
	return totalSize
}

// RestoreSessionsFromDisk scans the results directory and restores session information
// This allows sessions to persist across server restarts
func (sm *SessionManager) RestoreSessionsFromDisk(resultsDir, pcapsDir, uploadsDir string) error {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	log.Printf("[SessionManager] Restoring sessions from disk...")
	log.Printf("[SessionManager] Results directory: %s", resultsDir)
	log.Printf("[SessionManager] Pcaps directory: %s", pcapsDir)
	log.Printf("[SessionManager] Uploads directory: %s", uploadsDir)

	// Check if results directory exists
	if _, err := os.Stat(resultsDir); os.IsNotExist(err) {
		log.Printf("[SessionManager] Results directory does not exist, skipping session restoration")
		return nil
	}

	// Read all session directories in results
	entries, err := os.ReadDir(resultsDir)
	if err != nil {
		return fmt.Errorf("failed to read results directory: %w", err)
	}

	restoredCount := 0
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		sessionID := entry.Name()
		sessionDir := filepath.Join(resultsDir, sessionID)

		// Try to load session metadata file
		metadataPath := filepath.Join(sessionDir, "session.json")
		session, err := loadSessionMetadata(metadataPath)

		if err != nil {
			// If metadata file doesn't exist or is invalid, try to reconstruct session info
			session, err = sm.reconstructSession(sessionID, sessionDir, pcapsDir, uploadsDir)
			if err != nil {
				log.Printf("[SessionManager] Failed to restore session %s: %v", sessionID, err)
				continue
			}

			// Save reconstructed session metadata for next time
			if saveErr := saveSessionMetadata(metadataPath, session); saveErr != nil {
				log.Printf("[SessionManager] Warning: Failed to save reconstructed session metadata for %s: %v", sessionID, saveErr)
			}
		}

		// Add session to manager
		sm.sessions[sessionID] = session

		// Update IP tracker (don't count towards rate limits for restored sessions)
		tracker, exists := sm.ipTrackers[session.IP]
		if !exists {
			tracker = &IPTracker{
				IP:               session.IP,
				AnalysisTimes:    []time.Time{},
				Sessions:         []string{},
				IssueReportTimes: []time.Time{},
			}
			sm.ipTrackers[session.IP] = tracker
		}
		tracker.Sessions = append(tracker.Sessions, session.SessionID)

		restoredCount++
		log.Printf("[SessionManager] Restored session %s (IP: %s, file: %s, status: %s)",
			sessionID, session.IP, session.InputFilename, session.Status)
	}

	log.Printf("[SessionManager] Successfully restored %d session(s) from disk", restoredCount)
	return nil
}

// reconstructSession attempts to reconstruct session information from filesystem
func (sm *SessionManager) reconstructSession(sessionID, sessionDir, pcapsDir, uploadsDir string) (*SessionInfo, error) {
	// Get directory info for timestamp
	dirInfo, err := os.Stat(sessionDir)
	if err != nil {
		return nil, fmt.Errorf("failed to stat session directory: %w", err)
	}

	// Try to find the input file
	// 1. Check uploads directory (user uploads)
	inputFile := filepath.Join(uploadsDir, sessionID+".pcap")
	inputFilename := sessionID + ".pcap"
	isPreloaded := false
	ip := "unknown"

	if _, err := os.Stat(inputFile); os.IsNotExist(err) {
		// 2. Check pcaps directory (preloaded pcaps)
		// Search for any pcap file that might correspond to this session
		if pcapsDir != "" {
			if entries, err := os.ReadDir(pcapsDir); err == nil {
				for _, entry := range entries {
					if entry.IsDir() {
						continue
					}
					filename := entry.Name()
					ext := strings.ToLower(filepath.Ext(filename))
					if ext == ".pcap" || ext == ".pcapng" {
						// Use the first pcap file found as a guess
						// This is not perfect but better than nothing
						inputFile = filepath.Join(pcapsDir, filename)
						inputFilename = filename
						isPreloaded = true
						ip = "system"
						break
					}
				}
			}
		}

		// If still not found, use a placeholder path
		if inputFile == filepath.Join(uploadsDir, sessionID+".pcap") {
			inputFile = "unknown"
			inputFilename = "unknown"
		}
	}

	// Get file size if file exists
	var fileSize int64 = 0
	if fileInfo, err := os.Stat(inputFile); err == nil {
		fileSize = fileInfo.Size()
	}

	// Determine status by checking for completion markers
	status := StatusCompleted
	resultsReady := true

	// Check if there's an error log
	errorLogPath := filepath.Join(sessionDir, "analysis_error.log")
	errorMessage := ""
	if _, err := os.Stat(errorLogPath); err == nil {
		status = StatusFailed
		resultsReady = false
		errorMessage = "Analysis failed (see error log)"
	}

	// Check if there are any .ncap or .ncap.gz files (indicates successful completion)
	hasResults := false
	if entries, err := os.ReadDir(sessionDir); err == nil {
		for _, entry := range entries {
			if strings.HasSuffix(entry.Name(), ".ncap") || strings.HasSuffix(entry.Name(), ".ncap.gz") {
				hasResults = true
				break
			}
		}
	}

	if !hasResults && status != StatusFailed {
		status = StatusQueued
		resultsReady = false
	}

	session := &SessionInfo{
		SessionID:       sessionID,
		IP:              ip,
		UploadTimestamp: dirInfo.ModTime(),
		InputFile:       inputFile,
		InputFilename:   inputFilename,
		InputFileSize:   fileSize,
		OutputDir:       sessionDir,
		Status:          status,
		ErrorMessage:    errorMessage,
		ErrorLogPath:    errorLogPath,
		ResultsReady:    resultsReady,
		ShareUrl:        fmt.Sprintf("/view/%s", sessionID),
		IsPreloaded:     isPreloaded,
	}

	return session, nil
}

// loadSessionMetadata loads session metadata from JSON file
func loadSessionMetadata(path string) (*SessionInfo, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var session SessionInfo
	if err := json.Unmarshal(data, &session); err != nil {
		return nil, err
	}

	return &session, nil
}

// saveSessionMetadata saves session metadata to JSON file
func saveSessionMetadata(path string, session *SessionInfo) error {
	data, err := json.MarshalIndent(session, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(path, data, 0644)
}

// SaveSessionMetadata is a public method to save session metadata
// Call this after creating or updating a session to persist it to disk
func (sm *SessionManager) SaveSessionMetadata(sessionID string) error {
	sm.mu.RLock()
	session, exists := sm.sessions[sessionID]
	sm.mu.RUnlock()

	if !exists {
		return fmt.Errorf("session %s not found", sessionID)
	}

	metadataPath := filepath.Join(session.OutputDir, "session.json")
	return saveSessionMetadata(metadataPath, session)
}
