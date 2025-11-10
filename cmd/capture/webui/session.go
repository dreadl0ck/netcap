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
	"log"
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
	StartTime        time.Time     `json:"startTime,omitempty"`
	CompletionTime   time.Time     `json:"completionTime,omitempty"`
	ProcessingTime   float64       `json:"processingTime,omitempty"` // Processing duration in seconds
	PacketsTotal     int64         `json:"packetsTotal,omitempty"`
	ResultsReady     bool          `json:"resultsReady"`
	ShareUrl         string        `json:"shareUrl"`        // Shareable URL for viewing this session
	IsPreloaded      bool          `json:"isPreloaded"`     // True if this is a preloaded system pcap
	BPFFilter        string        `json:"bpfFilter"`       // BPF filter applied during capture
	IncludeDecoders  string        `json:"includeDecoders"` // Decoders included during capture
	ExcludeDecoders  string        `json:"excludeDecoders"` // Decoders excluded during capture
	HasReportedIssue bool          `json:"hasReportedIssue"` // True if an issue has been reported for this session
}

// IPTracker tracks analysis attempts per IP for rate limiting
type IPTracker struct {
	IP               string
	AnalysisTimes    []time.Time
	Sessions         []string // Session IDs
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

	remaining = sm.maxAnalysisHour - recentCount
	if remaining < 0 {
		remaining = 0
	}

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
			found := false
			for _, expired := range expiredSessions {
				if sid == expired {
					found = true
					break
				}
			}
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

	remaining = 3 - recentCount // 3 reports per hour
	if remaining < 0 {
		remaining = 0
	}

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

