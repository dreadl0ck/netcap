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
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/dreadl0ck/netcap/defaults"
)

// handleAuditStats delegates to the shared handler or aggregates across all sessions in service mode
func (s *Server) handleAuditStats(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	s.mu.RLock()
	isServiceMode := s.isServiceMode
	s.mu.RUnlock()

	// In service mode, aggregate across all session output directories
	if isServiceMode && s.serviceConfig != nil && s.sessionManager != nil {
		s.handleServiceModeAuditStats(w, r)
		return
	}

	// Local mode: use current output directory
	s.mu.RLock()
	outDir := s.outDir
	s.mu.RUnlock()

	HandleAuditStats(outDir)(w, r)
}

// handleServiceModeAuditStats aggregates audit statistics across all sessions in service mode
func (s *Server) handleServiceModeAuditStats(w http.ResponseWriter, r *http.Request) {
	response := AuditStatsResponse{
		TotalRecords:       0,
		ExploitCount:       0,
		VulnerabilityCount: 0,
		CredentialsCount:   0,
		SoftwareCount:      0,
	}

	// Get all sessions
	allSessions := s.sessionManager.GetAllSessions()
	
	// Iterate through all completed sessions and aggregate audit records
	for _, session := range allSessions {
		// Only count completed sessions
		if session.Status != StatusCompleted {
			continue
		}

		// Aggregate stats from this session's output directory
		sessionStats := s.getAuditStatsForDirectory(session.OutputDir)
		response.TotalRecords += sessionStats.TotalRecords
		response.ExploitCount += sessionStats.ExploitCount
		response.VulnerabilityCount += sessionStats.VulnerabilityCount
		response.CredentialsCount += sessionStats.CredentialsCount
		response.SoftwareCount += sessionStats.SoftwareCount
	}

	RespondJSON(w, http.StatusOK, response)
}

// getAuditStatsForDirectory returns audit statistics for a specific directory
func (s *Server) getAuditStatsForDirectory(outputDir string) AuditStatsResponse {
	stats := AuditStatsResponse{
		TotalRecords:       0,
		ExploitCount:       0,
		VulnerabilityCount: 0,
		CredentialsCount:   0,
		SoftwareCount:      0,
	}

	if outputDir == "" {
		return stats
	}

	files, err := os.ReadDir(outputDir)
	if err != nil {
		return stats
	}

	// Count records for specific audit types
	for _, file := range files {
		if file.IsDir() {
			continue
		}

		name := file.Name()
		// Check for audit record files (.ncap.gz)
		if !strings.HasSuffix(name, defaults.FileExtension+".gz") {
			continue
		}

		// Extract type name (remove .ncap.gz)
		typeName := strings.TrimSuffix(name, ".gz")
		typeName = strings.TrimSuffix(typeName, defaults.FileExtension)

		fullPath := filepath.Join(outputDir, name)

		// Count records for this file
		count := CountRecords(fullPath)
		if count == 0 {
			continue
		}

		// Add to total
		stats.TotalRecords += count

		// Check if this is one of the specific audit types we're tracking
		switch typeName {
		case "Exploit":
			stats.ExploitCount = count
		case "Vulnerability":
			stats.VulnerabilityCount = count
		case "Credentials":
			stats.CredentialsCount = count
		case "Software":
			stats.SoftwareCount = count
		}
	}

	return stats
}
