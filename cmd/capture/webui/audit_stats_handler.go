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
	"context"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/dreadl0ck/netcap/defaults"
)

// handleAuditStats serves audit statistics. Honors the optional `scope` query
// parameter:
//
//   - "" / "current": legacy behavior — single active output dir (or service
//     mode "across all sessions" aggregation when no current session exists).
//   - "all": always aggregate across every completed capture/session.
//   - any other value: scoped to the matching pcap id / file path.
func (s *Server) handleAuditStats(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	scope := r.URL.Query().Get("scope")

	// Honor explicit scope parameter via the shared resolver.
	if scope != "" && scope != "current" {
		dirs, status, err := s.resolveChartScopeDirs(scope, r)
		if err != nil {
			http.Error(w, err.Error(), status)
			return
		}
		response := AuditStatsResponse{}
		for _, dir := range dirs {
			d := getAuditStatsForDirectory(r.Context(), dir)
			if r.Context().Err() != nil {
				return
			}
			response.TotalRecords += d.TotalRecords
			response.ExploitCount += d.ExploitCount
			response.VulnerabilityCount += d.VulnerabilityCount
			response.SecretCount += d.SecretCount
			response.SoftwareCount += d.SoftwareCount
		}
		RespondJSON(w, http.StatusOK, response)
		return
	}

	if q := r.URL.Query(); q.Has("sessionId") || q.Has("inputFile") || q.Has("runId") {
		selection, ok := s.selectedCapture(w, r)
		if !ok {
			return
		}
		stats := getAuditStatsForDirectory(r.Context(), selection.OutputDir)
		if r.Context().Err() != nil {
			return
		}
		stats.AnalysisPhase, stats.TimelineGeneration = s.selectedAnalysisPhase(selection)
		RespondJSON(w, http.StatusOK, stats)
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

func (s *Server) selectedAnalysisPhase(selection captureSelection) (string, string) {
	s.mu.RLock()
	phase := s.postCapturePhases[selection.OutputDir]
	completed := s.completedFiles[selection.InputFile]
	manager := s.sessionManager
	s.mu.RUnlock()
	if selection.SessionID != "" && manager != nil {
		session, ok := manager.GetSession(selection.SessionID)
		completed = ok && session.Status == StatusCompleted
	}
	if phase != "" || !completed {
		return phase, ""
	}
	fingerprint, _, err := timelineFingerprint(selection.OutputDir)
	if err != nil {
		return "completed", ""
	}
	if fingerprint == "empty" {
		return "completed", fingerprint
	}
	timelineCache.Lock()
	entry := timelineCache.entries[selection.OutputDir]
	timelineCache.Unlock()
	if entry != nil && entry.fingerprint == fingerprint {
		entry.mu.RLock()
		defer entry.mu.RUnlock()
		if entry.state == timelineStateReady && entry.index != nil {
			return "completed", entry.index.Generation
		}
	}
	return "completed", ""
}

// handleServiceModeAuditStats aggregates audit statistics across all sessions in service mode
func (s *Server) handleServiceModeAuditStats(w http.ResponseWriter, r *http.Request) {
	response := AuditStatsResponse{
		TotalRecords:       0,
		ExploitCount:       0,
		VulnerabilityCount: 0,
		SecretCount:        0,
		SoftwareCount:      0,
	}

	// Only the caller's own sessions plus the preloaded demo pcaps. Using
	// GetAllSessions here summed secret, vulnerability and software counts out
	// of every visitor's uploaded capture into one figure.
	allSessions := s.sessionManager.GetAccessibleSessions(s.getUserIP(r))

	// Iterate through all completed sessions and aggregate audit records
	for _, session := range allSessions {
		// Only count completed sessions
		if session.Status != StatusCompleted {
			continue
		}

		// Aggregate stats from this session's output directory
		sessionStats := getAuditStatsForDirectory(r.Context(), session.OutputDir)
		if r.Context().Err() != nil {
			return
		}
		response.TotalRecords += sessionStats.TotalRecords
		response.ExploitCount += sessionStats.ExploitCount
		response.VulnerabilityCount += sessionStats.VulnerabilityCount
		response.SecretCount += sessionStats.SecretCount
		response.SoftwareCount += sessionStats.SoftwareCount
	}

	RespondJSON(w, http.StatusOK, response)
}

// getAuditStatsForDirectory returns audit statistics for a specific directory
func getAuditStatsForDirectory(ctx context.Context, outputDir string) AuditStatsResponse {
	stats := AuditStatsResponse{
		TotalRecords:       0,
		ExploitCount:       0,
		VulnerabilityCount: 0,
		SecretCount:        0,
		SoftwareCount:      0,
	}

	if outputDir == "" || ctx.Err() != nil {
		return stats
	}

	files, err := os.ReadDir(outputDir)
	if err != nil {
		return stats
	}

	// Count records for specific audit types
	for _, file := range files {
		if ctx.Err() != nil {
			break
		}
		if file.IsDir() {
			continue
		}

		name := file.Name()
		// Check for audit record files (.ncap.gz)
		if !preferredAuditFile(outputDir, name) {
			continue
		}

		// Extract type name (remove .ncap.gz)
		typeName := strings.TrimSuffix(name, ".gz")
		typeName = strings.TrimSuffix(typeName, defaults.FileExtension)

		fullPath := filepath.Join(outputDir, name)

		// Count records for this file
		count, ok := communityCachedTotal(fullPath)
		if !ok {
			count, _ = countAuditFrames(ctx, fullPath, typeName)
		}
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
		case "Secret":
			stats.SecretCount = count
		case "Software":
			stats.SoftwareCount = count
		}
	}

	return stats
}
