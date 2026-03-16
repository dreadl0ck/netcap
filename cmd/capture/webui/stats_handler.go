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
	"maps"
	"net/http"
	"path/filepath"
	"sync/atomic"
)

// StatsResponse represents the processing statistics response
type StatsResponse struct {
	ProcessingStats ProcessingStats      `json:"processingStats"`
	FileErrors      map[string]FileError `json:"fileErrors"`
}

// handleStats returns the current processing statistics
func (s *Server) handleStats(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	s.mu.RLock()
	stats := s.processingStats
	errors := make(map[string]FileError)
	maps.Copy(errors, s.fileErrors)
	isServiceMode := s.isServiceMode
	collector := s.collector
	s.mu.RUnlock()

	// Populate service mode specific fields
	if isServiceMode && s.jobQueue != nil {
		stats.QueueLength = len(s.jobQueue)
		stats.JobsScheduled = atomic.LoadInt64(&s.jobsScheduled)
		stats.JobsProcessed = atomic.LoadInt64(&s.jobsProcessed)

		// Get currently processing job
		s.currentJobMutex.RLock()
		if s.currentProcessing != nil {
			stats.CurrentFile = filepath.Base(s.currentProcessing.InputFile)
		}
		s.currentJobMutex.RUnlock()
	} else if !isServiceMode && collector != nil {
		// Local mode: populate stats from collector (similar to service mode)
		stats.PacketsProcessed = collector.GetCurrentPacketCount()
		stats.TotalPackets = collector.GetTotalPacketCount()
		stats.PacketsPerSecond = collector.GetPacketsPerSecond()
		stats.ProfilesCount = collector.GetProfilesCount()
		stats.ServicesCount = collector.GetServicesCount()

		// Calculate progress percentage
		if stats.TotalPackets > 0 {
			stats.ProgressPercent = (float64(stats.PacketsProcessed) / float64(stats.TotalPackets)) * 100.0
		}
	}

	response := StatsResponse{
		ProcessingStats: stats,
		FileErrors:      errors,
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(response); err != nil {
		http.Error(w, "Failed to encode response", http.StatusInternalServerError)
	}
}
