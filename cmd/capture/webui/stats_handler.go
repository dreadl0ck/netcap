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
	"encoding/json"
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
	for k, v := range s.fileErrors {
		errors[k] = v
	}
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
