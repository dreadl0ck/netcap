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
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"maps"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// ProgressInfo represents the progress of an analysis job
type ProgressInfo struct {
	SessionID       string  `json:"sessionId"`
	Status          string  `json:"status"`
	ProgressPercent float64 `json:"progressPercent"`
	Message         string  `json:"message"`
	ErrorMessage    string  `json:"errorMessage,omitempty"`
}

// progressRegex matches progress lines in netcap.log (format: "progress: XX%")
var progressRegex = regexp.MustCompile(`progress:\s*(\d+(?:\.\d+)?)%`)

// handleProgress returns the progress of an analysis job by reading the netcap.log file
func (s *Server) handleProgress(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Extract file ID from URL path: /api/progress/{fileId}
	encodedFileID := strings.TrimPrefix(r.URL.Path, "/api/progress/")
	if encodedFileID == "" {
		http.Error(w, "File ID required", http.StatusBadRequest)
		return
	}

	// URL-decode the file ID
	fileID, err := url.PathUnescape(encodedFileID)
	if err != nil {
		log.Printf("[Progress] Failed to decode file ID: %v", err)
		http.Error(w, "Invalid file ID encoding", http.StatusBadRequest)
		return
	}

	log.Printf("[Progress] Request for fileID: %s", fileID)

	var outputDir string
	var status string
	var errorMessage string

	// Service mode: Look up the session (file ID is session ID)
	if s.isServiceMode && s.sessionManager != nil {
		session, exists := s.sessionManager.GetSession(fileID)
		if !exists || session == nil {
			http.Error(w, "Session not found", http.StatusNotFound)
			return
		}

		outputDir = session.OutputDir
		status = string(session.Status)
		errorMessage = session.ErrorMessage
	} else {
		// Local mode: Look up file path from file ID
		s.mu.RLock()
		filePath, exists := s.fileIDToPath[fileID]
		if !exists {
			s.mu.RUnlock()
			log.Printf("[Progress] File ID not found: %s", fileID)
			http.Error(w, "File not found", http.StatusNotFound)
			return
		}

		fileOutputDirs := make(map[string]string)
		maps.Copy(fileOutputDirs, s.fileOutputDirs)
		inputFiles := s.inputFiles
		baseOutDir := s.baseOutDir
		fileErrors := s.fileErrors
		completedFiles := s.completedFiles
		s.mu.RUnlock()

		log.Printf("[Progress] Local mode - resolved fileID %s to path: %s", fileID, filePath)

		// Get output directory for this file
		if dir, exists := fileOutputDirs[filePath]; exists {
			outputDir = dir
			log.Printf("[Progress] Found cached output dir: %s", outputDir)
		} else {
			log.Printf("[Progress] No cached output dir, calculating...")
			// Calculate the subdirectory
			// For uploaded files, always use a subdirectory based on filename
			// Check if this is an uploaded file (in uploads directory)
			if strings.Contains(filePath, "/uploads/") || strings.Contains(filePath, "\\uploads\\") {
				// Uploaded file - always use subdirectory
				baseName := filepath.Base(filePath)
				dirName := strings.TrimSuffix(baseName, filepath.Ext(baseName))
				outputDir = filepath.Join(baseOutDir, dirName)
			} else if len(inputFiles) == 1 {
				// Single file mode (not uploaded) - use baseOutDir directly
				outputDir = baseOutDir
			} else {
				// Multi-file mode - calculate subdirectory
				baseName := filepath.Base(filePath)
				dirName := baseName
				for _, ext := range []string{".pcap", ".pcapng", ".cap", ".dmp"} {
					if before, ok := strings.CutSuffix(dirName, ext); ok {
						dirName = before
						break
					}
				}
				outputDir = filepath.Join(baseOutDir, dirName)
			}
		}

		// Determine status
		if ferr, hasError := fileErrors[filePath]; hasError {
			status = "failed"
			errorMessage = ferr.Error
		} else if completedFiles[filePath] {
			status = "completed"
		} else {
			status = "processing"
		}
	}

	// Read progress from netcap.log
	progress := s.readProgressFromLog(outputDir)

	// Build response
	response := ProgressInfo{
		SessionID:       fileID,
		Status:          status,
		ProgressPercent: progress,
		ErrorMessage:    errorMessage,
	}

	// Set message based on status
	switch status {
	case "completed":
		response.Message = "Analysis completed"
		response.ProgressPercent = 100
	case "failed":
		response.Message = "Analysis failed"
	case "queued":
		response.Message = "Queued for analysis"
		response.ProgressPercent = 0
	case "processing":
		if progress > 0 {
			response.Message = fmt.Sprintf("Processing... %.1f%%", progress)
		} else {
			response.Message = "Processing..."
		}
	default:
		response.Message = "Unknown status"
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(response); err != nil {
		log.Printf("[WebUI] Failed to encode progress response: %v", err)
		http.Error(w, fmt.Sprintf("Failed to encode response: %v", err), http.StatusInternalServerError)
	}
}

// readProgressFromLog reads the netcap.log file and extracts the latest progress percentage
func (s *Server) readProgressFromLog(outputDir string) float64 {
	if outputDir == "" {
		return 0
	}

	logPath := filepath.Join(outputDir, "netcap.log")

	// Check if log file exists
	if _, err := os.Stat(logPath); os.IsNotExist(err) {
		return 0
	}

	// Open and read the log file
	file, err := os.Open(logPath)
	if err != nil {
		log.Printf("[WebUI] Failed to open netcap.log: %v", err)
		return 0
	}
	defer file.Close()

	// Read file line by line and find the last progress line
	var lastProgress float64
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()

		// Look for progress lines (format: "progress: XX%")
		matches := progressRegex.FindStringSubmatch(line)
		if len(matches) >= 2 {
			// Parse the percentage
			var progress float64
			if _, err := fmt.Sscanf(matches[1], "%f", &progress); err == nil {
				lastProgress = progress
			}
		}
	}

	if err := scanner.Err(); err != nil && err != io.EOF {
		log.Printf("[WebUI] Error reading netcap.log: %v", err)
	}

	return lastProgress
}
