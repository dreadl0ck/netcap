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
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/dreadl0ck/netcap/defaults"
	netio "github.com/dreadl0ck/netcap/io"
	"github.com/dreadl0ck/netcap/types"
)

// CredentialSummary represents a captured credential
type CredentialSummary struct {
	Timestamp int64  `json:"timestamp"`
	Service   string `json:"service"`
	Flow      string `json:"flow"`
	User      string `json:"user"`
	Password  string `json:"password"`
	Notes     string `json:"notes"`
}

// CredentialsResponse contains the list of credentials
type CredentialsResponse struct {
	Credentials []CredentialSummary `json:"credentials"`
	TotalCount  int                 `json:"totalCount"`
}

// handleCredentials returns list of all credentials
func (s *Server) handleCredentials(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Determine the output directory
	s.mu.RLock()
	outDir := s.outDir

	// In service mode, use the current session's output directory
	if s.isServiceMode && s.currentSession != "" && s.sessionManager != nil {
		if session, ok := s.sessionManager.GetSession(s.currentSession); ok {
			outDir = session.OutputDir
			log.Printf("[Credentials] Using session output dir: %s (session: %s)", outDir, s.currentSession)
		}
	}
	s.mu.RUnlock()

	log.Printf("[Credentials] API request - outDir: %s, isServiceMode: %v", outDir, s.isServiceMode)

	if outDir == "" {
		log.Printf("[Credentials] No output directory set, returning empty response")
		RespondJSON(w, http.StatusOK, CredentialsResponse{
			Credentials: []CredentialSummary{},
			TotalCount:  0,
		})
		return
	}

	// Try to find Credentials audit file - try both compressed and uncompressed
	filePath := filepath.Join(outDir, "Credentials"+defaults.FileExtension+".gz")
	filePathUncompressed := filepath.Join(outDir, "Credentials"+defaults.FileExtension)

	// Check if compressed file exists
	if _, err := os.Stat(filePath); os.IsNotExist(err) {

		// Try uncompressed version
		if _, err := os.Stat(filePathUncompressed); os.IsNotExist(err) {

			RespondJSON(w, http.StatusOK, CredentialsResponse{
				Credentials: []CredentialSummary{},
				TotalCount:  0,
			})
			return
		}
		// Use uncompressed file
		filePath = filePathUncompressed
		log.Printf("[Credentials] Using uncompressed file: %s", filePath)
	} else {
		log.Printf("[Credentials] Found compressed credentials file: %s", filePath)
	}

	// Get file size for logging
	fileInfo, _ := os.Stat(filePath)
	log.Printf("[Credentials] Opening credentials file (size: %d bytes)", fileInfo.Size())

	// Open the audit file
	reader, err := netio.Open(filePath, defaults.BufferSize)
	if err != nil {
		log.Printf("[Credentials] ERROR: Failed to open Credentials audit file: %v", err)
		RespondJSON(w, http.StatusInternalServerError, map[string]string{
			"error": fmt.Sprintf("Failed to open credentials file: %v", err),
		})
		return
	}
	defer reader.Close()

	log.Printf("[Credentials] Successfully opened credentials file")

	// IMPORTANT: Read the netcap file header first!
	header, err := reader.ReadHeader()
	if err != nil {
		log.Printf("[Credentials] ERROR: Failed to read file header: %v", err)
		RespondJSON(w, http.StatusInternalServerError, map[string]string{
			"error": fmt.Sprintf("Failed to read file header: %v", err),
		})
		return
	}
	log.Printf("[Credentials] File header read successfully (type: %s, version: %s)", header.Type, header.Version)
	log.Printf("[Credentials] Reading credential records...")

	// Read all credentials
	var credentials []CredentialSummary
	var cred types.Credentials
	recordCount := 0

	for {
		err := reader.Next(&cred)
		if err != nil {
			if err != io.EOF {
				log.Printf("[Credentials] ERROR: Error reading Credentials audit record (after %d records): %v", recordCount, err)
				// Check if this is a protobuf schema mismatch error
				if strings.Contains(err.Error(), "wrong wireType") || strings.Contains(err.Error(), "proto:") {
					log.Printf("[Credentials] This appears to be a protobuf schema version mismatch.")
					log.Printf("[Credentials] The audit file was created with an older version of netcap.")
					log.Printf("[Credentials] Solution: Re-analyze the PCAP file to regenerate audit records with the current schema.")
				}
			}
			break
		}

		recordCount++

		// Skip credentials with empty username AND password - they provide no useful information
		if cred.User == "" && cred.Password == "" {
			continue
		}

		credentials = append(credentials, CredentialSummary{
			Timestamp: cred.Timestamp,
			Service:   cred.Service,
			Flow:      cred.Flow,
			User:      cred.User,
			Password:  cred.Password,
			Notes:     cred.Notes,
		})

		// Log first few credentials for debugging
		if recordCount <= 3 {
			log.Printf("[Credentials] Record #%d: service=%s, user=%s, flow=%s",
				recordCount, cred.Service, cred.User, cred.Flow)
		}
	}

	log.Printf("[Credentials] Read %d credential records from file", len(credentials))
	log.Printf("[Credentials] Returning response with %d credentials (totalCount: %d)",
		len(credentials), len(credentials))

	// Log summary of first few credentials for verification
	if len(credentials) > 0 {
		log.Printf("[Credentials] Sample credentials being returned:")
		for i := 0; i < len(credentials) && i < 3; i++ {
			log.Printf("[Credentials]   #%d: service=%s, user=%s, timestamp=%d",
				i+1, credentials[i].Service, credentials[i].User, credentials[i].Timestamp)
		}
	}

	RespondJSON(w, http.StatusOK, CredentialsResponse{
		Credentials: credentials,
		TotalCount:  len(credentials),
	})
}

// handleCredentialsByService generates a chart showing credentials grouped by service
func (s *Server) handleCredentialsByService(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Determine the output directory
	s.mu.RLock()
	outDir := s.outDir

	// In service mode, use the current session's output directory
	if s.isServiceMode && s.currentSession != "" && s.sessionManager != nil {
		if session, ok := s.sessionManager.GetSession(s.currentSession); ok {
			outDir = session.OutputDir
		}
	}
	s.mu.RUnlock()

	if outDir == "" {
		http.Error(w, "No output directory set", http.StatusServiceUnavailable)
		return
	}

	// Parse showLegend parameter (default to false)
	showLegendStr := r.URL.Query().Get("showLegend")
	showLegend := showLegendStr == "true"

	chart := generateCredentialsByServiceChart(outDir, showLegend)
	html, err := injectFullHeightCSS(chart.Render)
	if err != nil {
		http.Error(w, "Failed to generate chart", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/html")
	w.Write(html)
}

// handleCredentialsTimeline generates a timeline chart of credentials
func (s *Server) handleCredentialsTimeline(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Determine the output directory
	s.mu.RLock()
	outDir := s.outDir

	// In service mode, use the current session's output directory
	if s.isServiceMode && s.currentSession != "" && s.sessionManager != nil {
		if session, ok := s.sessionManager.GetSession(s.currentSession); ok {
			outDir = session.OutputDir
		}
	}
	s.mu.RUnlock()

	if outDir == "" {
		http.Error(w, "No output directory set", http.StatusServiceUnavailable)
		return
	}

	// Parse showLegend parameter (default to false)
	showLegendStr := r.URL.Query().Get("showLegend")
	showLegend := showLegendStr == "true"

	chart := generateCredentialsTimelineChart(outDir, showLegend)
	html, err := injectFullHeightCSS(chart.Render)
	if err != nil {
		http.Error(w, "Failed to generate chart", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/html")
	w.Write(html)
}

// handleCredentialsUsernames generates a chart showing top usernames
func (s *Server) handleCredentialsUsernames(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Determine the output directory
	s.mu.RLock()
	outDir := s.outDir

	// In service mode, use the current session's output directory
	if s.isServiceMode && s.currentSession != "" && s.sessionManager != nil {
		if session, ok := s.sessionManager.GetSession(s.currentSession); ok {
			outDir = session.OutputDir
		}
	}
	s.mu.RUnlock()

	if outDir == "" {
		http.Error(w, "No output directory set", http.StatusServiceUnavailable)
		return
	}

	// Parse showLegend parameter (default to false)
	showLegendStr := r.URL.Query().Get("showLegend")
	showLegend := showLegendStr == "true"

	chart := generateCredentialsUsernamesChart(outDir, showLegend)
	html, err := injectFullHeightCSS(chart.Render)
	if err != nil {
		http.Error(w, "Failed to generate chart", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/html")
	w.Write(html)
}

// handleCredentialsFlows generates a chart showing credentials by flow
func (s *Server) handleCredentialsFlows(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Determine the output directory
	s.mu.RLock()
	outDir := s.outDir

	// In service mode, use the current session's output directory
	if s.isServiceMode && s.currentSession != "" && s.sessionManager != nil {
		if session, ok := s.sessionManager.GetSession(s.currentSession); ok {
			outDir = session.OutputDir
		}
	}
	s.mu.RUnlock()

	if outDir == "" {
		http.Error(w, "No output directory set", http.StatusServiceUnavailable)
		return
	}

	// Parse showLegend parameter (default to true for pie charts)
	showLegendStr := r.URL.Query().Get("showLegend")
	showLegend := showLegendStr != "false"

	chart := generateCredentialsFlowsChart(outDir, showLegend)
	html, err := injectFullHeightCSS(chart.Render)
	if err != nil {
		http.Error(w, "Failed to generate chart", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/html")
	w.Write(html)
}
