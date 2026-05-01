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

// SecretSummary represents a captured credential
type SecretSummary struct {
	Timestamp int64  `json:"timestamp"`
	Service   string `json:"service"`
	Flow      string `json:"flow"`
	User      string `json:"user"`
	Password  string `json:"password"`
	Notes     string `json:"notes"`
	// Hash-based credentials
	Hash          string `json:"hash"`
	HashType      string `json:"hashType"`
	Domain        string `json:"domain"`
	Realm         string `json:"realm"`
	Challenge     string `json:"challenge"`
	ServiceName   string `json:"serviceName"`
	Etype         int32  `json:"etype"`
	HashcatFormat string `json:"hashcatFormat"`
	// HTTP Digest specific
	Method string `json:"method"`
	Nonce  string `json:"nonce"`
	Uri    string `json:"uri"`
	Qop    string `json:"qop"`
	Nc     string `json:"nc"`
	Cnonce string `json:"cnonce"`
	// NTLM specific
	Workstation string `json:"workstation"`
	LmHash      string `json:"lmHash"`
	NtHash      string `json:"ntHash"`
	// Authentication result tracking
	AuthSuccess    bool  `json:"authSuccess"`
	AuthSuccessSet bool  `json:"authSuccessSet"`
	AuthAttempts   int32 `json:"authAttempts"`
	// RADIUS specific
	MacAddress    string `json:"macAddress"`
	FramedAddress string `json:"framedAddress"`
	ConnectInfo   string `json:"connectInfo"`
	ReplyMessage  string `json:"replyMessage"`
	// SOCKS specific
	SocksVersion int32  `json:"socksVersion"`
	SocksStatus  string `json:"socksStatus"`
	// SIP specific
	SipMethod string `json:"sipMethod"`
	SipCallId string `json:"sipCallId"`
	SipFrom   string `json:"sipFrom"`
	SipTo     string `json:"sipTo"`
	// Community ID for cross-tool correlation
	CommunityID string `json:"communityId"`
}

// SecretsResponse contains the list of credentials
type SecretsResponse struct {
	Secrets []SecretSummary `json:"secrets"`
	TotalCount  int                 `json:"totalCount"`
}

// handleSecrets returns list of all credentials
func (s *Server) handleSecrets(w http.ResponseWriter, r *http.Request) {
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
		RespondJSON(w, http.StatusOK, SecretsResponse{
			Secrets: []SecretSummary{},
			TotalCount:  0,
		})
		return
	}

	// Try to find Credentials audit file - try both compressed and uncompressed
	filePath := filepath.Join(outDir, "Secret"+defaults.FileExtension+".gz")
	filePathUncompressed := filepath.Join(outDir, "Secret"+defaults.FileExtension)

	// Check if compressed file exists
	if _, err := os.Stat(filePath); os.IsNotExist(err) {

		// Try uncompressed version
		if _, err := os.Stat(filePathUncompressed); os.IsNotExist(err) {

			RespondJSON(w, http.StatusOK, SecretsResponse{
				Secrets: []SecretSummary{},
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
	if fileInfo, err := os.Stat(filePath); err == nil {
		log.Printf("[Credentials] Opening credentials file (size: %d bytes)", fileInfo.Size())
	}

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
	var credentials []SecretSummary
	var cred types.Secret
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

		credentials = append(credentials, SecretSummary{
			Timestamp: cred.Timestamp,
			Service:   cred.Service,
			Flow:      cred.Flow,
			User:      cred.User,
			Password:  cred.Password,
			Notes:     cred.Notes,
			// Hash-based credentials
			Hash:          cred.Hash,
			HashType:      cred.HashType,
			Domain:        cred.Domain,
			Realm:         cred.Realm,
			Challenge:     cred.Challenge,
			ServiceName:   cred.ServiceName,
			Etype:         cred.Etype,
			HashcatFormat: cred.HashcatFormat,
			// HTTP Digest specific
			Method: cred.Method,
			Nonce:  cred.Nonce,
			Uri:    cred.Uri,
			Qop:    cred.Qop,
			Nc:     cred.Nc,
			Cnonce: cred.Cnonce,
			// NTLM specific
			Workstation: cred.Workstation,
			LmHash:      cred.LmHash,
			NtHash:      cred.NtHash,
			// Authentication result tracking
			AuthSuccess:    cred.AuthSuccess,
			AuthSuccessSet: cred.AuthSuccessSet,
			AuthAttempts:   cred.AuthAttempts,
			// RADIUS specific
			MacAddress:    cred.MacAddress,
			FramedAddress: cred.FramedAddress,
			ConnectInfo:   cred.ConnectInfo,
			ReplyMessage:  cred.ReplyMessage,
			// SOCKS specific
			SocksVersion: cred.SocksVersion,
			SocksStatus:  cred.SocksStatus,
			// SIP specific
			SipMethod: cred.SipMethod,
			SipCallId: cred.SipCallId,
			SipFrom:   cred.SipFrom,
			SipTo:     cred.SipTo,
			// Community ID for cross-tool correlation
			CommunityID: cred.CommunityID,
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

	RespondJSON(w, http.StatusOK, SecretsResponse{
		Secrets: credentials,
		TotalCount:  len(credentials),
	})
}

// AuthActivityEvent represents a unified authentication event from any protocol
type AuthActivityEvent struct {
	Timestamp int64  `json:"timestamp"`
	Protocol  string `json:"protocol"` // "Credentials", "TACACS", "Kerberos"
	User      string `json:"user"`
	Service   string `json:"service"`
	Action    string `json:"action"`
	Status    string `json:"status"`
	SrcIP     string `json:"srcIP"`
	DstIP     string `json:"dstIP"`
	Details   string `json:"details"`
}

// AuthActivityResponse contains all authentication events
type AuthActivityResponse struct {
	Events     []AuthActivityEvent `json:"events"`
	TotalCount int                 `json:"totalCount"`
}

// handleAuthActivity returns a unified authentication activity timeline
// merging Credentials, TACACS+, and Kerberos records
func (s *Server) handleAuthActivity(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	s.mu.RLock()
	outDir := s.outDir
	if s.isServiceMode && s.currentSession != "" && s.sessionManager != nil {
		if session, ok := s.sessionManager.GetSession(s.currentSession); ok {
			outDir = session.OutputDir
		}
	}
	s.mu.RUnlock()

	if outDir == "" {
		RespondJSON(w, http.StatusOK, AuthActivityResponse{Events: []AuthActivityEvent{}})
		return
	}

	var events []AuthActivityEvent

	// Load TACACS+ records
	tacacsFile := filepath.Join(outDir, "TACACS"+defaults.FileExtension+".gz")
	if _, err := os.Stat(tacacsFile); err == nil {
		if reader, err := netio.Open(tacacsFile, defaults.BufferSize); err == nil {
			defer reader.Close()
			if _, err := reader.ReadHeader(); err == nil {
				var rec types.TACACS
				for {
					if err := reader.Next(&rec); err != nil {
						break
					}
					events = append(events, AuthActivityEvent{
						Timestamp: rec.Timestamp,
						Protocol:  "TACACS+",
						User:      rec.User,
						Service:   rec.Service,
						Action:    rec.Action,
						Status:    rec.StatusName,
						SrcIP:     rec.SrcIP,
						DstIP:     rec.DstIP,
						Details:   fmt.Sprintf("Type=%s Seq=%d Session=%d", rec.TypeName, rec.SequenceNumber, rec.SessionID),
					})
				}
			}
		}
	}

	// Load Kerberos records
	kerbFile := filepath.Join(outDir, "Kerberos"+defaults.FileExtension+".gz")
	if _, err := os.Stat(kerbFile); err == nil {
		if reader, err := netio.Open(kerbFile, defaults.BufferSize); err == nil {
			defer reader.Close()
			if _, err := reader.ReadHeader(); err == nil {
				var rec types.Kerberos
				for {
					if err := reader.Next(&rec); err != nil {
						break
					}
					status := rec.MessageType
					if rec.ErrorCode != 0 {
						status = fmt.Sprintf("%s (error %d: %s)", rec.MessageType, rec.ErrorCode, rec.ErrorMessage)
					}
					events = append(events, AuthActivityEvent{
						Timestamp: rec.Timestamp,
						Protocol:  "Kerberos",
						User:      rec.ClientName,
						Service:   rec.ServerName,
						Action:    rec.MessageType,
						Status:    status,
						SrcIP:     rec.SrcIP,
						DstIP:     rec.DstIP,
						Details:   fmt.Sprintf("Realm=%s Etype=%s", rec.Realm, rec.EncryptionTypeName),
					})
				}
			}
		}
	}

	// Load Credentials with auth results
	credFile := filepath.Join(outDir, "Secret"+defaults.FileExtension+".gz")
	if _, err := os.Stat(credFile); err == nil {
		if reader, err := netio.Open(credFile, defaults.BufferSize); err == nil {
			defer reader.Close()
			if _, err := reader.ReadHeader(); err == nil {
				var rec types.Secret
				for {
					if err := reader.Next(&rec); err != nil {
						break
					}
					if rec.User == "" && rec.Password == "" {
						continue
					}
					status := "captured"
					if rec.AuthSuccessSet {
						if rec.AuthSuccess {
							status = "success"
						} else {
							status = "failure"
						}
					}
					events = append(events, AuthActivityEvent{
						Timestamp: rec.Timestamp,
						Protocol:  rec.Service,
						User:      rec.User,
						Service:   rec.Service,
						Action:    "credential-capture",
						Status:    status,
						SrcIP:     "",
						DstIP:     "",
						Details:   fmt.Sprintf("Flow=%s", rec.Flow),
					})
				}
			}
		}
	}

	RespondJSON(w, http.StatusOK, AuthActivityResponse{
		Events:     events,
		TotalCount: len(events),
	})
}

// handleSecretsByService generates a chart showing credentials grouped by service
func (s *Server) handleSecretsByService(w http.ResponseWriter, r *http.Request) {
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

	chart := generateSecretsByServiceChart(outDir, showLegend)
	html, err := injectFullHeightCSS(chart.Render)
	if err != nil {
		http.Error(w, "Failed to generate chart", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/html")
	w.Write(html)
}

// handleSecretsTimeline generates a timeline chart of credentials
func (s *Server) handleSecretsTimeline(w http.ResponseWriter, r *http.Request) {
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

	chart := generateSecretsTimelineChart(outDir, showLegend)
	html, err := injectFullHeightCSS(chart.Render)
	if err != nil {
		http.Error(w, "Failed to generate chart", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/html")
	w.Write(html)
}

// handleSecretsUsernames generates a chart showing top usernames
func (s *Server) handleSecretsUsernames(w http.ResponseWriter, r *http.Request) {
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

	chart := generateSecretsUsernamesChart(outDir, showLegend)
	html, err := injectFullHeightCSS(chart.Render)
	if err != nil {
		http.Error(w, "Failed to generate chart", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/html")
	w.Write(html)
}

// handleSecretsFlows generates a chart showing credentials by flow
func (s *Server) handleSecretsFlows(w http.ResponseWriter, r *http.Request) {
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

	chart := generateSecretsFlowsChart(outDir, showLegend)
	html, err := injectFullHeightCSS(chart.Render)
	if err != nil {
		http.Error(w, "Failed to generate chart", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/html")
	w.Write(html)
}
