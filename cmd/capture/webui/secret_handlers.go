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
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"

	"github.com/dreadl0ck/netcap/defaults"
	"github.com/dreadl0ck/netcap/internal/netio"
	"github.com/dreadl0ck/netcap/types"
)

// SecretSummary represents a captured credential
type SecretSummary struct {
	Timestamp int64  `json:"timestamp"`
	Service   string `json:"service"`
	Flow      string `json:"flow"`
	User      string `json:"user"`
	Password  string `json:"password"`
	Kind      string `json:"kind,omitempty"`
	Value     string `json:"value,omitempty"`
	Parameter string `json:"parameter,omitempty"`
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
	Secrets    []SecretSummary `json:"secrets"`
	TotalCount int             `json:"totalCount"`
}

var secretInventorySlots = make(chan struct{}, 2)

// handleSecrets returns list of all credentials
func (s *Server) handleSecrets(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	selection, ok := s.selectedCapture(w, r)
	if !ok {
		return
	}
	outDir := selection.OutputDir

	var budget *inventoryAuditBudget
	if r.URL.Query().Get("mcpPage") == "true" {
		if r.Context().Err() != nil {
			return
		}
		select {
		case secretInventorySlots <- struct{}{}:
			defer func() { <-secretInventorySlots }()
		default:
			RespondJSON(w, http.StatusTooManyRequests, map[string]string{"error": "secret inventory is busy"})
			return
		}
		budget = &inventoryAuditBudget{ctx: r.Context(), stored: maxCollectionPageScanBytes, bodies: maxCollectionPageScanBytes, rows: maxCollectionPageRows}
	}
	credentials, err := readSecretInventory(outDir, budget)
	if err != nil {
		if r.Context().Err() != nil {
			return
		}
		if errors.Is(err, errInventoryAuditLimit) {
			RespondJSON(w, http.StatusRequestEntityTooLarge, map[string]string{"error": err.Error()})
			return
		}
		log.Print("[WebUI] Failed to read secret inventory")
		RespondJSON(w, http.StatusInternalServerError, map[string]string{"error": "Failed to read secret inventory"})
		return
	}
	if respondCollectionPage(w, r, credentials, "secrets") {
		return
	}
	RespondJSON(w, http.StatusOK, SecretsResponse{Secrets: credentials, TotalCount: len(credentials)})
}

func readSecretInventory(outDir string, budget *inventoryAuditBudget) ([]SecretSummary, error) {
	path := filepath.Join(outDir, "Secret"+defaults.FileExtension)
	reader, err := budget.open(path+".gz", types.Type_NC_Secret)
	if errors.Is(err, os.ErrNotExist) {
		reader, err = budget.open(path, types.Type_NC_Secret)
	}
	credentials := []SecretSummary{}
	if errors.Is(err, os.ErrNotExist) {
		return credentials, nil
	}
	if err != nil {
		return nil, err
	}
	defer reader.Close()
	for {
		record, err := budget.next(reader)
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		cred, ok := record.(*types.Secret)
		if !ok {
			return nil, fmt.Errorf("unexpected secret audit record %T", record)
		}

		// Skip credentials with empty username AND password - they provide no useful information
		if cred.User == "" && cred.Password == "" && cred.Value == "" && cred.Hash == "" {
			continue
		}

		credentials = append(credentials, SecretSummary{
			Timestamp: cred.Timestamp,
			Service:   cred.Service,
			Flow:      cred.Flow,
			User:      cred.User,
			Password:  cred.Password,
			Kind:      cred.Kind, Value: cred.Value, Parameter: cred.Parameter,
			Notes: cred.Notes,
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
	}
	return credentials, nil
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
	Events      []AuthActivityEvent `json:"events"`
	TotalCount  int                 `json:"totalCount"`
	Coverage    map[string]string   `json:"coverage,omitempty"`
	Limitations []string            `json:"limitations,omitempty"`
}

// handleAuthActivity returns a unified authentication activity timeline
// merging Credentials, TACACS+, and Kerberos records
func (s *Server) handleAuthActivity(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	selection, err := s.resolveCaptureSelection(r)
	if err != nil {
		writeSelectionError(w, err)
		return
	}
	outDir := selection.OutputDir

	if outDir == "" {
		RespondJSON(w, http.StatusOK, AuthActivityResponse{Events: []AuthActivityEvent{}})
		return
	}

	var events []AuthActivityEvent
	coverage := map[string]string{"TACACS": "unavailable", "Kerberos": "unavailable", "Secret": "unavailable"}
	eventBytes := 0
	keepEvent := func(event AuthActivityEvent) bool {
		eventBytes += 512 + len(event.Protocol) + len(event.User) + len(event.Service) + len(event.Action) + len(event.Status) + len(event.SrcIP) + len(event.DstIP) + len(event.Details)
		if eventBytes > 8<<20 {
			return false
		}
		events = append(events, event)
		return true
	}
	scanned := 0

	// Load TACACS+ records
	tacacsFile := filepath.Join(outDir, "TACACS"+defaults.FileExtension+".gz")
	if _, err := os.Stat(tacacsFile); err == nil {
		if reader, err := netio.Open(tacacsFile, defaults.BufferSize); err == nil {
			defer reader.Close()
			coverage["TACACS"] = "invalid"
			if header, err := reader.ReadHeader(); err == nil && header.Type == types.Type_NC_TACACS {
				coverage["TACACS"] = "available"
				var rec types.TACACS
				for {
					scanned++
					if scanned > 100000 || r.Context().Err() != nil {
						http.Error(w, "authentication activity scan budget exceeded or canceled", 422)
						return
					}
					if err := reader.Next(&rec); err != nil {
						if err != io.EOF {
							coverage["TACACS"] = "unreadable"
						}
						break
					}
					if !keepEvent(AuthActivityEvent{
						Timestamp: rec.Timestamp,
						Protocol:  "TACACS+",
						User:      rec.User,
						Service:   rec.Service,
						Action:    rec.Action,
						Status:    rec.StatusName,
						SrcIP:     rec.SrcIP,
						DstIP:     rec.DstIP,
						Details:   fmt.Sprintf("Type=%s Seq=%d Session=%d", rec.TypeName, rec.SequenceNumber, rec.SessionID),
					}) {
						http.Error(w, "authentication event memory budget exceeded; use scoped audit-record queries", 422)
						return
					}
				}
			}
		}
	}

	// Load Kerberos records
	kerbFile := filepath.Join(outDir, "Kerberos"+defaults.FileExtension+".gz")
	if _, err := os.Stat(kerbFile); err == nil {
		if reader, err := netio.Open(kerbFile, defaults.BufferSize); err == nil {
			defer reader.Close()
			coverage["Kerberos"] = "invalid"
			if header, err := reader.ReadHeader(); err == nil && header.Type == types.Type_NC_Kerberos {
				coverage["Kerberos"] = "available"
				var rec types.Kerberos
				for {
					scanned++
					if scanned > 100000 || r.Context().Err() != nil {
						http.Error(w, "authentication activity scan budget exceeded or canceled", 422)
						return
					}
					if err := reader.Next(&rec); err != nil {
						if err != io.EOF {
							coverage["Kerberos"] = "unreadable"
						}
						break
					}
					status := rec.MessageType
					if rec.ErrorCode != 0 {
						status = fmt.Sprintf("%s (error %d: %s)", rec.MessageType, rec.ErrorCode, rec.ErrorMessage)
					}
					if !keepEvent(AuthActivityEvent{
						Timestamp: rec.Timestamp,
						Protocol:  "Kerberos",
						User:      rec.ClientName,
						Service:   rec.ServerName,
						Action:    rec.MessageType,
						Status:    status,
						SrcIP:     rec.SrcIP,
						DstIP:     rec.DstIP,
						Details:   fmt.Sprintf("Realm=%s Etype=%s", rec.Realm, rec.EncryptionTypeName),
					}) {
						http.Error(w, "authentication event memory budget exceeded; use scoped audit-record queries", 422)
						return
					}
				}
			}
		}
	}

	// Load Credentials with auth results
	credFile := filepath.Join(outDir, "Secret"+defaults.FileExtension+".gz")
	if _, err := os.Stat(credFile); err == nil {
		if reader, err := netio.Open(credFile, defaults.BufferSize); err == nil {
			defer reader.Close()
			coverage["Secret"] = "invalid"
			if header, err := reader.ReadHeader(); err == nil && header.Type == types.Type_NC_Secret {
				coverage["Secret"] = "available"
				var rec types.Secret
				for {
					scanned++
					if scanned > 100000 || r.Context().Err() != nil {
						http.Error(w, "authentication activity scan budget exceeded or canceled", 422)
						return
					}
					if err := reader.Next(&rec); err != nil {
						if err != io.EOF {
							coverage["Secret"] = "unreadable"
						}
						break
					}
					if rec.User == "" && rec.Password == "" && rec.Value == "" && rec.Hash == "" {
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
					if !keepEvent(AuthActivityEvent{
						Timestamp: rec.Timestamp,
						Protocol:  rec.Service,
						User:      rec.User,
						Service:   rec.Service,
						Action:    "credential-capture",
						Status:    status,
						SrcIP:     "",
						DstIP:     "",
						Details:   fmt.Sprintf("Flow=%s", rec.Flow),
					}) {
						http.Error(w, "authentication event memory budget exceeded; use scoped audit-record queries", 422)
						return
					}
				}
			}
		}
	}

	total := len(events)
	offset, limit := 0, 500
	if r.URL.Query().Has("offset") {
		offset, err = strconv.Atoi(r.URL.Query().Get("offset"))
		if err != nil || offset < 0 || offset > 100000 {
			http.Error(w, "invalid event offset", 400)
			return
		}
	}
	if r.URL.Query().Has("limit") {
		limit, err = strconv.Atoi(r.URL.Query().Get("limit"))
		if err != nil || limit < 1 || limit > 500 {
			http.Error(w, "event limit must be 1..500", 400)
			return
		}
	}
	offset = min(offset, total)
	end := min(offset+limit, total)
	RespondJSON(w, http.StatusOK, AuthActivityResponse{
		Events:      events[offset:end],
		TotalCount:  total,
		Coverage:    coverage,
		Limitations: []string{"Retained source observations only; unavailable, invalid or unreadable sources do not establish absence of authentication."},
	})
}

// handleSecretsByService generates a chart showing credentials grouped by service
func (s *Server) handleSecretsByService(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Determine the output directory
	outDir, _ := s.resolveOutDirFromRequest(r)

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
	outDir, _ := s.resolveOutDirFromRequest(r)

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
	outDir, _ := s.resolveOutDirFromRequest(r)

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
	outDir, _ := s.resolveOutDirFromRequest(r)

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
