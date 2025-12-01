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
	"encoding/json"
	"fmt"
	"io"
	stdio "io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/dreadl0ck/netcap/types"
)

// HTTPSummary represents HTTP request/response information
type HTTPSummary struct {
	Timestamp              int64             `json:"timestamp"`
	Proto                  string            `json:"proto"`
	Method                 string            `json:"method"`
	Host                   string            `json:"host"`
	URL                    string            `json:"url"`
	UserAgent              string            `json:"userAgent"`
	Referer                string            `json:"referer"`
	ReqContentLength       int32             `json:"reqContentLength"`
	ResContentLength       int32             `json:"resContentLength"`
	ContentType            string            `json:"contentType"`
	StatusCode             int32             `json:"statusCode"`
	SrcIP                  string            `json:"srcIP"`
	DstIP                  string            `json:"dstIP"`
	SrcPort                int32             `json:"srcPort"`
	DstPort                int32             `json:"dstPort"`
	Flow                   string            `json:"flow"`
	ReqContentEncoding     string            `json:"reqContentEncoding"`
	ResContentEncoding     string            `json:"resContentEncoding"`
	ServerName             string            `json:"serverName"`
	ResContentType         string            `json:"resContentType"`
	ContentTypeDetected    string            `json:"contentTypeDetected"`
	ResContentTypeDetected string            `json:"resContentTypeDetected"`
	DoneAfter              int64             `json:"doneAfter"`
	DNSDoneAfter           int64             `json:"dnsDoneAfter"`
	FirstByteAfter         int64             `json:"firstByteAfter"`
	TLSDoneAfter           int64             `json:"tlsDoneAfter"`
	RequestHeader          map[string]string `json:"requestHeader"`
	ResponseHeader         map[string]string `json:"responseHeader"`
	Parameters             map[string]string `json:"parameters"`
	// Security headers
	StrictTransportSecurity  string   `json:"strictTransportSecurity"`
	ContentSecurityPolicy    string   `json:"contentSecurityPolicy"`
	XContentTypeOptions      string   `json:"xContentTypeOptions"`
	XFrameOptions            string   `json:"xFrameOptions"`
	XXSSProtection           string   `json:"xXSSProtection"`
	ReferrerPolicy           string   `json:"referrerPolicy"`
	AccessControlAllowOrigin string   `json:"accessControlAllowOrigin"`
	HasServerTiming          bool     `json:"hasServerTiming"`
	// Authentication and server info
	AuthorizationType string `json:"authorizationType"`
	XForwardedFor     string `json:"xForwardedFor"`
	XRealIP           string `json:"xRealIP"`
	Server            string `json:"server"`
	XPoweredBy        string `json:"xPoweredBy"`
	// JA4H fingerprinting
	Ja4h            string `json:"ja4h"`
	Ja4hDescription string `json:"ja4hDescription"`
	// Community ID for cross-tool correlation
	CommunityID     string `json:"communityId"`
}

// HTTPResponse contains the list of HTTP records
type HTTPResponse struct {
	HTTP       []HTTPSummary `json:"http"`
	TotalCount int           `json:"totalCount"`
}

// handleHTTP returns a list of all HTTP records
func (s *Server) handleHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

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

	httpRecords, err := readHTTP(outDir)
	if err != nil {
		log.Printf("[WebUI] Failed to read HTTP records: %v", err)
		http.Error(w, "Failed to read HTTP records", http.StatusInternalServerError)
		return
	}

	response := HTTPResponse{
		HTTP:       httpRecords,
		TotalCount: len(httpRecords),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// readHTTP reads HTTP records from the output directory
func readHTTP(outDir string) ([]HTTPSummary, error) {
	filePath := filepath.Join(outDir, "HTTP.ncap.gz")

	// Check if file exists
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		log.Printf("[WebUI] HTTP file not found: %s", filePath)
		return []HTTPSummary{}, nil
	}

	// Read HTTP records
	reader, err := NewAuditRecordReader(filePath)
	if err != nil {
		return nil, err
	}
	defer reader.Close()

	// Read header
	_, err = reader.ReadHeader()
	if err != nil {
		return nil, err
	}

	httpRecords := make([]HTTPSummary, 0)

	// Read all records
	for {
		record, err := reader.NextRecord()
		if err != nil {
			if err == io.EOF {
				break
			}
			log.Printf("[WebUI] Error reading HTTP record: %v", err)
			continue
		}

		// Type assert to HTTP
		httpRec, ok := record.(*types.HTTP)
		if !ok {
			continue
		}

		httpRecords = append(httpRecords, HTTPSummary{
			Timestamp:              httpRec.Timestamp,
			Proto:                  httpRec.Proto,
			Method:                 httpRec.Method,
			Host:                   httpRec.Host,
			URL:                    httpRec.URL,
			UserAgent:              httpRec.UserAgent,
			Referer:                httpRec.Referer,
			ReqContentLength:       httpRec.ReqContentLength,
			ResContentLength:       httpRec.ResContentLength,
			ContentType:            httpRec.ContentType,
			StatusCode:             httpRec.StatusCode,
			SrcIP:                  httpRec.SrcIP,
			DstIP:                  httpRec.DstIP,
			SrcPort:                httpRec.SrcPort,
			DstPort:                httpRec.DstPort,
			Flow:                   httpRec.Flow,
			ReqContentEncoding:     httpRec.ReqContentEncoding,
			ResContentEncoding:     httpRec.ResContentEncoding,
			ServerName:             httpRec.ServerName,
			ResContentType:         httpRec.ResContentType,
			ContentTypeDetected:    httpRec.ContentTypeDetected,
			ResContentTypeDetected: httpRec.ResContentTypeDetected,
			DoneAfter:              httpRec.DoneAfter,
			DNSDoneAfter:           httpRec.DNSDoneAfter,
			FirstByteAfter:         httpRec.FirstByteAfter,
			TLSDoneAfter:           httpRec.TLSDoneAfter,
			RequestHeader:          httpRec.RequestHeader,
			ResponseHeader:         httpRec.ResponseHeader,
			Parameters:             httpRec.Parameters,
			// Security headers
			StrictTransportSecurity:  httpRec.StrictTransportSecurity,
			ContentSecurityPolicy:    httpRec.ContentSecurityPolicy,
			XContentTypeOptions:      httpRec.XContentTypeOptions,
			XFrameOptions:            httpRec.XFrameOptions,
			XXSSProtection:           httpRec.XXSSProtection,
			ReferrerPolicy:           httpRec.ReferrerPolicy,
			AccessControlAllowOrigin: httpRec.AccessControlAllowOrigin,
			HasServerTiming:          httpRec.HasServerTiming,
			// Authentication and server info
			AuthorizationType: httpRec.AuthorizationType,
			XForwardedFor:     httpRec.XForwardedFor,
			XRealIP:           httpRec.XRealIP,
			Server:            httpRec.Server,
			XPoweredBy:        httpRec.XPoweredBy,
			// JA4H fingerprinting
			Ja4h:            httpRec.Ja4H,
			Ja4hDescription: httpRec.Ja4HDescription,
			// Community ID for cross-tool correlation
			CommunityID:     httpRec.CommunityID,
		})
	}

	// Sort by timestamp descending
	sort.Slice(httpRecords, func(i, j int) bool {
		return httpRecords[i].Timestamp > httpRecords[j].Timestamp
	})

	return httpRecords, nil
}

// handleHTTPDownloadPCAP filters and downloads PCAP for HTTP traffic
func (s *Server) handleHTTPDownloadPCAP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Get query parameters
	srcIP := r.URL.Query().Get("srcIP")
	dstIP := r.URL.Query().Get("dstIP")

	if srcIP == "" || dstIP == "" {
		http.Error(w, "Missing required parameters", http.StatusBadRequest)
		return
	}

	s.mu.RLock()
	activeInputFile := s.activeInputFile

	// In service mode, use the current session's input file
	if s.isServiceMode && s.currentSession != "" && s.sessionManager != nil {
		if session, ok := s.sessionManager.GetSession(s.currentSession); ok {
			activeInputFile = session.InputFile
		}
	}
	s.mu.RUnlock()

	if activeInputFile == "" {
		http.Error(w, "No active input file", http.StatusServiceUnavailable)
		return
	}

	// Check if input file exists
	if _, err := os.Stat(activeInputFile); os.IsNotExist(err) {
		http.Error(w, "Input file not found", http.StatusNotFound)
		return
	}

	// Create BPF filter for HTTP traffic
	// Format: (host srcIP and host dstIP) and (tcp port 80 or tcp port 443 or tcp port 8080)
	bpf := fmt.Sprintf("(host %s and host %s) and (tcp port 80 or tcp port 443 or tcp port 8080)",
		srcIP, dstIP)

	// Create temporary output file
	tempDir := os.TempDir()
	outputFile := filepath.Join(tempDir, fmt.Sprintf("http_%s_%s.pcap",
		strings.ReplaceAll(srcIP, ".", "_"),
		strings.ReplaceAll(dstIP, ".", "_")))

	// Use tcpdump to filter the PCAP with a timeout
	tcpdumpCmd := "tcpdump"
	args := []string{"-r", activeInputFile, "-w", outputFile, bpf}

	log.Printf("[WebUI] Filtering HTTP PCAP: %s %v", tcpdumpCmd, args)

	// Create context with 30 second timeout
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, tcpdumpCmd, args...)
	output, err := cmd.CombinedOutput()

	log.Printf("[WebUI] tcpdump completed, err=%v, output=%s", err, string(output))

	if err != nil {
		log.Printf("[WebUI] tcpdump error: %v, output: %s", err, string(output))

		// Check for timeout
		if ctx.Err() == context.DeadlineExceeded {
			http.Error(w, "PCAP filtering timed out. The file may be too large or the filter too complex.", http.StatusRequestTimeout)
			return
		}

		// Check if tcpdump is not found
		if strings.Contains(err.Error(), "executable file not found") || strings.Contains(err.Error(), "not found") {
			http.Error(w, "tcpdump is not installed or not available in PATH. Please install tcpdump to use this feature.", http.StatusServiceUnavailable)
			return
		}

		// Check for permission errors
		if strings.Contains(string(output), "permission denied") || strings.Contains(string(output), "Operation not permitted") {
			http.Error(w, "Permission denied: tcpdump requires special capabilities. Please ensure the container has CAP_NET_RAW and CAP_NET_ADMIN capabilities.", http.StatusForbidden)
			return
		}

		http.Error(w, fmt.Sprintf("Failed to filter PCAP: %v - Output: %s", err, string(output)), http.StatusInternalServerError)
		return
	}

	// Check if output file was created
	fileInfo, err := os.Stat(outputFile)
	if err != nil {
		log.Printf("[WebUI] Output file not found: %v", err)
		http.Error(w, "Failed to create filtered PCAP", http.StatusInternalServerError)
		return
	}

	log.Printf("[WebUI] Filtered PCAP created: %s, size: %d bytes", outputFile, fileInfo.Size())

	// Check if file is empty (no packets matched)
	if fileInfo.Size() == 0 {
		log.Printf("[WebUI] No packets matched filter, removing empty file")
		os.Remove(outputFile)
		http.Error(w, "No packets found for this HTTP traffic", http.StatusNotFound)
		return
	}

	// PCAP files need at least 24 bytes for the header
	if fileInfo.Size() < 24 {
		log.Printf("[WebUI] File too small to be a valid PCAP (size: %d bytes)", fileInfo.Size())
		os.Remove(outputFile)
		http.Error(w, "Generated PCAP file is invalid", http.StatusInternalServerError)
		return
	}

	// Open the filtered PCAP file BEFORE defer cleanup
	file, err := os.Open(outputFile)
	if err != nil {
		log.Printf("[WebUI] Failed to open filtered PCAP: %v", err)
		os.Remove(outputFile)
		http.Error(w, "Failed to read filtered PCAP", http.StatusInternalServerError)
		return
	}

	// Read entire file into memory
	fileData, err := stdio.ReadAll(file)
	file.Close()

	if err != nil {
		log.Printf("[WebUI] Failed to read PCAP file: %v", err)
		os.Remove(outputFile)
		http.Error(w, "Failed to read filtered PCAP", http.StatusInternalServerError)
		return
	}

	// Clean up temp file immediately after reading
	os.Remove(outputFile)

	// Verify we read the expected amount
	if len(fileData) != int(fileInfo.Size()) {
		log.Printf("[WebUI] File size mismatch: expected %d, read %d", fileInfo.Size(), len(fileData))
		http.Error(w, "File read error", http.StatusInternalServerError)
		return
	}

	log.Printf("[WebUI] Read PCAP file successfully: %d bytes", len(fileData))

	// Set headers for download
	filename := fmt.Sprintf("http_%s_%s.pcap", srcIP, dstIP)
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s\"", filename))
	w.Header().Set("Content-Type", "application/vnd.tcpdump.pcap")
	w.Header().Set("Content-Length", fmt.Sprintf("%d", len(fileData)))
	w.Header().Set("Cache-Control", "no-cache")

	// Write the entire file in one go
	bytesWritten, err := w.Write(fileData)
	if err != nil {
		log.Printf("[WebUI] Failed to send PCAP file after %d bytes: %v", bytesWritten, err)
		return
	}

	log.Printf("[WebUI] Successfully sent PCAP file: %d bytes written", bytesWritten)
}
