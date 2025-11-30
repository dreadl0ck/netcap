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
	"encoding/base64"
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
	"strconv"
	"strings"
	"time"

	"github.com/dreadl0ck/netcap/types"
	"github.com/dreadl0ck/netcap/utils"
)

// ConnectionSummary represents aggregated information for a single connection
type ConnectionSummary struct {
	TimestampFirst       int64    `json:"timestampFirst"`
	TimestampLast        int64    `json:"timestampLast"`
	LinkProto            string   `json:"linkProto"`
	NetworkProto         string   `json:"networkProto"`
	TransportProto       string   `json:"transportProto"`
	ApplicationProto     string   `json:"applicationProto"`
	SrcMAC               string   `json:"srcMAC"`
	DstMAC               string   `json:"dstMAC"`
	SrcIP                string   `json:"srcIP"`
	SrcPort              string   `json:"srcPort"`
	DstIP                string   `json:"dstIP"`
	DstPort              string   `json:"dstPort"`
	TotalSize            int32    `json:"totalSize"`
	AppPayloadSize       int32    `json:"appPayloadSize"`
	NumPackets           int32    `json:"numPackets"`
	Duration             int64    `json:"duration"`
	BytesClientToServer  int64    `json:"bytesClientToServer"`
	BytesServerToClient  int64    `json:"bytesServerToClient"`
	NumFINFlags          int32    `json:"numFINFlags"`
	NumRSTFlags          int32    `json:"numRSTFlags"`
	NumACKFlags          int32    `json:"numACKFlags"`
	NumSYNFlags          int32    `json:"numSYNFlags"`
	NumURGFlags          int32    `json:"numURGFlags"`
	NumECEFlags          int32    `json:"numECEFlags"`
	NumPSHFlags          int32    `json:"numPSHFlags"`
	NumCWRFlags          int32    `json:"numCWRFlags"`
	NumNSFlags           int32    `json:"numNSFlags"`
	MeanWindowSize       int32    `json:"meanWindowSize"`
	Applications         []string `json:"applications"`
	ServerPortName       string   `json:"serverPortName"`
	DetectedProtocolName string   `json:"detectedProtocolName"`
	// JA4L timing fields
	TcpRttNanos       int64  `json:"tcpRttNanos"`
	TlsHandshakeNanos int64  `json:"tlsHandshakeNanos"`
	Ja4lClient        string `json:"ja4lClient"`
	Ja4lServer        string `json:"ja4lServer"`
	SynTtl            int32  `json:"synTtl"`
	// Security behavioral analysis fields
	PacketsClientToServer    int64   `json:"packetsClientToServer"`
	PacketsServerToClient    int64   `json:"packetsServerToClient"`
	ByteRatio                float64 `json:"byteRatio"`
	PacketRatio              float64 `json:"packetRatio"`
	AvgPacketSizeClientToServer int32 `json:"avgPacketSizeClientToServer"`
	AvgPacketSizeServerToClient int32 `json:"avgPacketSizeServerToClient"`
	IsExternal               bool    `json:"isExternal"`
	IsBroadcast              bool    `json:"isBroadcast"`
	IsMulticast              bool    `json:"isMulticast"`
	// TLS SNI
	Sni                      string  `json:"sni"`
}

// ConnectionsResponse contains the list of connections
type ConnectionsResponse struct {
	Connections []ConnectionSummary `json:"connections"`
	TotalCount  int                 `json:"totalCount"`
}

// handleConnections returns a list of all connections
// Supports query parameter ?layer=all|transport|network to filter by layer type
func (s *Server) handleConnections(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Get layer filter parameter (all, transport, network)
	layerFilter := r.URL.Query().Get("layer")
	if layerFilter == "" {
		layerFilter = "all"
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

	connections, err := readConnections(outDir)
	if err != nil {
		log.Printf("[WebUI] Failed to read connections: %v", err)
		http.Error(w, "Failed to read connections", http.StatusInternalServerError)
		return
	}

	// Apply layer filter
	filteredConnections := filterConnectionsByLayer(connections, layerFilter)

	response := ConnectionsResponse{
		Connections: filteredConnections,
		TotalCount:  len(filteredConnections),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// filterConnectionsByLayer filters connections based on the layer type
// - "all": returns all connections
// - "transport": returns only connections with transport layer (TCP/UDP)
// - "network": returns only connections without transport layer (ICMP, IGMP, etc.)
func filterConnectionsByLayer(connections []ConnectionSummary, layerFilter string) []ConnectionSummary {
	if layerFilter == "all" || layerFilter == "" {
		return connections
	}

	filtered := make([]ConnectionSummary, 0)
	for _, conn := range connections {
		hasTransport := conn.TransportProto != ""

		switch layerFilter {
		case "transport":
			if hasTransport {
				filtered = append(filtered, conn)
			}
		case "network":
			if !hasTransport {
				filtered = append(filtered, conn)
			}
		}
	}
	return filtered
}

// readConnections reads and aggregates Connection data from the output directory
func readConnections(outDir string) ([]ConnectionSummary, error) {
	filePath := filepath.Join(outDir, "Connection.ncap.gz")

	// Check if file exists
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		log.Printf("[WebUI] Connection file not found: %s", filePath)
		return []ConnectionSummary{}, nil
	}

	// Read Connection records
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

	connections := make([]ConnectionSummary, 0)

	// Read all records
	for {
		record, err := reader.NextRecord()
		if err != nil {
			if err == io.EOF {
				break
			}
			log.Printf("[WebUI] Error reading Connection record: %v", err)
			continue
		}

		// Type assert to Connection
		conn, ok := record.(*types.Connection)
		if !ok {
			continue
		}

		connections = append(connections, ConnectionSummary{
			TimestampFirst:       conn.TimestampFirst,
			TimestampLast:        conn.TimestampLast,
			LinkProto:            conn.LinkProto,
			NetworkProto:         conn.NetworkProto,
			TransportProto:       conn.TransportProto,
			ApplicationProto:     conn.ApplicationProto,
			SrcMAC:               conn.SrcMAC,
			DstMAC:               conn.DstMAC,
			SrcIP:                conn.SrcIP,
			SrcPort:              conn.SrcPort,
			DstIP:                conn.DstIP,
			DstPort:              conn.DstPort,
			TotalSize:            conn.TotalSize,
			AppPayloadSize:       conn.AppPayloadSize,
			NumPackets:           conn.NumPackets,
			Duration:             conn.Duration,
			BytesClientToServer:  conn.BytesClientToServer,
			BytesServerToClient:  conn.BytesServerToClient,
			NumFINFlags:          conn.NumFINFlags,
			NumRSTFlags:          conn.NumRSTFlags,
			NumACKFlags:          conn.NumACKFlags,
			NumSYNFlags:          conn.NumSYNFlags,
			NumURGFlags:          conn.NumURGFlags,
			NumECEFlags:          conn.NumECEFlags,
			NumPSHFlags:          conn.NumPSHFlags,
			NumCWRFlags:          conn.NumCWRFlags,
			NumNSFlags:           conn.NumNSFlags,
			MeanWindowSize:       conn.MeanWindowSize,
			Applications:         conn.Applications,
			ServerPortName:       conn.ServerPortName,
			DetectedProtocolName: conn.DetectedProtocolName,
			// JA4L timing fields
			TcpRttNanos:       conn.TcpRttNanos,
			TlsHandshakeNanos: conn.TlsHandshakeNanos,
			Ja4lClient:        conn.Ja4LClient,
			Ja4lServer:        conn.Ja4LServer,
			SynTtl:            conn.SynTtl,
			// Security behavioral analysis fields
			PacketsClientToServer:       conn.PacketsClientToServer,
			PacketsServerToClient:       conn.PacketsServerToClient,
			ByteRatio:                   conn.ByteRatio,
			PacketRatio:                 conn.PacketRatio,
			AvgPacketSizeClientToServer: conn.AvgPacketSizeClientToServer,
			AvgPacketSizeServerToClient: conn.AvgPacketSizeServerToClient,
			IsExternal:                  conn.IsExternal,
			IsBroadcast:                 conn.IsBroadcast,
			IsMulticast:                 conn.IsMulticast,
			// TLS SNI
			Sni:                         conn.Sni,
		})
	}

	// Sort by total size descending (or by timestamp - could be configurable)
	sort.Slice(connections, func(i, j int) bool {
		return connections[i].TotalSize > connections[j].TotalSize
	})

	return connections, nil
}

// ConversationDataResponse contains the raw conversation data for a connection
type ConversationDataResponse struct {
	SrcIP            string `json:"srcIP"`
	SrcPort          string `json:"srcPort"`
	DstIP            string `json:"dstIP"`
	DstPort          string `json:"dstPort"`
	Protocol         string `json:"protocol"`
	ConversationData string `json:"conversationData"` // base64-encoded chunk
	Exists           bool   `json:"exists"`
	FilePath         string `json:"filePath"`
	TotalSize        int64  `json:"totalSize"` // Total file size in bytes
	ChunkSize        int    `json:"chunkSize"` // Size of this chunk
	Offset           int64  `json:"offset"`    // Current offset
	HasMore          bool   `json:"hasMore"`   // Whether there's more data
	ErrorMessage     string `json:"errorMessage,omitempty"`
}

// handleConnectionConversation returns paginated raw conversation data for a specific connection
func (s *Server) handleConnectionConversation(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Get query parameters
	srcIP := r.URL.Query().Get("srcIP")
	srcPort := r.URL.Query().Get("srcPort")
	dstIP := r.URL.Query().Get("dstIP")
	dstPort := r.URL.Query().Get("dstPort")
	protocol := r.URL.Query().Get("protocol")
	offsetStr := r.URL.Query().Get("offset")
	limitStr := r.URL.Query().Get("limit")

	if srcIP == "" || srcPort == "" || dstIP == "" || dstPort == "" || protocol == "" {
		http.Error(w, "Missing required parameters", http.StatusBadRequest)
		return
	}

	// Parse pagination parameters
	offset := int64(0)
	if offsetStr != "" {
		if parsed, err := strconv.ParseInt(offsetStr, 10, 64); err == nil {
			offset = parsed
		}
	}

	// Default chunk size: 64KB (enough for ~4K rows of hex dump at 16 bytes per row, faster initial load)
	limit := 64 * 1024
	if limitStr != "" {
		if parsed, err := strconv.Atoi(limitStr); err == nil && parsed > 0 && parsed <= 10*1024*1024 { // Max 10MB per chunk
			limit = parsed
		}
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

	response := ConversationDataResponse{
		SrcIP:    srcIP,
		SrcPort:  srcPort,
		DstIP:    dstIP,
		DstPort:  dstPort,
		Protocol: protocol,
		Exists:   false,
		Offset:   offset,
	}

	// Try to find and read the conversation file chunk
	conversationData, filePath, totalSize, hasMore, err := readConversationFileChunk(
		outDir, srcIP, srcPort, dstIP, dstPort, protocol, offset, limit,
	)
	if err != nil {
		response.ErrorMessage = err.Error()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
		return
	}

	if conversationData != "" {
		response.Exists = true
		response.FilePath = filePath
		response.ConversationData = conversationData
		response.TotalSize = totalSize
		response.ChunkSize = len(conversationData)
		response.HasMore = hasMore
	} else {
		response.ErrorMessage = "Conversation file not found. Make sure stream reassembly was enabled during capture."
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// readConversationFileChunk reads a chunk of the conversation file
// Returns base64-encoded data, relative file path, total size, hasMore flag, and error
func readConversationFileChunk(outDir, srcIP, srcPort, dstIP, dstPort, protocol string, offset int64, limit int) (string, string, int64, bool, error) {
	// Find the conversation file path
	foundPath, err := findConversationFilePath(outDir, srcIP, srcPort, dstIP, dstPort, protocol)
	if err != nil {
		return "", "", 0, false, err
	}

	if foundPath == "" {
		return "", "", 0, false, nil // File not found
	}

	// Open the file
	file, err := os.Open(foundPath)
	if err != nil {
		return "", "", 0, false, err
	}
	defer file.Close()

	// Get file size
	fileInfo, err := file.Stat()
	if err != nil {
		return "", "", 0, false, err
	}
	totalSize := fileInfo.Size()

	// Check if offset is valid
	if offset >= totalSize {
		return "", "", totalSize, false, nil // No more data
	}

	// Seek to offset
	_, err = file.Seek(offset, 0)
	if err != nil {
		return "", "", 0, false, err
	}

	// Read chunk
	remaining := totalSize - offset
	readSize := int64(limit)
	if readSize > remaining {
		readSize = remaining
	}

	buffer := make([]byte, readSize)
	n, err := stdio.ReadFull(file, buffer)
	if err != nil && err != stdio.EOF && err != stdio.ErrUnexpectedEOF {
		return "", "", 0, false, err
	}

	// Check if there's more data
	hasMore := offset+int64(n) < totalSize

	// Convert to base64
	encoded := base64.StdEncoding.EncodeToString(buffer[:n])

	// Get relative path
	relPath, _ := filepath.Rel(outDir, foundPath)

	return encoded, relPath, totalSize, hasMore, nil
}

// findConversationFilePath searches for the conversation file and returns its path
func findConversationFilePath(outDir, srcIP, srcPort, dstIP, dstPort, protocol string) (string, error) {
	// Construct connection identifier using the same logic as the recorder
	// The file naming uses: srcIP-srcPort--dstIP-dstPort
	flowIdent := utils.CreateFlowIdent(srcIP, srcPort, dstIP, dstPort)
	connIdent := utils.CleanIdent(flowIdent)

	// Protocol directory (tcp or udp)
	protoDir := strings.ToLower(protocol)
	protoDirPath := filepath.Join(outDir, protoDir)

	// Check if protocol directory exists
	if _, err := os.Stat(protoDirPath); os.IsNotExist(err) {
		return "", nil // No conversation files saved
	}

	// Search for the file in all service subdirectories
	var foundPath string
	err := filepath.Walk(protoDirPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		// Check if filename matches the connection identifier
		// Note: CleanIdent produces dashes instead of colons
		if strings.Contains(info.Name(), connIdent) {
			foundPath = path
			return filepath.SkipDir // Stop walking once found
		}
		return nil
	})

	if err != nil {
		return "", err
	}

	if foundPath == "" {
		// Try reverse direction
		reverseFlowIdent := utils.CreateFlowIdent(dstIP, dstPort, srcIP, srcPort)
		reverseIdent := utils.CleanIdent(reverseFlowIdent)

		err = filepath.Walk(protoDirPath, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			if info.IsDir() {
				return nil
			}
			if strings.Contains(info.Name(), reverseIdent) {
				foundPath = path
				return filepath.SkipDir
			}
			return nil
		})
		if err != nil {
			return "", err
		}
	}

	return foundPath, nil
}

// handleConnectionDownloadPCAP filters and downloads PCAP for a specific connection
func (s *Server) handleConnectionDownloadPCAP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Get query parameters
	srcIP := r.URL.Query().Get("srcIP")
	srcPort := r.URL.Query().Get("srcPort")
	dstIP := r.URL.Query().Get("dstIP")
	dstPort := r.URL.Query().Get("dstPort")

	if srcIP == "" || srcPort == "" || dstIP == "" || dstPort == "" {
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

	// Create BPF filter for the connection
	// Format: (host srcIP and port srcPort) and (host dstIP and port dstPort)
	bpf := fmt.Sprintf("(host %s and port %s) and (host %s and port %s)",
		srcIP, srcPort, dstIP, dstPort)

	// Create temporary output file
	tempDir := os.TempDir()
	outputFile := filepath.Join(tempDir, fmt.Sprintf("connection_%s-%s_%s-%s.pcap",
		strings.ReplaceAll(srcIP, ".", "_"),
		srcPort,
		strings.ReplaceAll(dstIP, ".", "_"),
		dstPort))

	// Use tcpdump to filter the PCAP with a timeout
	// tcpdump -r input.pcap -w output.pcap "BPF_FILTER"
	tcpdumpCmd := "tcpdump"
	args := []string{"-r", activeInputFile, "-w", outputFile, bpf}

	log.Printf("[WebUI] Filtering PCAP: %s %v", tcpdumpCmd, args)

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
		http.Error(w, "No packets found for this connection", http.StatusNotFound)
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
		os.Remove(outputFile) // Clean up on error
		http.Error(w, "Failed to read filtered PCAP", http.StatusInternalServerError)
		return
	}

	// Read entire file into memory (files are small, typically < 1MB for single connections)
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
	filename := fmt.Sprintf("connection_%s-%s_%s-%s.pcap", srcIP, srcPort, dstIP, dstPort)
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s\"", filename))
	w.Header().Set("Content-Type", "application/vnd.tcpdump.pcap")
	w.Header().Set("Content-Length", fmt.Sprintf("%d", len(fileData)))
	w.Header().Set("Cache-Control", "no-cache")

	// Write the entire file in one go (better for HTTP/2)
	bytesWritten, err := w.Write(fileData)
	if err != nil {
		log.Printf("[WebUI] Failed to send PCAP file after %d bytes: %v", bytesWritten, err)
		return
	}

	log.Printf("[WebUI] Successfully sent PCAP file: %d bytes written", bytesWritten)
}

// NetworkConversationDataResponse contains the raw conversation data for a network-layer connection
type NetworkConversationDataResponse struct {
	SrcIP            string `json:"srcIP"`
	DstIP            string `json:"dstIP"`
	Protocol         string `json:"protocol"`
	ConversationData string `json:"conversationData"` // base64-encoded chunk
	Exists           bool   `json:"exists"`
	FilePath         string `json:"filePath"`
	TotalSize        int64  `json:"totalSize"` // Total file size in bytes
	ChunkSize        int    `json:"chunkSize"` // Size of this chunk
	Offset           int64  `json:"offset"`    // Current offset
	HasMore          bool   `json:"hasMore"`   // Whether there's more data
	ErrorMessage     string `json:"errorMessage,omitempty"`
}

// handleNetworkConversation returns paginated raw conversation data for a network-layer connection
// These are connections without transport layer (ICMP, IGMP, GRE, etc.)
func (s *Server) handleNetworkConversation(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Get query parameters
	srcIP := r.URL.Query().Get("srcIP")
	dstIP := r.URL.Query().Get("dstIP")
	protocol := r.URL.Query().Get("protocol") // e.g., "icmpv4", "icmpv6", "igmp", "gre"
	offsetStr := r.URL.Query().Get("offset")
	limitStr := r.URL.Query().Get("limit")

	if srcIP == "" || dstIP == "" || protocol == "" {
		http.Error(w, "Missing required parameters (srcIP, dstIP, protocol)", http.StatusBadRequest)
		return
	}

	// Parse pagination parameters
	offset := int64(0)
	if offsetStr != "" {
		if parsed, err := strconv.ParseInt(offsetStr, 10, 64); err == nil {
			offset = parsed
		}
	}

	// Default chunk size: 64KB
	limit := 64 * 1024
	if limitStr != "" {
		if parsed, err := strconv.Atoi(limitStr); err == nil && parsed > 0 && parsed <= 10*1024*1024 {
			limit = parsed
		}
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

	response := NetworkConversationDataResponse{
		SrcIP:    srcIP,
		DstIP:    dstIP,
		Protocol: protocol,
		Exists:   false,
		Offset:   offset,
	}

	// Try to find and read the network conversation file chunk
	conversationData, filePath, totalSize, hasMore, err := readNetworkConversationFileChunk(
		outDir, srcIP, dstIP, protocol, offset, limit,
	)
	if err != nil {
		response.ErrorMessage = err.Error()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
		return
	}

	if conversationData != "" {
		response.Exists = true
		response.FilePath = filePath
		response.ConversationData = conversationData
		response.TotalSize = totalSize
		response.ChunkSize = len(conversationData)
		response.HasMore = hasMore
	} else {
		response.ErrorMessage = "Network conversation file not found. Make sure stream reassembly was enabled during capture."
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// readNetworkConversationFileChunk reads a chunk of the network conversation file
func readNetworkConversationFileChunk(outDir, srcIP, dstIP, protocol string, offset int64, limit int) (string, string, int64, bool, error) {
	// Find the conversation file path
	foundPath, err := findNetworkConversationFilePath(outDir, srcIP, dstIP, protocol)
	if err != nil {
		return "", "", 0, false, err
	}

	if foundPath == "" {
		return "", "", 0, false, nil // File not found
	}

	// Open the file
	file, err := os.Open(foundPath)
	if err != nil {
		return "", "", 0, false, err
	}
	defer file.Close()

	// Get file size
	fileInfo, err := file.Stat()
	if err != nil {
		return "", "", 0, false, err
	}
	totalSize := fileInfo.Size()

	// Check if offset is valid
	if offset >= totalSize {
		return "", "", totalSize, false, nil // No more data
	}

	// Seek to offset
	_, err = file.Seek(offset, 0)
	if err != nil {
		return "", "", 0, false, err
	}

	// Read chunk
	remaining := totalSize - offset
	readSize := int64(limit)
	if readSize > remaining {
		readSize = remaining
	}

	buffer := make([]byte, readSize)
	n, err := stdio.ReadFull(file, buffer)
	if err != nil && err != stdio.EOF && err != stdio.ErrUnexpectedEOF {
		return "", "", 0, false, err
	}

	// Check if there's more data
	hasMore := offset+int64(n) < totalSize

	// Convert to base64
	encoded := base64.StdEncoding.EncodeToString(buffer[:n])

	// Get relative path
	relPath, _ := filepath.Rel(outDir, foundPath)

	return encoded, relPath, totalSize, hasMore, nil
}

// findNetworkConversationFilePath searches for the network conversation file and returns its path
// Network conversations are stored in: network/{protocol}/{srcIP}--{dstIP}.bin
func findNetworkConversationFilePath(outDir, srcIP, dstIP, protocol string) (string, error) {
	// Construct connection identifier for network-layer (no ports)
	flowIdent := utils.CreateFlowIdent(srcIP, "", dstIP, "")
	connIdent := utils.CleanIdent(flowIdent)

	// Network conversation directory: network/{protocol}/
	protoDirPath := filepath.Join(outDir, "network", strings.ToLower(protocol))

	// Check if protocol directory exists
	if _, err := os.Stat(protoDirPath); os.IsNotExist(err) {
		return "", nil // No conversation files saved
	}

	// Search for the file
	var foundPath string
	err := filepath.Walk(protoDirPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		// Check if filename matches the connection identifier
		if strings.Contains(info.Name(), connIdent) {
			foundPath = path
			return filepath.SkipDir
		}
		return nil
	})

	if err != nil {
		return "", err
	}

	if foundPath == "" {
		// Try reverse direction
		reverseFlowIdent := utils.CreateFlowIdent(dstIP, "", srcIP, "")
		reverseIdent := utils.CleanIdent(reverseFlowIdent)

		err = filepath.Walk(protoDirPath, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			if info.IsDir() {
				return nil
			}
			if strings.Contains(info.Name(), reverseIdent) {
				foundPath = path
				return filepath.SkipDir
			}
			return nil
		})
		if err != nil {
			return "", err
		}
	}

	return foundPath, nil
}
