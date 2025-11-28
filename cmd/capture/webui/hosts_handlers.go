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

// IPProfileSummary represents aggregated information for a single IP address
type IPProfileSummary struct {
	Addr                   string            `json:"addr"`
	NumPackets             int64             `json:"numPackets"`
	Bytes                  uint64            `json:"bytes"`
	Geolocation            string            `json:"geolocation"`
	DNSNames               []string          `json:"dnsNames"`
	TimestampFirst         int64             `json:"timestampFirst"`
	TimestampLast          int64             `json:"timestampLast"`
	Applications           []string          `json:"applications"`
	Ja3Hashes              map[string]string `json:"ja3Hashes"`
	ProtocolsCount         int               `json:"protocolsCount"`
	SNIsCount              int               `json:"snisCount"`
	SrcPortsCount          int               `json:"srcPortsCount"`
	DstPortsCount          int               `json:"dstPortsCount"`
	ContactedPortsCount    int               `json:"contactedPortsCount"`
	Ja3FingerprintMatches  []string          `json:"ja3FingerprintMatches"`
	Ja3sFingerprintMatches []string          `json:"ja3sFingerprintMatches"`
	TopProtocols           []ProtocolInfo    `json:"topProtocols"`
	TopSrcPorts            []PortInfo        `json:"topSrcPorts"`
	TopDstPorts            []PortInfo        `json:"topDstPorts"`
	TopContactedPorts      []PortInfo        `json:"topContactedPorts"`
	IsInternal             bool              `json:"isInternal"`
}

// ProtocolInfo represents protocol statistics
type ProtocolInfo struct {
	Name     string `json:"name"`
	Packets  uint64 `json:"packets"`
	Category string `json:"category"`
}

// PortInfo represents port statistics
type PortInfo struct {
	Port     int32  `json:"port"`
	Protocol string `json:"protocol"`
	Packets  uint64 `json:"packets"`
	Bytes    uint64 `json:"bytes"`
}

// HostsResponse contains the list of IP profiles
type HostsResponse struct {
	Hosts      []IPProfileSummary `json:"hosts"`
	TotalCount int                `json:"totalCount"`
}

// handleHosts returns a list of all IP profiles
func (s *Server) handleHosts(w http.ResponseWriter, r *http.Request) {
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

	hosts, err := readIPProfiles(outDir)
	if err != nil {
		log.Printf("[WebUI] Failed to read IP profiles: %v", err)
		http.Error(w, "Failed to read IP profiles", http.StatusInternalServerError)
		return
	}

	response := HostsResponse{
		Hosts:      hosts,
		TotalCount: len(hosts),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// readIPProfiles reads and aggregates IPProfile data from the output directory
func readIPProfiles(outDir string) ([]IPProfileSummary, error) {
	filePath := filepath.Join(outDir, "IPProfile.ncap.gz")

	// Check if file exists
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		log.Printf("[WebUI] IPProfile file not found: %s", filePath)
		return []IPProfileSummary{}, nil
	}

	// Read IPProfile records
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

	hosts := make([]IPProfileSummary, 0)

	// Read all records
	for {
		record, err := reader.NextRecord()
		if err != nil {
			if err == io.EOF {
				break
			}
			log.Printf("[WebUI] Error reading IPProfile record: %v", err)
			continue
		}

		// Type assert to IPProfile
		ipProfile, ok := record.(*types.IPProfile)
		if !ok {
			continue
		}

		// Extract top protocols (limited to top 5)
		topProtocols := make([]ProtocolInfo, 0)
		if ipProfile.Protocols != nil {
			type protoPair struct {
				name     string
				packets  uint64
				category string
			}
			protos := make([]protoPair, 0, len(ipProfile.Protocols))
			for name, proto := range ipProfile.Protocols {
				protos = append(protos, protoPair{
					name:     name,
					packets:  proto.Packets,
					category: proto.Category,
				})
			}
			// Sort by packet count descending
			sort.Slice(protos, func(i, j int) bool {
				return protos[i].packets > protos[j].packets
			})
			// Take top 5
			limit := 5
			if len(protos) < limit {
				limit = len(protos)
			}
			for i := 0; i < limit; i++ {
				topProtocols = append(topProtocols, ProtocolInfo{
					Name:     protos[i].name,
					Packets:  protos[i].packets,
					Category: protos[i].category,
				})
			}
		}

		// Extract top source ports (limited to top 5)
		topSrcPorts := extractTopPorts(ipProfile.SrcPorts, 5)

		// Extract top destination ports (limited to top 5)
		topDstPorts := extractTopPorts(ipProfile.DstPorts, 5)

		// Extract top contacted ports (limited to top 5)
		topContactedPorts := extractTopPorts(ipProfile.ContactedPorts, 5)

		hosts = append(hosts, IPProfileSummary{
			Addr:                   ipProfile.Addr,
			NumPackets:             ipProfile.NumPackets,
			Bytes:                  ipProfile.Bytes,
			Geolocation:            ipProfile.Geolocation,
			DNSNames:               ipProfile.DNSNames,
			TimestampFirst:         ipProfile.TimestampFirst,
			TimestampLast:          ipProfile.TimestampLast,
			Applications:           ipProfile.Applications,
			Ja3Hashes:              ipProfile.Ja3Hashes,
			ProtocolsCount:         len(ipProfile.Protocols),
			SNIsCount:              len(ipProfile.SNIs),
			SrcPortsCount:          len(ipProfile.SrcPorts),
			DstPortsCount:          len(ipProfile.DstPorts),
			ContactedPortsCount:    len(ipProfile.ContactedPorts),
			Ja3FingerprintMatches:  ipProfile.Ja3FingerprintMatches,
			Ja3sFingerprintMatches: ipProfile.Ja3SFingerprintMatches,
			TopProtocols:           topProtocols,
			TopSrcPorts:            topSrcPorts,
			TopDstPorts:            topDstPorts,
			TopContactedPorts:      topContactedPorts,
			IsInternal:             isPrivateIP(ipProfile.Addr),
		})
	}

	// Sort by packet count descending
	sort.Slice(hosts, func(i, j int) bool {
		return hosts[i].NumPackets > hosts[j].NumPackets
	})

	return hosts, nil
}

// extractTopPorts extracts top N ports sorted by packet count
func extractTopPorts(ports []*types.Port, limit int) []PortInfo {
	result := make([]PortInfo, 0)
	if ports == nil {
		return result
	}

	// Convert to sortable slice
	type portPair struct {
		port     int32
		protocol string
		packets  uint64
		bytes    uint64
	}
	pairs := make([]portPair, 0, len(ports))
	for _, port := range ports {
		pairs = append(pairs, portPair{
			port:     port.PortNumber,
			protocol: port.Protocol,
			packets:  port.Stats.Packets,
			bytes:    port.Stats.Bytes,
		})
	}

	// Sort by packet count descending
	sort.Slice(pairs, func(i, j int) bool {
		return pairs[i].packets > pairs[j].packets
	})

	// Take top N
	if len(pairs) < limit {
		limit = len(pairs)
	}
	for i := 0; i < limit; i++ {
		result = append(result, PortInfo{
			Port:     pairs[i].port,
			Protocol: pairs[i].protocol,
			Packets:  pairs[i].packets,
			Bytes:    pairs[i].bytes,
		})
	}

	return result
}

// handleHostDownloadPCAP filters and downloads PCAP for a specific host
func (s *Server) handleHostDownloadPCAP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Get query parameter
	hostIP := r.URL.Query().Get("host")

	if hostIP == "" {
		http.Error(w, "Missing required parameter: host", http.StatusBadRequest)
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

	// Create BPF filter for the host (match src or dst IP)
	// Format: host <IP>
	bpf := fmt.Sprintf("host %s", hostIP)

	// Create temporary output file
	tempDir := os.TempDir()
	outputFile := filepath.Join(tempDir, fmt.Sprintf("host_%s.pcap",
		strings.ReplaceAll(strings.ReplaceAll(hostIP, ".", "_"), ":", "_")))

	// Use tcpdump to filter the PCAP with a timeout
	// tcpdump -r input.pcap -w output.pcap "BPF_FILTER"
	tcpdumpCmd := "tcpdump"
	args := []string{"-r", activeInputFile, "-w", outputFile, bpf}

	log.Printf("[WebUI] Filtering PCAP for host: %s %v", tcpdumpCmd, args)

	// Create context with 60 second timeout (hosts can have more traffic than single connections)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
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
		http.Error(w, "No packets found for this host", http.StatusNotFound)
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
	filename := fmt.Sprintf("host_%s.pcap", strings.ReplaceAll(strings.ReplaceAll(hostIP, ".", "_"), ":", "_"))
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

	log.Printf("[WebUI] Successfully sent host PCAP file: %d bytes written", bytesWritten)
}
