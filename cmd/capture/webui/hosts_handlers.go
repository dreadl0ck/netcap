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
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	stdio "io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/dreadl0ck/netcap/internal/artifactio"
	"github.com/dreadl0ck/netcap/internal/delimited"
	"github.com/dreadl0ck/netcap/types"
)

// HostSummary represents aggregated information for a single IP address
type HostSummary struct {
	Addr                string         `json:"addr"`
	NumPackets          int64          `json:"numPackets"`
	Bytes               uint64         `json:"bytes"`
	Geolocation         string         `json:"geolocation"`
	DNSNames            []string       `json:"dnsNames"`
	TimestampFirst      int64          `json:"timestampFirst"`
	TimestampLast       int64          `json:"timestampLast"`
	Applications        []string       `json:"applications"`
	Ja4Fingerprints     []string       `json:"ja4Fingerprints"`
	Ja4SFingerprints    []string       `json:"ja4sFingerprints"`
	ProtocolsCount      int            `json:"protocolsCount"`
	SNIsCount           int            `json:"snisCount"`
	SrcPortsCount       int            `json:"srcPortsCount"`
	DstPortsCount       int            `json:"dstPortsCount"`
	ContactedPortsCount int            `json:"contactedPortsCount"`
	TopProtocols        []ProtocolInfo `json:"topProtocols"`
	TopSrcPorts         []PortInfo     `json:"topSrcPorts"`
	TopDstPorts         []PortInfo     `json:"topDstPorts"`
	TopContactedPorts   []PortInfo     `json:"topContactedPorts"`
	IsInternal          bool           `json:"isInternal"`
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
	Hosts      []HostSummary      `json:"hosts"`
	TotalCount int                `json:"totalCount"`
	Identity   hostIdentityReport `json:"identity"`
}

var hostPageSlots = make(chan struct{}, 2)

// handleHosts returns a list of all IP profiles
func (s *Server) handleHosts(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	selected, ok := s.selectedCapture(w, r)
	if !ok {
		return
	}
	outDir := selected.OutputDir

	if outDir == "" {
		http.Error(w, "No output directory set", http.StatusServiceUnavailable)
		return
	}

	query := r.URL.Query()
	paged := query.Get("mcpPage") == "true"
	if paged {
		if r.Context().Err() != nil {
			return
		}
		select {
		case hostPageSlots <- struct{}{}:
			defer func() { <-hostPageSlots }()
		default:
			RespondJSON(w, http.StatusTooManyRequests, map[string]string{"error": "host pages are busy"})
			return
		}
	}
	view := "traffic"
	if paged && query.Get("view") != "" {
		view = query.Get("view")
	}
	var hosts []HostSummary
	switch view {
	case "traffic":
		var err error
		if paged {
			hosts, err = readHostTraffic(r.Context(), outDir)
		} else {
			hosts, err = readHosts(outDir)
		}
		if err != nil {
			if errors.Is(err, errHostTrafficLimit) {
				RespondJSON(w, http.StatusRequestEntityTooLarge, map[string]string{"error": err.Error()})
				return
			}
			log.Printf("[WebUI] Failed to read IP profiles: %v", err)
			http.Error(w, "Failed to read IP profiles", http.StatusInternalServerError)
			return
		}
	case "identity", "directory":
	default:
		RespondJSON(w, 400, map[string]string{"error": "view must be traffic, identity or directory"})
		return
	}

	identity, err := readHostIdentity(r.Context(), outDir)
	if err != nil {
		http.Error(w, "Cannot read qualified host identity evidence", http.StatusInternalServerError)
		return
	}
	response := HostsResponse{
		Hosts:      hosts,
		TotalCount: len(hosts),
		Identity:   identity,
	}

	w.Header().Set("Content-Type", "application/json")
	if paged {
		var rows any = response.Hosts
		switch view {
		case "traffic":
		case "identity", "directory":
			field := "hosts"
			if view == "directory" {
				field = "directory"
			}
			rows = []any{}
			if identity.Report != nil && identity.Report[field] != nil {
				rows = identity.Report[field]
			}
		}
		summary := map[string]any{"state": identity.State, "generation": hex.EncodeToString(identity.digest[:])}
		for _, field := range []string{"schema", "overflow", "unscopedRecords", "limitations"} {
			if value, ok := identity.Report[field]; ok {
				summary[field] = value
			}
		}
		respondCollectionPage(w, r, rows, "hosts", map[string]any{"view": view, "identity": summary})
		return
	}
	json.NewEncoder(w).Encode(response)
}

// readHosts reads and aggregates IPProfile data from the output directory
func readHosts(outDir string) ([]HostSummary, error) {
	return readHostTraffic(nil, outDir)
}

var errHostTrafficLimit = errors.New("host traffic audit exceeds page scan limits")

func readHostTraffic(ctx context.Context, outDir string) ([]HostSummary, error) {
	const name = "Host.ncap.gz"
	var reader *AuditRecordReader
	var err error
	if ctx == nil {
		reader, err = NewAuditRecordReader(filepath.Join(outDir, name))
	} else {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		file, info, openErr := artifactio.Open(outDir, name)
		if openErr != nil {
			err = openErr
		} else if info.Size() > maxCollectionPageScanBytes {
			file.Close()
			return nil, errHostTrafficLimit
		} else {
			reader, err = auditRecordReaderFromInput(file, io.NewSectionReader(file, 0, info.Size()), true, func(in io.Reader) io.Reader {
				return auditContextReader{ctx: ctx, input: in}
			})
		}
	}
	if errors.Is(err, os.ErrNotExist) {
		return []HostSummary{}, nil
	}
	if err != nil {
		return nil, err
	}
	defer reader.Close()

	// Read header
	header, err := reader.ReadHeader()
	if err != nil {
		return nil, err
	}
	if ctx != nil && header.Type != types.Type_NC_Host {
		return nil, fmt.Errorf("unexpected host traffic audit type %s", header.Type)
	}

	hosts := make([]HostSummary, 0)
	remaining := maxCollectionPageScanBytes

	// Read all records
	for {
		var record any
		if ctx == nil {
			record, err = reader.NextRecord()
		} else {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			frameLimit := remaining
			if len(hosts) == maxCollectionPageRows {
				frameLimit = 0
			}
			var raw []byte
			raw, err = reader.delimitedReader.NextWithLimit(uint64(max(1, frameLimit)))
			if errors.Is(err, delimited.ErrRecordLimit) || (err == nil && (len(raw) > frameLimit || len(hosts) == maxCollectionPageRows)) {
				return nil, errHostTrafficLimit
			}
			if err == nil {
				remaining -= len(raw)
				record, err = reader.DecodeRecord(raw)
			}
		}
		if err != nil {
			if err == io.EOF {
				break
			}
			return nil, err
		}

		// Type assert to IPProfile
		ipProfile, ok := record.(*types.Host)
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
				if protos[i].packets == protos[j].packets {
					return protos[i].name < protos[j].name
				}
				return protos[i].packets > protos[j].packets
			})
			// Take top 5
			limit := min(len(protos), 5)
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

		hosts = append(hosts, HostSummary{
			Addr:                ipProfile.Addr,
			NumPackets:          ipProfile.NumPackets,
			Bytes:               ipProfile.Bytes,
			Geolocation:         ipProfile.Geolocation,
			DNSNames:            ipProfile.DNSNames,
			TimestampFirst:      ipProfile.TimestampFirst,
			TimestampLast:       ipProfile.TimestampLast,
			Applications:        ipProfile.Applications,
			Ja4Fingerprints:     ipProfile.Ja4Fingerprints,
			Ja4SFingerprints:    ipProfile.Ja4SFingerprints,
			ProtocolsCount:      len(ipProfile.Protocols),
			SNIsCount:           len(ipProfile.SNIs),
			SrcPortsCount:       len(ipProfile.SrcPorts),
			DstPortsCount:       len(ipProfile.DstPorts),
			ContactedPortsCount: len(ipProfile.ContactedPorts),
			TopProtocols:        topProtocols,
			TopSrcPorts:         topSrcPorts,
			TopDstPorts:         topDstPorts,
			TopContactedPorts:   topContactedPorts,
			IsInternal:          isPrivateIP(ipProfile.Addr),
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

	activeInputFile, _ := s.resolveInputFileFromRequest(r)

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

	// Filter the PCAP entirely in-process (no external tcpdump).
	log.Printf("[WebUI] Filtering PCAP for host in-process: %s -> %s (bpf: %s)", activeInputFile, outputFile, bpf)

	written, err := filterPCAPToFileWithTimeout(r.Context(), activeInputFile, bpf, outputFile, 60*time.Second)
	if err != nil {
		log.Printf("[WebUI] PCAP filter error: %v", err)
		os.Remove(outputFile)
		if isPCAPFilterTimeout(err) {
			http.Error(w, "PCAP filtering timed out. The file may be too large or the filter too complex.", http.StatusRequestTimeout)
			return
		}
		http.Error(w, fmt.Sprintf("Failed to filter PCAP: %v", err), http.StatusInternalServerError)
		return
	}

	// No packets matched the filter.
	if written == 0 {
		log.Printf("[WebUI] No packets matched filter, removing empty file")
		os.Remove(outputFile)
		http.Error(w, "No packets found for this host", http.StatusNotFound)
		return
	}

	// Confirm the output file exists before reading it back.
	fileInfo, err := os.Stat(outputFile)
	if err != nil {
		log.Printf("[WebUI] Output file not found: %v", err)
		http.Error(w, "Failed to create filtered PCAP", http.StatusInternalServerError)
		return
	}

	log.Printf("[WebUI] Filtered PCAP created: %s, %d packets, size: %d bytes", outputFile, written, fileInfo.Size())

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
