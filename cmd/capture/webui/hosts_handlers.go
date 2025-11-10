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
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sort"

	"github.com/dreadl0ck/netcap/types"
)

// IPProfileSummary represents aggregated information for a single IP address
type IPProfileSummary struct {
	Addr                    string            `json:"addr"`
	NumPackets              int64             `json:"numPackets"`
	Bytes                   uint64            `json:"bytes"`
	Geolocation             string            `json:"geolocation"`
	DNSNames                []string          `json:"dnsNames"`
	TimestampFirst          int64             `json:"timestampFirst"`
	TimestampLast           int64             `json:"timestampLast"`
	Applications            []string          `json:"applications"`
	Ja3Hashes               map[string]string `json:"ja3Hashes"`
	ProtocolsCount          int               `json:"protocolsCount"`
	SNIsCount               int               `json:"snisCount"`
	SrcPortsCount           int               `json:"srcPortsCount"`
	DstPortsCount           int               `json:"dstPortsCount"`
	ContactedPortsCount     int               `json:"contactedPortsCount"`
	Ja3FingerprintMatches   []string          `json:"ja3FingerprintMatches"`
	Ja3sFingerprintMatches  []string          `json:"ja3sFingerprintMatches"`
	TopProtocols            []ProtocolInfo    `json:"topProtocols"`
	TopSrcPorts             []PortInfo        `json:"topSrcPorts"`
	TopDstPorts             []PortInfo        `json:"topDstPorts"`
	TopContactedPorts       []PortInfo        `json:"topContactedPorts"`
	IsInternal              bool              `json:"isInternal"`
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

