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
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// ProtocolHierarchyNode represents a node in the protocol hierarchy
type ProtocolHierarchyNode struct {
	Name     string                  `json:"name"`
	Layer    string                  `json:"layer"`
	Count    int64                   `json:"count"`
	Bytes    int64                   `json:"bytes"`
	Children []ProtocolHierarchyNode `json:"children"`
}

// SankeyLink represents a link for Sankey diagram
type SankeyLink struct {
	Source string `json:"source"`
	Target string `json:"target"`
	Value  int64  `json:"value"`
}

// ProtocolHierarchyResponse is the API response
type ProtocolHierarchyResponse struct {
	Links []SankeyLink             `json:"links"`
	Nodes []string                 `json:"nodes"`
	Stats map[string]ProtocolStats `json:"stats"`
}

// ProtocolStats contains statistics for a protocol
type ProtocolStats struct {
	Count int64  `json:"count"`
	Bytes int64  `json:"bytes"`
	Layer string `json:"layer"`
}

// handleProtocolHierarchy returns protocol hierarchy data for Sankey visualization
func (s *Server) handleProtocolHierarchy(w http.ResponseWriter, r *http.Request) {
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

	// Build protocol hierarchy from audit files
	hierarchy, err := buildProtocolHierarchy(outDir)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to build protocol hierarchy: %v", err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(hierarchy); err != nil {
		http.Error(w, fmt.Sprintf("Failed to encode response: %v", err), http.StatusInternalServerError)
	}
}

// HandleProtocolHierarchy is an exported handler factory for service mode
func HandleProtocolHierarchy(outDir string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		if outDir == "" {
			http.Error(w, "No output directory set", http.StatusServiceUnavailable)
			return
		}

		// Build protocol hierarchy from audit files
		hierarchy, err := buildProtocolHierarchy(outDir)
		if err != nil {
			http.Error(w, fmt.Sprintf("Failed to build protocol hierarchy: %v", err), http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(hierarchy); err != nil {
			http.Error(w, fmt.Sprintf("Failed to encode response: %v", err), http.StatusInternalServerError)
		}
	}
}

// buildProtocolHierarchy builds protocol hierarchy from audit files
func buildProtocolHierarchy(outDir string) (*ProtocolHierarchyResponse, error) {
	// Map to store protocol statistics
	stats := make(map[string]ProtocolStats)

	// Map to track protocol relationships (parent -> child -> count)
	relationships := make(map[string]map[string]int64)

	// Layer mapping for protocols
	layerMap := map[string]string{
		// Link Layer
		"Ethernet":               "Link Layer",
		"Dot1Q":                  "Link Layer",
		"Dot11":                  "Link Layer",
		"LLC":                    "Link Layer",
		"SNAP":                   "Link Layer",
		"ARP":                    "Link Layer",
		"CiscoDiscovery":         "Link Layer",
		"NortelDiscovery":        "Link Layer",
		"LinkLayerDiscovery":     "Link Layer",
		"LinkLayerDiscoveryInfo": "Link Layer",
		"STP":                    "Link Layer",
		"LLDP":                   "Link Layer",

		// Network Layer
		"IPv4":                        "Network Layer",
		"IPv6":                        "Network Layer",
		"IPv6HopByHop":                "Network Layer",
		"ICMPv4":                      "Network Layer",
		"ICMPv6":                      "Network Layer",
		"ICMPv6Echo":                  "Network Layer",
		"ICMPv6RouterSolicitation":    "Network Layer",
		"ICMPv6RouterAdvertisement":   "Network Layer",
		"ICMPv6NeighborSolicitation":  "Network Layer",
		"ICMPv6NeighborAdvertisement": "Network Layer",
		"IGMP":                        "Network Layer",
		"IPSecAH":                     "Network Layer",
		"IPSecESP":                    "Network Layer",
		"GRE":                         "Network Layer",
		"MPLS":                        "Network Layer",
		"OSPFv2":                      "Network Layer",
		"OSPFv3":                      "Network Layer",

		// Transport Layer
		"TCP":  "Transport Layer",
		"UDP":  "Transport Layer",
		"SCTP": "Transport Layer",

		// Application Layer
		"HTTP":           "Application Layer",
		"TLS":            "Application Layer",
		"TLSClientHello": "Application Layer",
		"TLSServerHello": "Application Layer",
		"DNS":            "Application Layer",
		"SMTP":           "Application Layer",
		"POP3":           "Application Layer",
		"SSH":            "Application Layer",
		"FTP":            "Application Layer",
		"Telnet":         "Application Layer",
		"SIP":            "Application Layer",
		"NTP":            "Application Layer",
		"DHCPv4":         "Application Layer",
		"DHCPv6":         "Application Layer",
		"DHCP":           "Application Layer",
		"Modbus":         "Application Layer",
		"ENIP":           "Application Layer",
		"CIP":            "Application Layer",
		"Diameter":       "Application Layer",
		"VXLAN":          "Application Layer",
		"Geneve":         "Application Layer",
	}

	// Typical protocol encapsulation hierarchy
	encapsulationMap := map[string][]string{
		"Link Layer":        {"Ethernet", "Dot1Q", "Dot11", "LLC", "SNAP", "ARP", "LinkLayerDiscovery", "LinkLayerDiscoveryInfo"},
		"Network Layer":     {"IPv4", "IPv6", "IPv6HopByHop", "ICMPv4", "ICMPv6", "ICMPv6Echo", "ICMPv6RouterSolicitation", "ICMPv6RouterAdvertisement", "ICMPv6NeighborSolicitation", "ICMPv6NeighborAdvertisement", "IGMP", "OSPFv2", "OSPFv3"},
		"Transport Layer":   {"TCP", "UDP", "SCTP"},
		"Application Layer": {"HTTP", "TLS", "DNS", "SMTP", "SSH", "FTP", "DHCPv4", "DHCPv6"},
	}

	// Read all audit record files
	files, err := ioutil.ReadDir(outDir)
	if err != nil {
		return nil, fmt.Errorf("failed to read output directory: %v", err)
	}

	// Process each audit file to get counts
	for _, file := range files {
		if file.IsDir() || !strings.HasSuffix(file.Name(), ".ncap.gz") {
			continue
		}

		// Extract protocol name from filename
		fileName := strings.TrimSuffix(file.Name(), ".ncap.gz")
		parts := strings.Split(fileName, ".")
		if len(parts) < 1 {
			continue
		}

		protocol := parts[0]
		layer := layerMap[protocol]
		if layer == "" {
			layer = "Custom Abstraction"
		}

		// Get file metadata
		fullPath := filepath.Join(outDir, file.Name())
		fileInfo, err := os.Stat(fullPath)
		if err != nil {
			continue
		}

		// Try to get actual record count from metadata
		count := int64(0)
		bytes := fileInfo.Size()

		// Try to read metadata from .meta.json file
		metaPath := fullPath + ".meta.json"
		if metaData, err := os.ReadFile(metaPath); err == nil {
			var meta struct {
				RecordCount int64 `json:"recordCount"`
			}
			if err := json.Unmarshal(metaData, &meta); err == nil && meta.RecordCount > 0 {
				count = meta.RecordCount
			}
		}

		// If no metadata, count records properly instead of estimating
		if count == 0 {
			count = CountRecords(fullPath)
		}

		// Store stats
		stats[protocol] = ProtocolStats{
			Count: count,
			Bytes: bytes,
			Layer: layer,
		}
	}

	// Build relationships based on typical encapsulation
	// Link Layer -> Network Layer
	linkLayerTotal := int64(0)
	for _, proto := range encapsulationMap["Link Layer"] {
		if s, ok := stats[proto]; ok {
			linkLayerTotal += s.Count
		}
	}

	networkLayerTotal := int64(0)
	for _, proto := range encapsulationMap["Network Layer"] {
		if s, ok := stats[proto]; ok {
			networkLayerTotal += s.Count
		}
	}

	transportLayerTotal := int64(0)
	for _, proto := range encapsulationMap["Transport Layer"] {
		if s, ok := stats[proto]; ok {
			transportLayerTotal += s.Count
		}
	}

	applicationLayerTotal := int64(0)
	for _, proto := range encapsulationMap["Application Layer"] {
		if s, ok := stats[proto]; ok {
			applicationLayerTotal += s.Count
		}
	}

	// Link protocols from Link Layer to Network Layer
	if linkLayerTotal > 0 {
		for _, proto := range encapsulationMap["Link Layer"] {
			if s, ok := stats[proto]; ok {
				if relationships[proto] == nil {
					relationships[proto] = make(map[string]int64)
				}
				// Distribute to network layer protocols proportionally
				for _, netProto := range encapsulationMap["Network Layer"] {
					if netStats, ok := stats[netProto]; ok {
						value := int64(float64(s.Count) * float64(netStats.Count) / float64(networkLayerTotal))
						if value > 0 {
							relationships[proto][netProto] = value
						}
					}
				}
			}
		}
	}

	// Network Layer to Transport Layer
	if networkLayerTotal > 0 && transportLayerTotal > 0 {
		for _, proto := range encapsulationMap["Network Layer"] {
			if s, ok := stats[proto]; ok {
				if relationships[proto] == nil {
					relationships[proto] = make(map[string]int64)
				}
				for _, transProto := range encapsulationMap["Transport Layer"] {
					if transStats, ok := stats[transProto]; ok {
						value := int64(float64(s.Count) * float64(transStats.Count) / float64(transportLayerTotal))
						if value > 0 {
							relationships[proto][transProto] = value
						}
					}
				}
			}
		}
	}

	// Transport Layer to Application Layer
	if transportLayerTotal > 0 && applicationLayerTotal > 0 {
		for _, proto := range encapsulationMap["Transport Layer"] {
			if s, ok := stats[proto]; ok {
				if relationships[proto] == nil {
					relationships[proto] = make(map[string]int64)
				}
				for _, appProto := range encapsulationMap["Application Layer"] {
					if appStats, ok := stats[appProto]; ok {
						value := int64(float64(s.Count) * float64(appStats.Count) / float64(applicationLayerTotal))
						if value > 0 {
							relationships[proto][appProto] = value
						}
					}
				}
			}
		}
	}

	// Build Sankey links
	links := []SankeyLink{}
	nodesMap := make(map[string]bool)

	for source, targets := range relationships {
		nodesMap[source] = true
		for target, value := range targets {
			nodesMap[target] = true
			links = append(links, SankeyLink{
				Source: source,
				Target: target,
				Value:  value,
			})
		}
	}

	// Convert nodes map to sorted slice
	nodes := make([]string, 0, len(nodesMap))
	for node := range nodesMap {
		nodes = append(nodes, node)
	}
	sort.Strings(nodes)

	// Also add protocols without relationships
	for proto := range stats {
		if !nodesMap[proto] {
			nodes = append(nodes, proto)
			nodesMap[proto] = true
		}
	}
	sort.Strings(nodes)

	return &ProtocolHierarchyResponse{
		Links: links,
		Nodes: nodes,
		Stats: stats,
	}, nil
}
