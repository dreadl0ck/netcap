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
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"

	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcap"
)

// BPFConfig represents the BPF filter configuration
type BPFConfig struct {
	Filter string `json:"filter"`
}

// BPFExample represents a BPF filter example
type BPFExample struct {
	Name        string `json:"name"`
	Filter      string `json:"filter"`
	Description string `json:"description"`
}

// BPFInfoResponse contains BPF configuration and examples
type BPFInfoResponse struct {
	CurrentFilter string       `json:"currentFilter"`
	Examples      []BPFExample `json:"examples"`
	DocsURL       string       `json:"docsUrl"`
}

// handleBPFConfig handles GET and POST requests for BPF filter configuration
func (s *Server) handleBPFConfig(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		config := s.loadBPFConfig()
		response := BPFInfoResponse{
			CurrentFilter: config.Filter,
			Examples:      getBPFExamples(),
			DocsURL:       "https://biot.com/capstats/bpf.html",
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(response); err != nil {
			http.Error(w, fmt.Sprintf("Failed to encode response: %v", err), http.StatusInternalServerError)
		}
	case http.MethodPost:
		var config BPFConfig
		if err := json.NewDecoder(r.Body).Decode(&config); err != nil {
			http.Error(w, fmt.Sprintf("Invalid request: %v", err), http.StatusBadRequest)
			return
		}

		// Validate BPF filter if not empty
		if config.Filter != "" {
			if err := validateBPFFilter(config.Filter); err != nil {
				http.Error(w, fmt.Sprintf("Invalid BPF filter: %v", err), http.StatusBadRequest)
				return
			}
		}

		if err := s.saveBPFConfig(config); err != nil {
			http.Error(w, fmt.Sprintf("Failed to save BPF configuration: %v", err), http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"success": true,
			"message": "BPF filter configuration saved successfully. Changes will be applied to future capture sessions.",
		})
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// loadBPFConfig loads the BPF configuration from file
func (s *Server) loadBPFConfig() BPFConfig {
	configPath := s.getBPFConfigPath()

	data, err := os.ReadFile(configPath)
	if err != nil {
		// Return default empty config if file doesn't exist
		return BPFConfig{
			Filter: "",
		}
	}

	var config BPFConfig
	if err := json.Unmarshal(data, &config); err != nil {
		// Return default empty config if file is corrupted
		return BPFConfig{
			Filter: "",
		}
	}

	return config
}

// saveBPFConfig saves the BPF configuration to file
func (s *Server) saveBPFConfig(config BPFConfig) error {
	configPath := s.getBPFConfigPath()

	// Ensure directory exists
	if err := os.MkdirAll(filepath.Dir(configPath), 0755); err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}

	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	if err := os.WriteFile(configPath, data, 0644); err != nil {
		return fmt.Errorf("failed to write config file: %w", err)
	}

	return nil
}

// getBPFConfigPath returns the path to the BPF configuration file
func (s *Server) getBPFConfigPath() string {
	configRoot := getConfigRootPath()
	return filepath.Join(configRoot, "bpf-config.json")
}

// validateBPFFilter validates a BPF filter expression by attempting to compile it
func validateBPFFilter(filter string) error {
	// Try to compile the BPF filter using pcap's BPF compiler
	// This validates the syntax without needing to open an actual pcap file
	_, err := pcap.CompileBPFFilter(layers.LinkTypeEthernet, 65535, filter)
	if err != nil {
		return fmt.Errorf("invalid BPF syntax: %w", err)
	}

	return nil
}

// getBPFExamples returns a list of common BPF filter examples
func getBPFExamples() []BPFExample {
	return []BPFExample{
		{
			Name:        "HTTP Traffic",
			Filter:      "tcp port 80",
			Description: "Capture only HTTP traffic on port 80",
		},
		{
			Name:        "HTTPS Traffic",
			Filter:      "tcp port 443",
			Description: "Capture only HTTPS traffic on port 443",
		},
		{
			Name:        "DNS Traffic",
			Filter:      "udp port 53",
			Description: "Capture DNS queries and responses",
		},
		{
			Name:        "SSH Traffic",
			Filter:      "tcp port 22",
			Description: "Capture SSH connections",
		},
		{
			Name:        "Specific IP Address",
			Filter:      "host 192.168.1.100",
			Description: "Capture all traffic to/from a specific IP address",
		},
		{
			Name:        "Subnet Traffic",
			Filter:      "net 192.168.1.0/24",
			Description: "Capture traffic within a specific subnet",
		},
		{
			Name:        "TCP SYN Packets",
			Filter:      "tcp[tcpflags] & tcp-syn != 0",
			Description: "Capture TCP SYN packets (connection attempts)",
		},
		{
			Name:        "Non-SSH Traffic",
			Filter:      "not tcp port 22",
			Description: "Exclude SSH traffic from capture",
		},
		{
			Name:        "HTTP GET Requests",
			Filter:      "tcp port 80 and (((ip[2:2] - ((ip[0]&0xf)<<2)) - ((tcp[12]&0xf0)>>2)) != 0)",
			Description: "Capture HTTP packets with payload (potential GET requests)",
		},
		{
			Name:        "IPv4 Only",
			Filter:      "ip",
			Description: "Capture only IPv4 traffic",
		},
		{
			Name:        "IPv6 Only",
			Filter:      "ip6",
			Description: "Capture only IPv6 traffic",
		},
		{
			Name:        "ICMP Traffic",
			Filter:      "icmp",
			Description: "Capture ICMP packets (ping, etc.)",
		},
		{
			Name:        "Multiple Ports",
			Filter:      "tcp port 80 or tcp port 443 or tcp port 8080",
			Description: "Capture traffic on multiple ports",
		},
		{
			Name:        "Port Range",
			Filter:      "tcp portrange 8000-9000",
			Description: "Capture traffic within a port range",
		},
		{
			Name:        "Broadcast Traffic",
			Filter:      "ether broadcast or ether multicast",
			Description: "Capture broadcast and multicast frames",
		},
		{
			Name:        "Large Packets",
			Filter:      "greater 1000",
			Description: "Capture packets larger than 1000 bytes",
		},
		{
			Name:        "Source Host",
			Filter:      "src host 192.168.1.1",
			Description: "Capture traffic from a specific source IP",
		},
		{
			Name:        "Destination Host",
			Filter:      "dst host 192.168.1.1",
			Description: "Capture traffic to a specific destination IP",
		},
		{
			Name:        "Web Traffic (HTTP/HTTPS)",
			Filter:      "tcp port 80 or tcp port 443",
			Description: "Capture both HTTP and HTTPS traffic",
		},
		{
			Name:        "Exclude Private Networks",
			Filter:      "not (net 192.168.0.0/16 or net 10.0.0.0/8 or net 172.16.0.0/12)",
			Description: "Exclude RFC1918 private network traffic",
		},
	}
}
