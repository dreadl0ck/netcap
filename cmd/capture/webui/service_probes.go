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
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/dreadl0ck/netcap/resolvers"
)

// ServiceProbeInfo represents a parsed service probe entry
type ServiceProbeInfo struct {
	ID            string   `json:"id"`            // Unique identifier (generated)
	Protocol      string   `json:"protocol"`      // TCP or UDP
	ProbeName     string   `json:"probeName"`     // e.g., "GetRequest", "NULL"
	Service       string   `json:"service"`       // e.g., "http", "ssh"
	Pattern       string   `json:"pattern"`       // Regex pattern
	Product       string   `json:"product"`       // p/ field
	Version       string   `json:"version"`       // v/ field
	Info          string   `json:"info"`          // i/ field
	Hostname      string   `json:"hostname"`      // h/ field
	OS            string   `json:"os"`            // o/ field
	DeviceType    string   `json:"deviceType"`    // d/ field
	CPEs          []string `json:"cpes"`          // cpe:/ fields
	Ports         []int    `json:"ports"`         // Port numbers
	SSLPorts      []int    `json:"sslPorts"`      // SSL port numbers
	Rarity        int      `json:"rarity"`        // 1-9
	IsSoftMatch   bool     `json:"isSoftMatch"`   // match vs softmatch
	SendString    string   `json:"sendString"`    // Probe send string
	RawLine       string   `json:"rawLine"`       // Original line from file
	LineNumber    int      `json:"lineNumber"`    // Line number in file
	ProbeProtocol string   `json:"probeProtocol"` // Protocol from Probe directive
	Enabled       bool     `json:"enabled"`       // Whether the probe is enabled (not commented out)
}

// disabledProbePrefix is the prefix used to mark disabled probes in the file
const disabledProbePrefix = "#DISABLED: "

// ServiceProbesResponse represents the response with all service probe information
type ServiceProbesResponse struct {
	Probes     []ServiceProbeInfo `json:"probes"`
	TotalCount int                `json:"totalCount"`
}

// TestProbeRequest represents a request to test a probe regex
type TestProbeRequest struct {
	Pattern     string `json:"pattern"`
	SampleInput string `json:"sampleInput"`
	Flags       string `json:"flags,omitempty"`
}

// TestProbeResponse represents the result of testing a probe regex
type TestProbeResponse struct {
	Matches        bool              `json:"matches"`
	CapturedGroups map[string]string `json:"capturedGroups"`
	Error          string            `json:"error,omitempty"`
}

var (
	// Cache for parsed service probes
	serviceProbesCache struct {
		sync.RWMutex
		probes      []ServiceProbeInfo
		lastModTime time.Time
		filePath    string
	}
)

// getServiceProbesFilePath returns the path to the nmap-service-probes file
func getServiceProbesFilePath() string {
	return filepath.Join(resolvers.DataBaseFolderPath, "nmap-service-probes")
}

// loadServiceProbes loads and parses the nmap-service-probes file
func loadServiceProbes() ([]ServiceProbeInfo, error) {
	filePath := getServiceProbesFilePath()

	// Check file modification time for caching
	fileInfo, err := os.Stat(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to stat service probes file: %w", err)
	}

	serviceProbesCache.RLock()
	if serviceProbesCache.probes != nil &&
		serviceProbesCache.filePath == filePath &&
		serviceProbesCache.lastModTime.Equal(fileInfo.ModTime()) {
		probes := serviceProbesCache.probes
		serviceProbesCache.RUnlock()
		return probes, nil
	}
	serviceProbesCache.RUnlock()

	// Need to reload
	data, err := ioutil.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read service probes file: %w", err)
	}

	probes, err := parseServiceProbes(string(data))
	if err != nil {
		return nil, fmt.Errorf("failed to parse service probes: %w", err)
	}

	// Update cache
	serviceProbesCache.Lock()
	serviceProbesCache.probes = probes
	serviceProbesCache.lastModTime = fileInfo.ModTime()
	serviceProbesCache.filePath = filePath
	serviceProbesCache.Unlock()

	return probes, nil
}

// parseServiceProbes parses the nmap-service-probes file format
func parseServiceProbes(data string) ([]ServiceProbeInfo, error) {
	lines := strings.Split(data, "\n")
	var probes []ServiceProbeInfo
	var currentProbe *struct {
		protocol   string
		probeName  string
		sendString string
		ports      []int
		sslPorts   []int
		rarity     int
	}

	for lineNum, line := range lines {
		trimmed := strings.TrimSpace(line)

		// Skip empty lines
		if len(trimmed) == 0 {
			continue
		}

		// Check for disabled probe lines (lines starting with #DISABLED:)
		isDisabled := false
		if strings.HasPrefix(trimmed, disabledProbePrefix) {
			isDisabled = true
			trimmed = strings.TrimPrefix(trimmed, disabledProbePrefix)
		} else if strings.HasPrefix(trimmed, "#") {
			// Skip regular comments
			continue
		}

		// Parse Probe directive
		if strings.HasPrefix(trimmed, "Probe ") {
			parts := strings.Fields(trimmed)
			if len(parts) >= 3 {
				currentProbe = &struct {
					protocol   string
					probeName  string
					sendString string
					ports      []int
					sslPorts   []int
					rarity     int
				}{
					protocol:  parts[1],
					probeName: parts[2],
				}
				// Extract send string if present
				if idx := strings.Index(trimmed, parts[2]); idx != -1 {
					rest := trimmed[idx+len(parts[2]):]
					currentProbe.sendString = strings.TrimSpace(rest)
				}
			}
			continue
		}

		// Parse ports directive
		if strings.HasPrefix(trimmed, "ports ") && currentProbe != nil {
			portsStr := strings.TrimPrefix(trimmed, "ports ")
			currentProbe.ports = parsePortList(portsStr)
			continue
		}

		// Parse sslports directive
		if strings.HasPrefix(trimmed, "sslports ") && currentProbe != nil {
			portsStr := strings.TrimPrefix(trimmed, "sslports ")
			currentProbe.sslPorts = parsePortList(portsStr)
			continue
		}

		// Parse rarity directive
		if strings.HasPrefix(trimmed, "rarity ") && currentProbe != nil {
			rarityStr := strings.TrimPrefix(trimmed, "rarity ")
			if rarity, err := strconv.Atoi(strings.TrimSpace(rarityStr)); err == nil {
				currentProbe.rarity = rarity
			}
			continue
		}

		// Parse match/softmatch directives
		if (strings.HasPrefix(trimmed, "match ") || strings.HasPrefix(trimmed, "softmatch ")) && currentProbe != nil {
			probe, err := parseMatchLine(trimmed, currentProbe, lineNum+1, line, !isDisabled)
			if err == nil && probe != nil {
				probes = append(probes, *probe)
			}
		}
	}

	// Generate IDs for all probes using the same enumeration as the service matching code
	// This creates IDs like "http-1", "http-2", "smtp-1", etc.
	serviceCounters := make(map[string]int)
	for i := range probes {
		service := probes[i].Service
		serviceCounters[service]++
		probes[i].ID = fmt.Sprintf("%s-%d", service, serviceCounters[service])
	}

	return probes, nil
}

// parsePortList parses a comma-separated list of ports
func parsePortList(portsStr string) []int {
	var ports []int
	parts := strings.Split(portsStr, ",")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if port, err := strconv.Atoi(part); err == nil {
			ports = append(ports, port)
		}
	}
	return ports
}

// parseMatchLine parses a match or softmatch line
func parseMatchLine(line string, currentProbe *struct {
	protocol   string
	probeName  string
	sendString string
	ports      []int
	sslPorts   []int
	rarity     int
}, lineNum int, rawLine string, enabled bool) (*ServiceProbeInfo, error) {
	isSoftMatch := strings.HasPrefix(line, "softmatch ")
	var prefix string
	if isSoftMatch {
		prefix = "softmatch "
	} else {
		prefix = "match "
	}

	line = strings.TrimPrefix(line, prefix)
	fields := strings.Fields(line)
	if len(fields) < 2 {
		return nil, errors.New("invalid match line format")
	}

	probe := &ServiceProbeInfo{
		Service:       fields[0],
		IsSoftMatch:   isSoftMatch,
		Ports:         currentProbe.ports,
		SSLPorts:      currentProbe.sslPorts,
		Rarity:        currentProbe.rarity,
		ProbeName:     currentProbe.probeName,
		ProbeProtocol: currentProbe.protocol,
		Protocol:      currentProbe.protocol,
		SendString:    currentProbe.sendString,
		RawLine:       rawLine,
		LineNumber:    lineNum,
		Enabled:       enabled,
	}

	// Parse the pattern and metadata
	// Format: service m/pattern/flags metadata
	rest := line[len(fields[0]):]
	rest = strings.TrimSpace(rest)

	// Extract pattern
	if strings.HasPrefix(rest, "m") {
		// Find delimiter
		if len(rest) < 2 {
			return nil, errors.New("invalid pattern format")
		}
		delim := rest[1]
		// Find closing delimiter
		endIdx := strings.IndexByte(rest[2:], delim)
		if endIdx == -1 {
			return nil, errors.New("unclosed pattern delimiter")
		}
		pattern := rest[2 : 2+endIdx]
		probe.Pattern = pattern

		// Parse flags and metadata
		remaining := rest[2+endIdx+1:]
		probe.parseMetadata(remaining)
	}

	return probe, nil
}

// parseMetadata parses the metadata fields from a match line
func (p *ServiceProbeInfo) parseMetadata(metadata string) {
	// Metadata format: [flags] p/product/ v/version/ i/info/ h/hostname/ o/os/ d/devicetype/ cpe:/cpe/
	metadata = strings.TrimSpace(metadata)

	for len(metadata) > 0 {
		metadata = strings.TrimSpace(metadata)
		if len(metadata) == 0 {
			break
		}

		// Check for field markers
		if strings.HasPrefix(metadata, "p/") {
			p.Product, metadata = extractField(metadata, "p/")
		} else if strings.HasPrefix(metadata, "v/") {
			p.Version, metadata = extractField(metadata, "v/")
		} else if strings.HasPrefix(metadata, "i/") {
			p.Info, metadata = extractField(metadata, "i/")
		} else if strings.HasPrefix(metadata, "h/") {
			p.Hostname, metadata = extractField(metadata, "h/")
		} else if strings.HasPrefix(metadata, "o/") {
			p.OS, metadata = extractField(metadata, "o/")
		} else if strings.HasPrefix(metadata, "d/") {
			p.DeviceType, metadata = extractField(metadata, "d/")
		} else if strings.HasPrefix(metadata, "cpe:/") {
			cpe, rest := extractField(metadata, "cpe:/")
			p.CPEs = append(p.CPEs, "cpe:/"+cpe)
			metadata = rest
		} else {
			// Skip unknown character
			metadata = metadata[1:]
		}
	}
}

// extractField extracts a field value enclosed in delimiters
func extractField(str, prefix string) (value string, remaining string) {
	str = strings.TrimPrefix(str, prefix)
	if len(str) == 0 {
		return "", ""
	}

	// Find closing delimiter
	endIdx := strings.Index(str, "/")
	if endIdx == -1 {
		// Take rest of string
		return str, ""
	}

	return str[:endIdx], str[endIdx+1:]
}

// generateProbeID generates a unique ID for a probe
func generateProbeID(probe *ServiceProbeInfo) string {
	// Use hash of service, pattern, and line number for uniqueness
	h := sha256.New()
	h.Write([]byte(fmt.Sprintf("%s:%s:%d", probe.Service, probe.Pattern, probe.LineNumber)))
	return fmt.Sprintf("%x", h.Sum(nil))[:16]
}

// handleServiceProbes returns all service probes with optional filtering and pagination
// Also handles POST for creating new probes
func (s *Server) handleServiceProbes(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		// Continue with listing
	case http.MethodPost:
		s.handleCreateServiceProbe(w, r)
		return
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	probes, err := loadServiceProbes()
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to load service probes: %v", err), http.StatusInternalServerError)
		return
	}

	// Parse query parameters
	query := r.URL.Query()
	search := strings.ToLower(query.Get("search"))
	protocol := query.Get("protocol")
	service := query.Get("service")
	matchType := query.Get("matchType")
	offset, _ := strconv.Atoi(query.Get("offset"))
	limit, _ := strconv.Atoi(query.Get("limit"))

	if limit <= 0 || limit > 1000 {
		limit = 100
	}

	// Filter probes
	var filtered []ServiceProbeInfo
	for _, probe := range probes {
		// Apply filters
		if search != "" {
			searchMatch := strings.Contains(strings.ToLower(probe.Service), search) ||
				strings.Contains(strings.ToLower(probe.Product), search) ||
				strings.Contains(strings.ToLower(probe.Pattern), search) ||
				strings.Contains(strings.ToLower(probe.ProbeName), search) ||
				strings.Contains(strings.ToLower(probe.ID), search)
			if !searchMatch {
				continue
			}
		}

		if protocol != "" && protocol != "all" {
			if !strings.EqualFold(probe.Protocol, protocol) {
				continue
			}
		}

		if service != "" && service != "all" {
			if !strings.EqualFold(probe.Service, service) {
				continue
			}
		}

		if matchType != "" && matchType != "all" {
			if matchType == "match" && probe.IsSoftMatch {
				continue
			}
			if matchType == "softmatch" && !probe.IsSoftMatch {
				continue
			}
		}

		filtered = append(filtered, probe)
	}

	totalCount := len(filtered)

	// Apply pagination
	if offset >= len(filtered) {
		filtered = []ServiceProbeInfo{}
	} else {
		end := offset + limit
		if end > len(filtered) {
			end = len(filtered)
		}
		filtered = filtered[offset:end]
	}

	response := ServiceProbesResponse{
		Probes:     filtered,
		TotalCount: totalCount,
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(response); err != nil {
		http.Error(w, fmt.Sprintf("Failed to encode response: %v", err), http.StatusInternalServerError)
	}
}

// CreateServiceProbeRequest represents a request to create a new service probe
type CreateServiceProbeRequest struct {
	Service    string `json:"service"`
	Pattern    string `json:"pattern"`
	Product    string `json:"product"`
	Version    string `json:"version"`
	Info       string `json:"info"`
	Hostname   string `json:"hostname"`
	OS         string `json:"os"`
	DeviceType string `json:"deviceType"`
	Protocol   string `json:"protocol"`
	ProbeName  string `json:"probeName"`
	Enabled    bool   `json:"enabled"`
}

// handleCreateServiceProbe creates a new service probe
func (s *Server) handleCreateServiceProbe(w http.ResponseWriter, r *http.Request) {
	var req CreateServiceProbeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, fmt.Sprintf("Invalid request body: %v", err), http.StatusBadRequest)
		return
	}

	// Validate required fields
	if req.Service == "" {
		http.Error(w, "Service name is required", http.StatusBadRequest)
		return
	}
	if req.Pattern == "" {
		http.Error(w, "Pattern is required", http.StatusBadRequest)
		return
	}

	// Set defaults
	if req.Protocol == "" {
		req.Protocol = "TCP"
	}
	if req.ProbeName == "" {
		req.ProbeName = "NULL"
	}

	filePath := getServiceProbesFilePath()

	// Read the file
	data, err := ioutil.ReadFile(filePath)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to read file: %v", err), http.StatusInternalServerError)
		return
	}

	// Find the right place to insert the new probe
	// We'll look for the first Probe directive that matches the protocol
	// or append to the end of the file
	lines := strings.Split(string(data), "\n")

	// Create the new match line
	newProbe := &ServiceProbeInfo{
		Service:    req.Service,
		Pattern:    req.Pattern,
		Product:    req.Product,
		Version:    req.Version,
		Info:       req.Info,
		Hostname:   req.Hostname,
		OS:         req.OS,
		DeviceType: req.DeviceType,
		Protocol:   req.Protocol,
		ProbeName:  req.ProbeName,
		Enabled:    req.Enabled,
	}

	newLine := reconstructMatchLine(newProbe)

	// Find the best place to insert - after the last match/softmatch for the NULL probe of matching protocol
	insertIdx := -1
	inTargetProbe := false
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)

		// Look for Probe directive
		if strings.HasPrefix(trimmed, "Probe ") {
			parts := strings.Fields(trimmed)
			if len(parts) >= 3 {
				probeProtocol := parts[1]
				probeName := parts[2]
				// Check if this is a good probe to append to (same protocol, NULL probe preferred)
				if strings.EqualFold(probeProtocol, req.Protocol) {
					if probeName == req.ProbeName || probeName == "NULL" {
						inTargetProbe = true
					} else {
						inTargetProbe = false
					}
				} else {
					inTargetProbe = false
				}
			}
		}

		// Track the last match/softmatch line in our target probe section
		if inTargetProbe && (strings.HasPrefix(trimmed, "match ") || strings.HasPrefix(trimmed, "softmatch ") ||
			strings.HasPrefix(trimmed, disabledProbePrefix+"match ") || strings.HasPrefix(trimmed, disabledProbePrefix+"softmatch ")) {
			insertIdx = i + 1
		}
	}

	// If we didn't find a good place, append to the end
	if insertIdx == -1 {
		insertIdx = len(lines)
	}

	// Insert the new line
	newLines := make([]string, 0, len(lines)+1)
	newLines = append(newLines, lines[:insertIdx]...)
	newLines = append(newLines, newLine)
	newLines = append(newLines, lines[insertIdx:]...)

	// Write back to file
	newData := strings.Join(newLines, "\n")
	if err := ioutil.WriteFile(filePath, []byte(newData), 0644); err != nil {
		http.Error(w, fmt.Sprintf("Failed to write file: %v", err), http.StatusInternalServerError)
		return
	}

	// Invalidate cache
	serviceProbesCache.Lock()
	serviceProbesCache.probes = nil
	serviceProbesCache.Unlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"message": "Service probe created successfully",
	})
}

// handleServiceProbeRouter routes requests for individual probes
func (s *Server) handleServiceProbeRouter(w http.ResponseWriter, r *http.Request) {
	// Extract path parts: /api/service-probes/{id} or /api/service-probes/{id}/toggle
	pathParts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if len(pathParts) < 3 {
		http.Error(w, "Invalid path", http.StatusBadRequest)
		return
	}

	// Check if this is a toggle request: /api/service-probes/{id}/toggle
	if len(pathParts) >= 4 && pathParts[len(pathParts)-1] == "toggle" {
		s.handleToggleServiceProbe(w, r)
		return
	}

	id := pathParts[len(pathParts)-1]

	switch r.Method {
	case http.MethodGet:
		s.handleGetServiceProbe(w, r, id)
	case http.MethodPut:
		s.handleUpdateServiceProbe(w, r, id)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleGetServiceProbe returns a single service probe by ID
func (s *Server) handleGetServiceProbe(w http.ResponseWriter, r *http.Request, id string) {
	probes, err := loadServiceProbes()
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to load service probes: %v", err), http.StatusInternalServerError)
		return
	}

	for _, probe := range probes {
		if probe.ID == id {
			w.Header().Set("Content-Type", "application/json")
			if err := json.NewEncoder(w).Encode(probe); err != nil {
				http.Error(w, fmt.Sprintf("Failed to encode response: %v", err), http.StatusInternalServerError)
			}
			return
		}
	}

	http.Error(w, "Probe not found", http.StatusNotFound)
}

// handleUpdateServiceProbe updates a service probe
func (s *Server) handleUpdateServiceProbe(w http.ResponseWriter, r *http.Request, id string) {
	var updates ServiceProbeInfo
	if err := json.NewDecoder(r.Body).Decode(&updates); err != nil {
		http.Error(w, fmt.Sprintf("Invalid request body: %v", err), http.StatusBadRequest)
		return
	}

	filePath := getServiceProbesFilePath()

	// Read the file
	data, err := ioutil.ReadFile(filePath)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to read file: %v", err), http.StatusInternalServerError)
		return
	}

	lines := strings.Split(string(data), "\n")
	probes, err := loadServiceProbes()
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to load probes: %v", err), http.StatusInternalServerError)
		return
	}

	// Find the probe to update
	var targetProbe *ServiceProbeInfo
	for _, probe := range probes {
		if probe.ID == id {
			targetProbe = &probe
			break
		}
	}

	if targetProbe == nil {
		http.Error(w, "Probe not found", http.StatusNotFound)
		return
	}

	// Update the line in the file
	lineIdx := targetProbe.LineNumber - 1
	if lineIdx >= 0 && lineIdx < len(lines) {
		// Reconstruct the line with updates
		newLine := reconstructMatchLine(&updates)
		lines[lineIdx] = newLine
	}

	// Write back to file
	newData := strings.Join(lines, "\n")
	if err := ioutil.WriteFile(filePath, []byte(newData), 0644); err != nil {
		http.Error(w, fmt.Sprintf("Failed to write file: %v", err), http.StatusInternalServerError)
		return
	}

	// Invalidate cache
	serviceProbesCache.Lock()
	serviceProbesCache.probes = nil
	serviceProbesCache.Unlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"message": "Service probe updated successfully",
	})
}

// reconstructMatchLine reconstructs a match/softmatch line from a ServiceProbeInfo
func reconstructMatchLine(probe *ServiceProbeInfo) string {
	var buf bytes.Buffer

	// Add disabled prefix if not enabled
	if !probe.Enabled {
		buf.WriteString(disabledProbePrefix)
	}

	// Write match/softmatch
	if probe.IsSoftMatch {
		buf.WriteString("softmatch ")
	} else {
		buf.WriteString("match ")
	}

	// Write service and pattern
	buf.WriteString(probe.Service)
	buf.WriteString(" m/")
	buf.WriteString(probe.Pattern)
	buf.WriteString("/")

	// Write metadata
	if probe.Product != "" {
		buf.WriteString(" p/")
		buf.WriteString(probe.Product)
		buf.WriteString("/")
	}
	if probe.Version != "" {
		buf.WriteString(" v/")
		buf.WriteString(probe.Version)
		buf.WriteString("/")
	}
	if probe.Info != "" {
		buf.WriteString(" i/")
		buf.WriteString(probe.Info)
		buf.WriteString("/")
	}
	if probe.Hostname != "" {
		buf.WriteString(" h/")
		buf.WriteString(probe.Hostname)
		buf.WriteString("/")
	}
	if probe.OS != "" {
		buf.WriteString(" o/")
		buf.WriteString(probe.OS)
		buf.WriteString("/")
	}
	if probe.DeviceType != "" {
		buf.WriteString(" d/")
		buf.WriteString(probe.DeviceType)
		buf.WriteString("/")
	}
	for _, cpe := range probe.CPEs {
		buf.WriteString(" ")
		buf.WriteString(cpe)
	}

	return buf.String()
}

// ToggleServiceProbeRequest represents a request to toggle a probe's enabled state
type ToggleServiceProbeRequest struct {
	Enabled bool `json:"enabled"`
}

// handleToggleServiceProbe toggles a service probe's enabled state
func (s *Server) handleToggleServiceProbe(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPatch {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Extract ID from path: /api/service-probes/{id}/toggle
	pathParts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if len(pathParts) < 4 {
		http.Error(w, "Invalid path", http.StatusBadRequest)
		return
	}
	id := pathParts[len(pathParts)-2]

	var req ToggleServiceProbeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, fmt.Sprintf("Invalid request body: %v", err), http.StatusBadRequest)
		return
	}

	filePath := getServiceProbesFilePath()

	// Read the file
	data, err := ioutil.ReadFile(filePath)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to read file: %v", err), http.StatusInternalServerError)
		return
	}

	lines := strings.Split(string(data), "\n")
	probes, err := loadServiceProbes()
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to load probes: %v", err), http.StatusInternalServerError)
		return
	}

	// Find the probe to toggle
	var targetProbe *ServiceProbeInfo
	for _, probe := range probes {
		if probe.ID == id {
			targetProbe = &probe
			break
		}
	}

	if targetProbe == nil {
		http.Error(w, "Probe not found", http.StatusNotFound)
		return
	}

	// Update the line in the file
	lineIdx := targetProbe.LineNumber - 1
	if lineIdx >= 0 && lineIdx < len(lines) {
		currentLine := lines[lineIdx]
		var newLine string

		if req.Enabled {
			// Enable: remove the #DISABLED: prefix if present
			if strings.HasPrefix(strings.TrimSpace(currentLine), disabledProbePrefix) {
				// Preserve leading whitespace
				leadingSpaces := len(currentLine) - len(strings.TrimLeft(currentLine, " \t"))
				newLine = currentLine[:leadingSpaces] + strings.TrimPrefix(strings.TrimSpace(currentLine), disabledProbePrefix)
			} else {
				newLine = currentLine // Already enabled
			}
		} else {
			// Disable: add the #DISABLED: prefix if not present
			if !strings.HasPrefix(strings.TrimSpace(currentLine), disabledProbePrefix) {
				// Preserve leading whitespace
				leadingSpaces := len(currentLine) - len(strings.TrimLeft(currentLine, " \t"))
				newLine = currentLine[:leadingSpaces] + disabledProbePrefix + strings.TrimSpace(currentLine)
			} else {
				newLine = currentLine // Already disabled
			}
		}
		lines[lineIdx] = newLine
	}

	// Write back to file
	newData := strings.Join(lines, "\n")
	if err := ioutil.WriteFile(filePath, []byte(newData), 0644); err != nil {
		http.Error(w, fmt.Sprintf("Failed to write file: %v", err), http.StatusInternalServerError)
		return
	}

	// Invalidate cache
	serviceProbesCache.Lock()
	serviceProbesCache.probes = nil
	serviceProbesCache.Unlock()

	status := "disabled"
	if req.Enabled {
		status = "enabled"
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"message": fmt.Sprintf("Service probe %s", status),
		"enabled": req.Enabled,
	})
}

// handleTestServiceProbe tests a probe regex against sample input
func (s *Server) handleTestServiceProbe(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req TestProbeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, fmt.Sprintf("Invalid request body: %v", err), http.StatusBadRequest)
		return
	}

	response := TestProbeResponse{
		CapturedGroups: make(map[string]string),
	}

	// Compile the regex
	re, err := regexp.Compile(req.Pattern)
	if err != nil {
		response.Error = fmt.Sprintf("Failed to compile regex: %v", err)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
		return
	}

	// Test the pattern
	matches := re.FindStringSubmatch(req.SampleInput)
	if matches != nil {
		response.Matches = true

		// Extract named groups
		names := re.SubexpNames()
		for i, name := range names {
			if i > 0 && i < len(matches) && name != "" {
				response.CapturedGroups[name] = matches[i]
			}
		}

		// Also add numbered groups
		for i := 1; i < len(matches); i++ {
			key := fmt.Sprintf("$%d", i)
			response.CapturedGroups[key] = matches[i]
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// handleExportServiceProbes exports the service probes file
func (s *Server) handleExportServiceProbes(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	filePath := getServiceProbesFilePath()
	data, err := ioutil.ReadFile(filePath)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to read file: %v", err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/plain")
	w.Header().Set("Content-Disposition", "attachment; filename=nmap-service-probes")
	w.Write(data)
}

// handleImportServiceProbes imports a service probes file
func (s *Server) handleImportServiceProbes(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Parse multipart form
	err := r.ParseMultipartForm(32 << 20) // 32 MB max
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to parse form: %v", err), http.StatusBadRequest)
		return
	}

	file, _, err := r.FormFile("file")
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to get file: %v", err), http.StatusBadRequest)
		return
	}
	defer file.Close()

	// Read file contents
	data, err := io.ReadAll(file)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to read file: %v", err), http.StatusInternalServerError)
		return
	}

	// Validate by parsing
	probes, err := parseServiceProbes(string(data))
	if err != nil {
		http.Error(w, fmt.Sprintf("Invalid service probes file: %v", err), http.StatusBadRequest)
		return
	}

	// Backup current file
	filePath := getServiceProbesFilePath()
	backupPath := filePath + ".backup." + time.Now().Format("20060102-150405")
	if err := copyFile(filePath, backupPath); err != nil {
		http.Error(w, fmt.Sprintf("Failed to create backup: %v", err), http.StatusInternalServerError)
		return
	}

	// Write new file
	if err := ioutil.WriteFile(filePath, data, 0644); err != nil {
		http.Error(w, fmt.Sprintf("Failed to write file: %v", err), http.StatusInternalServerError)
		return
	}

	// Invalidate cache
	serviceProbesCache.Lock()
	serviceProbesCache.probes = nil
	serviceProbesCache.Unlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success":       true,
		"message":       "Service probes imported successfully",
		"importedCount": len(probes),
	})
}
