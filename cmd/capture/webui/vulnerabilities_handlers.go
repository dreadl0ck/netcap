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
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"

	"github.com/dreadl0ck/netcap/resolvers"
	"github.com/dreadl0ck/netcap/types"
	"github.com/dreadl0ck/netcap/utils"
)

// SoftwareInfo contains software details including flows and community IDs
type SoftwareInfo struct {
	Product      string   `json:"product"`
	Vendor       string   `json:"vendor"`
	Version      string   `json:"version"`
	Flows        []string `json:"flows"`
	CommunityIDs []string `json:"communityIds"` // Community IDs for cross-tool correlation
}

// VulnerabilitySummary represents aggregated vulnerability information
type VulnerabilitySummary struct {
	ID           string        `json:"id"`
	Description  string        `json:"description"`
	Severity     string        `json:"severity"`
	V2Score      string        `json:"v2Score"`
	AccessVector string        `json:"accessVector"`
	Versions     []string      `json:"versions"`
	Count        int           `json:"count"`
	Software     *SoftwareInfo `json:"software"`     // Software details including flows
	Affected     int           `json:"affected"`     // Number of affected hosts
	CommunityIDs []string      `json:"communityIds"` // Community IDs for cross-tool correlation
}

// ExploitSummary represents aggregated exploit information
type ExploitSummary struct {
	ID           string        `json:"id"`
	Description  string        `json:"description"`
	File         string        `json:"file"`
	Date         string        `json:"date"`
	Author       string        `json:"author"`
	Type         string        `json:"type"`
	Platform     string        `json:"platform"`
	Port         string        `json:"port"`
	Count        int           `json:"count"`
	Software     *SoftwareInfo `json:"software"`     // Software details including flows
	Affected     int           `json:"affected"`     // Number of affected hosts
	CommunityIDs []string      `json:"communityIds"` // Community IDs for cross-tool correlation
}

// HostVulnerabilitySummary represents a host and its vulnerabilities
type HostVulnerabilitySummary struct {
	Host            string `json:"host"`
	Vulnerabilities int    `json:"vulnerabilities"`
	Exploits        int    `json:"exploits"`
	TopSeverity     string `json:"topSeverity"`
	SoftwareCount   int    `json:"softwareCount"`
}

// VulnerabilitiesResponse contains the aggregated data
type VulnerabilitiesResponse struct {
	Vulnerabilities []VulnerabilitySummary     `json:"vulnerabilities"`
	Exploits        []ExploitSummary           `json:"exploits"`
	AffectedHosts   []HostVulnerabilitySummary `json:"affectedHosts"`
	TotalVulns      int                        `json:"totalVulns"`
	TotalExploits   int                        `json:"totalExploits"`
}

// handleVulnerabilities returns aggregated vulnerability and exploit data
func (s *Server) handleVulnerabilities(w http.ResponseWriter, r *http.Request) {
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

	data, err := readVulnerabilitiesAndExploits(outDir)
	if err != nil {
		log.Printf("[WebUI] Failed to read vulnerabilities/exploits: %v", err)
		http.Error(w, "Failed to read vulnerabilities/exploits", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(data)
}

// readVulnerabilitiesAndExploits reads and aggregates Vulnerability and Exploit records
func readVulnerabilitiesAndExploits(outDir string) (*VulnerabilitiesResponse, error) {
	response := &VulnerabilitiesResponse{
		Vulnerabilities: []VulnerabilitySummary{},
		Exploits:        []ExploitSummary{},
		AffectedHosts:   []HostVulnerabilitySummary{},
	}

	// Maps for aggregation
	vulnMap := make(map[string]*VulnerabilitySummary)
	exploitMap := make(map[string]*ExploitSummary)
	hostMap := make(map[string]*HostVulnerabilitySummary)

	// Create a map of MAC addresses to IP addresses (from DeviceProfile)
	log.Printf("[WebUI][Vulnerabilities] Building MAC-to-IP mapping from directory: %s", outDir)
	macToIP := buildMacToIPMap(outDir)

	// Create a map of software product+version to hosts (from IPProfile)
	log.Printf("[WebUI][Vulnerabilities] Building software-to-hosts mapping from directory: %s", outDir)
	softwareToHosts := buildSoftwareToHostsMap(outDir)

	// 1. Read Vulnerabilities
	vulnPath := filepath.Join(outDir, "Vulnerability.ncap.gz")
	if _, err := os.Stat(vulnPath); err == nil {
		log.Printf("[WebUI][Vulnerabilities] Processing vulnerability records from: %s", vulnPath)
		if err := processVulnerabilities(vulnPath, vulnMap, hostMap, macToIP, softwareToHosts); err != nil {
			log.Printf("[WebUI] Warning: Failed to process vulnerabilities: %v", err)
		}
	} else {
		log.Printf("[WebUI][Vulnerabilities] No vulnerability file found at: %s", vulnPath)
	}

	// 2. Read Exploits
	exploitPath := filepath.Join(outDir, "Exploit.ncap.gz")
	if _, err := os.Stat(exploitPath); err == nil {
		log.Printf("[WebUI][Vulnerabilities] Processing exploit records from: %s", exploitPath)
		if err := processExploits(exploitPath, exploitMap, hostMap, macToIP, softwareToHosts); err != nil {
			log.Printf("[WebUI] Warning: Failed to process exploits: %v", err)
		}
	} else {
		log.Printf("[WebUI][Vulnerabilities] No exploit file found at: %s", exploitPath)
	}

	// Convert maps to slices
	for _, v := range vulnMap {
		response.Vulnerabilities = append(response.Vulnerabilities, *v)
	}
	for _, e := range exploitMap {
		response.Exploits = append(response.Exploits, *e)
	}
	for _, h := range hostMap {
		response.AffectedHosts = append(response.AffectedHosts, *h)
	}

	// Sort slices
	sort.Slice(response.Vulnerabilities, func(i, j int) bool {
		return response.Vulnerabilities[i].Count > response.Vulnerabilities[j].Count
	})
	sort.Slice(response.Exploits, func(i, j int) bool {
		return response.Exploits[i].Count > response.Exploits[j].Count
	})
	sort.Slice(response.AffectedHosts, func(i, j int) bool {
		return response.AffectedHosts[i].Vulnerabilities > response.AffectedHosts[j].Vulnerabilities
	})

	response.TotalVulns = len(response.Vulnerabilities)
	response.TotalExploits = len(response.Exploits)

	log.Printf("[WebUI][Vulnerabilities] Summary: %d unique vulnerabilities, %d unique exploits, %d affected hosts",
		response.TotalVulns, response.TotalExploits, len(response.AffectedHosts))

	return response, nil
}

// buildMacToIPMap creates a mapping from MAC addresses to IP addresses
func buildMacToIPMap(outDir string) map[string][]string {
	macToIP := make(map[string][]string)

	// Read DeviceProfile records to find MAC to IP mappings
	deviceProfilePath := filepath.Join(outDir, "DeviceProfile.ncap.gz")
	if _, err := os.Stat(deviceProfilePath); err != nil {
		log.Printf("[WebUI][Vulnerabilities] DeviceProfile file not found: %s", deviceProfilePath)
		return macToIP
	}

	reader, err := NewAuditRecordReader(deviceProfilePath)
	if err != nil {
		log.Printf("[WebUI][Vulnerabilities] Failed to create reader for DeviceProfile: %v", err)
		return macToIP
	}
	defer reader.Close()

	if _, err := reader.ReadHeader(); err != nil {
		log.Printf("[WebUI][Vulnerabilities] Failed to read DeviceProfile header: %v", err)
		return macToIP
	}

	deviceProfileCount := 0
	totalIPMappings := 0
	for {
		record, err := reader.NextRecord()
		if err != nil {
			if err == io.EOF {
				break
			}
			continue
		}

		deviceProfile, ok := record.(*types.DeviceProfile)
		if !ok || deviceProfile.MacAddr == "" {
			continue
		}

		deviceProfileCount++

		// Map MAC address to all associated IP addresses
		for _, ip := range deviceProfile.DeviceIPs {
			if ip != "" {
				macToIP[deviceProfile.MacAddr] = append(macToIP[deviceProfile.MacAddr], ip)
				totalIPMappings++
			}
		}
	}

	log.Printf("[WebUI][Vulnerabilities] Built MAC-to-IP map: %d device profiles, %d total IP mappings, %d unique MACs",
		deviceProfileCount, totalIPMappings, len(macToIP))

	// Log a few sample mappings for debugging
	if len(macToIP) > 0 {
		sampleCount := 0
		for mac, ips := range macToIP {
			if sampleCount < 5 {
				log.Printf("[WebUI][Vulnerabilities] Sample MAC mapping: %s -> %d IPs", mac, len(ips))
				sampleCount++
			}
		}
	}

	return macToIP
}

// buildSoftwareToHostsMap creates a mapping from software product+version to host IPs
func buildSoftwareToHostsMap(outDir string) map[string][]string {
	softwareToHosts := make(map[string][]string)

	// Read IPProfile records to find which hosts have which software
	ipProfilePath := filepath.Join(outDir, "IPProfile.ncap.gz")
	if _, err := os.Stat(ipProfilePath); err != nil {
		log.Printf("[WebUI][Vulnerabilities] IPProfile file not found: %s", ipProfilePath)
		return softwareToHosts
	}

	reader, err := NewAuditRecordReader(ipProfilePath)
	if err != nil {
		log.Printf("[WebUI][Vulnerabilities] Failed to create reader for IPProfile: %v", err)
		return softwareToHosts
	}
	defer reader.Close()

	if _, err := reader.ReadHeader(); err != nil {
		log.Printf("[WebUI][Vulnerabilities] Failed to read IPProfile header: %v", err)
		return softwareToHosts
	}

	ipProfileCount := 0
	appCount := 0
	for {
		record, err := reader.NextRecord()
		if err != nil {
			if err == io.EOF {
				break
			}
			continue
		}

		ipProfile, ok := record.(*types.IPProfile)
		if !ok || ipProfile.Addr == "" {
			continue
		}

		ipProfileCount++

		// Index by application names (which often match software product names)
		for _, app := range ipProfile.Applications {
			if app != "" {
				softwareToHosts[app] = append(softwareToHosts[app], ipProfile.Addr)
				appCount++
			}
		}
	}

	log.Printf("[WebUI][Vulnerabilities] Built software-to-hosts map: %d IP profiles, %d applications, %d unique software products",
		ipProfileCount, appCount, len(softwareToHosts))

	// Log a few sample mappings for debugging
	if len(softwareToHosts) > 0 {
		sampleCount := 0
		for software, hosts := range softwareToHosts {
			if sampleCount < 5 {
				log.Printf("[WebUI][Vulnerabilities] Sample mapping: %s -> %d hosts", software, len(hosts))
				sampleCount++
			}
		}
	}

	return softwareToHosts
}

func processVulnerabilities(path string, vulnMap map[string]*VulnerabilitySummary, hostMap map[string]*HostVulnerabilitySummary, macToIP map[string][]string, softwareToHosts map[string][]string) error {
	reader, err := NewAuditRecordReader(path)
	if err != nil {
		return err
	}
	defer reader.Close()

	if _, err := reader.ReadHeader(); err != nil {
		return err
	}

	recordCount := 0
	vulnsWithSoftware := 0
	vulnsWithDeviceProfiles := 0
	vulnsWithMatchedHosts := 0
	totalHostsFromDeviceProfiles := 0
	totalHostsFromSoftwareMap := 0

	for {
		record, err := reader.NextRecord()
		if err != nil {
			if err == io.EOF {
				break
			}
			continue
		}

		v, ok := record.(*types.Vulnerability)
		if !ok {
			continue
		}

		recordCount++

		// Update vuln summary
		if _, exists := vulnMap[v.ID]; !exists {
			var softwareInfo *SoftwareInfo
			if v.Software != nil && (v.Software.Product != "" || v.Software.Vendor != "" || v.Software.Version != "") {
				softwareInfo = &SoftwareInfo{
					Product:      v.Software.Product,
					Vendor:       v.Software.Vendor,
					Version:      v.Software.Version,
					Flows:        v.Software.Flows,
					CommunityIDs: v.Software.CommunityIDs,
				}
			}
			vulnMap[v.ID] = &VulnerabilitySummary{
				ID:           v.ID,
				Description:  v.Description,
				Severity:     v.Severity,
				V2Score:      v.V2Score,
				AccessVector: v.AccessVector,
				Versions:     v.Versions,
				Software:     softwareInfo,
				Count:        0,
				Affected:     0,
				CommunityIDs: v.CommunityIDs, // Direct community IDs from the vulnerability record
			}
		} else {
			// Update software info if we don't have it yet but this record does
			if vulnMap[v.ID].Software == nil && v.Software != nil && (v.Software.Product != "" || v.Software.Vendor != "" || v.Software.Version != "") {
				vulnMap[v.ID].Software = &SoftwareInfo{
					Product:      v.Software.Product,
					Vendor:       v.Software.Vendor,
					Version:      v.Software.Version,
					Flows:        v.Software.Flows,
					CommunityIDs: v.Software.CommunityIDs,
				}
			}
			// Merge community IDs from this record
			for _, cid := range v.CommunityIDs {
				found := slices.Contains(vulnMap[v.ID].CommunityIDs, cid)
				if !found && cid != "" {
					vulnMap[v.ID].CommunityIDs = append(vulnMap[v.ID].CommunityIDs, cid)
				}
			}
		}
		vulnMap[v.ID].Count++

		// Count affected hosts based on software flows, device profiles, AND software-to-hosts mapping
		if v.Software != nil {
			vulnsWithSoftware++
			hostsAffected := make(map[string]bool) // Use map to deduplicate hosts

			// PRIORITY 1: Parse flows to directly extract source and destination IPs
			flowHostCount := 0
			for _, flowIdent := range v.Software.Flows {
				if flowIdent != "" {
					srcIP, _, dstIP, _ := utils.ParseFlowIdent(flowIdent)
					if srcIP != "" {
						hostsAffected[srcIP] = true
						flowHostCount++
					}
					if dstIP != "" {
						hostsAffected[dstIP] = true
						flowHostCount++
					}
				}
			}

			// PRIORITY 2: Try to get hosts from DeviceProfiles (MAC addresses) and map to IPs
			deviceProfileCount := 0
			for _, macAddr := range v.Software.DeviceProfiles {
				if macAddr != "" {
					deviceProfileCount++
					// Map MAC address to IP addresses
					if ips, found := macToIP[macAddr]; found {
						for _, ip := range ips {
							if ip != "" {
								hostsAffected[ip] = true
								totalHostsFromDeviceProfiles++
							}
						}
					} else {
						// If no IP mapping found, still use the MAC address as a fallback
						hostsAffected[macAddr] = true
						totalHostsFromDeviceProfiles++
					}
				}
			}
			if deviceProfileCount > 0 {
				vulnsWithDeviceProfiles++
			}

			// PRIORITY 3: Also try to get hosts from software product name
			softwareMapHosts := 0
			if v.Software.Product != "" {
				if hosts, found := softwareToHosts[v.Software.Product]; found {
					for _, host := range hosts {
						if host != "" {
							hostsAffected[host] = true
							softwareMapHosts++
							totalHostsFromSoftwareMap++
						}
					}
				}
			}

			// Update host map with all affected hosts
			for host := range hostsAffected {
				if _, exists := hostMap[host]; !exists {
					hostMap[host] = &HostVulnerabilitySummary{
						Host: host,
					}
				}
				hostMap[host].Vulnerabilities++
				// Simple top severity logic
				currentSev := severityToScore(hostMap[host].TopSeverity)
				newSev := severityToScore(v.Severity)
				if newSev > currentSev {
					hostMap[host].TopSeverity = v.Severity
				}
			}

			if len(hostsAffected) > 0 {
				vulnsWithMatchedHosts++
			}

			vulnMap[v.ID].Affected = len(hostsAffected)
		}
	}

	log.Printf("[WebUI][Vulnerabilities] Processed %d vulnerability records, %d with software, %d with device profiles, %d with matched hosts",
		recordCount, vulnsWithSoftware, vulnsWithDeviceProfiles, vulnsWithMatchedHosts)
	log.Printf("[WebUI][Vulnerabilities] Total hosts found: %d from DeviceProfiles, %d from software-to-hosts map",
		totalHostsFromDeviceProfiles, totalHostsFromSoftwareMap)
	log.Printf("[WebUI][Vulnerabilities] Final unique hosts in hostMap: %d", len(hostMap))

	return nil
}

func processExploits(path string, exploitMap map[string]*ExploitSummary, hostMap map[string]*HostVulnerabilitySummary, macToIP map[string][]string, softwareToHosts map[string][]string) error {
	reader, err := NewAuditRecordReader(path)
	if err != nil {
		return err
	}
	defer reader.Close()

	if _, err := reader.ReadHeader(); err != nil {
		return err
	}

	recordCount := 0
	exploitsWithSoftware := 0
	exploitsWithDeviceProfiles := 0
	exploitsWithMatchedHosts := 0
	totalHostsFromDeviceProfiles := 0
	totalHostsFromSoftwareMap := 0

	for {
		record, err := reader.NextRecord()
		if err != nil {
			if err == io.EOF {
				break
			}
			continue
		}

		e, ok := record.(*types.Exploit)
		if !ok {
			continue
		}

		recordCount++

		// Update exploit summary
		if _, exists := exploitMap[e.ID]; !exists {
			var softwareInfo *SoftwareInfo
			if e.Software != nil && (e.Software.Product != "" || e.Software.Vendor != "" || e.Software.Version != "") {
				softwareInfo = &SoftwareInfo{
					Product:      e.Software.Product,
					Vendor:       e.Software.Vendor,
					Version:      e.Software.Version,
					Flows:        e.Software.Flows,
					CommunityIDs: e.Software.CommunityIDs,
				}
			}
			exploitMap[e.ID] = &ExploitSummary{
				ID:           e.ID,
				Description:  e.Description,
				File:         e.File,
				Date:         e.Date,
				Author:       e.Author,
				Type:         e.Typ,
				Platform:     e.Platform,
				Port:         e.Port,
				Software:     softwareInfo,
				Count:        0,
				Affected:     0,
				CommunityIDs: e.CommunityIDs, // Direct community IDs from the exploit record
			}
		} else {
			// Update software info if we don't have it yet but this record does
			if exploitMap[e.ID].Software == nil && e.Software != nil && (e.Software.Product != "" || e.Software.Vendor != "" || e.Software.Version != "") {
				exploitMap[e.ID].Software = &SoftwareInfo{
					Product:      e.Software.Product,
					Vendor:       e.Software.Vendor,
					Version:      e.Software.Version,
					Flows:        e.Software.Flows,
					CommunityIDs: e.Software.CommunityIDs,
				}
			}
			// Merge community IDs from this record
			for _, cid := range e.CommunityIDs {
				found := slices.Contains(exploitMap[e.ID].CommunityIDs, cid)
				if !found && cid != "" {
					exploitMap[e.ID].CommunityIDs = append(exploitMap[e.ID].CommunityIDs, cid)
				}
			}
		}
		exploitMap[e.ID].Count++

		// Count affected hosts from flows, DeviceProfiles, AND software-to-hosts mapping
		if e.Software != nil {
			exploitsWithSoftware++
			hostsAffected := make(map[string]bool) // Use map to deduplicate hosts

			// PRIORITY 1: Parse flows to directly extract source and destination IPs
			flowHostCount := 0
			for _, flowIdent := range e.Software.Flows {
				if flowIdent != "" {
					srcIP, _, dstIP, _ := utils.ParseFlowIdent(flowIdent)
					if srcIP != "" {
						hostsAffected[srcIP] = true
						flowHostCount++
					}
					if dstIP != "" {
						hostsAffected[dstIP] = true
						flowHostCount++
					}
				}
			}

			// PRIORITY 2: Try to get hosts from DeviceProfiles (MAC addresses) and map to IPs
			deviceProfileCount := 0
			for _, macAddr := range e.Software.DeviceProfiles {
				if macAddr != "" {
					deviceProfileCount++
					// Map MAC address to IP addresses
					if ips, found := macToIP[macAddr]; found {
						for _, ip := range ips {
							if ip != "" {
								hostsAffected[ip] = true
								totalHostsFromDeviceProfiles++
							}
						}
					} else {
						// If no IP mapping found, still use the MAC address as a fallback
						hostsAffected[macAddr] = true
						totalHostsFromDeviceProfiles++
					}
				}
			}
			if deviceProfileCount > 0 {
				exploitsWithDeviceProfiles++
			}

			// PRIORITY 3: Also try to get hosts from software product name
			softwareMapHosts := 0
			if e.Software.Product != "" {
				if hosts, found := softwareToHosts[e.Software.Product]; found {
					for _, host := range hosts {
						if host != "" {
							hostsAffected[host] = true
							softwareMapHosts++
							totalHostsFromSoftwareMap++
						}
					}
				}
			}

			// Update host map with all affected hosts
			for host := range hostsAffected {
				if _, exists := hostMap[host]; !exists {
					hostMap[host] = &HostVulnerabilitySummary{
						Host: host,
					}
				}
				hostMap[host].Exploits++
			}

			if len(hostsAffected) > 0 {
				exploitsWithMatchedHosts++
			}

			exploitMap[e.ID].Affected = len(hostsAffected)
		}
	}

	log.Printf("[WebUI][Exploits] Processed %d exploit records, %d with software, %d with device profiles, %d with matched hosts",
		recordCount, exploitsWithSoftware, exploitsWithDeviceProfiles, exploitsWithMatchedHosts)
	log.Printf("[WebUI][Exploits] Total hosts found: %d from DeviceProfiles, %d from software-to-hosts map",
		totalHostsFromDeviceProfiles, totalHostsFromSoftwareMap)

	return nil
}

func severityToScore(severity string) int {
	switch severity {
	case "HIGH":
		return 3
	case "MEDIUM":
		return 2
	case "LOW":
		return 1
	default:
		return 0
	}
}

// handleExploitFileContent returns the contents of an exploit file
func (s *Server) handleExploitFileContent(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Get the file path from query parameter
	filePath := r.URL.Query().Get("file")
	if filePath == "" {
		http.Error(w, "File path is required", http.StatusBadRequest)
		return
	}

	// Security: prevent path traversal attacks by cleaning the path
	cleanPath := filepath.Clean(filePath)
	if strings.Contains(cleanPath, "..") {
		log.Printf("[WebUI][Exploit] Path traversal attempt detected: %s", filePath)
		http.Error(w, "Invalid file path", http.StatusBadRequest)
		return
	}

	// The file path from the database starts with "exploitdb/" (e.g., "exploitdb/exploits/linux/dos/34133.txt")
	// Strip this prefix since we'll construct the full path using DataBaseFolderPath
	cleanPath = strings.TrimPrefix(cleanPath, "exploitdb/")
	cleanPath = strings.TrimPrefix(cleanPath, "exploitdb\\") // Windows path separator

	// Construct the correct path: ~/.config/netcap/dbs/exploitdb/<relative-path>
	fullPath := filepath.Join(resolvers.DataBaseFolderPath, "exploitdb", cleanPath)

	// Read the file
	fileContent, err := os.ReadFile(fullPath)
	if err != nil {
		log.Printf("[WebUI][Exploit] Failed to read exploit file: %s", fullPath)
		log.Printf("[WebUI][Exploit] Original file path from database: %s", filePath)
		log.Printf("[WebUI][Exploit] Error: %v", err)

		// Return a helpful error message
		response := map[string]any{
			"error": "Exploit file not found. The exploitdb files may not be installed on this server.",
			"hint":  "Run 'net util -download-dbs' to download the latest database bundle including exploit files.",
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(response)
		return
	}

	log.Printf("[WebUI][Exploit] Successfully read exploit file: %s (size: %d bytes)", fullPath, len(fileContent))

	// Detect language from file extension
	language := detectLanguageFromPath(cleanPath)

	// Return the content with metadata
	response := map[string]any{
		"content":  string(fileContent),
		"language": language,
		"path":     cleanPath,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// detectLanguageFromPath attempts to determine the programming language from the file path
func detectLanguageFromPath(path string) string {
	ext := strings.ToLower(filepath.Ext(path))

	// Common exploit file extensions and their languages
	languageMap := map[string]string{
		".py":   "python",
		".rb":   "ruby",
		".pl":   "perl",
		".php":  "php",
		".sh":   "bash",
		".c":    "c",
		".cpp":  "cpp",
		".h":    "c",
		".java": "java",
		".js":   "javascript",
		".asp":  "vbscript",
		".vbs":  "vbscript",
		".ps1":  "powershell",
		".txt":  "text",
		".html": "html",
		".htm":  "html",
		".xml":  "xml",
		".sql":  "sql",
		".go":   "go",
		".cs":   "csharp",
		".vb":   "vbnet",
	}

	if lang, ok := languageMap[ext]; ok {
		return lang
	}

	// Check for common patterns in path
	lowerPath := strings.ToLower(path)
	if strings.Contains(lowerPath, "python") {
		return "python"
	} else if strings.Contains(lowerPath, "ruby") {
		return "ruby"
	} else if strings.Contains(lowerPath, "perl") {
		return "perl"
	} else if strings.Contains(lowerPath, "php") {
		return "php"
	} else if strings.Contains(lowerPath, "shell") || strings.Contains(lowerPath, "bash") {
		return "bash"
	}

	// Default to text
	return "text"
}
