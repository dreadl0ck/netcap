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

// VulnerabilitySummary represents aggregated vulnerability information
type VulnerabilitySummary struct {
	ID           string   `json:"id"`
	Description  string   `json:"description"`
	Severity     string   `json:"severity"`
	V2Score      string   `json:"v2Score"`
	AccessVector string   `json:"accessVector"`
	Versions     []string `json:"versions"`
	Count        int      `json:"count"`
	Software     string   `json:"software"` // Product name
	Affected     int      `json:"affected"` // Number of affected hosts
}

// ExploitSummary represents aggregated exploit information
type ExploitSummary struct {
	ID          string `json:"id"`
	Description string `json:"description"`
	File        string `json:"file"`
	Date        string `json:"date"`
	Author      string `json:"author"`
	Type        string `json:"type"`
	Platform    string `json:"platform"`
	Port        string `json:"port"`
	Count       int    `json:"count"`
	Software    string `json:"software"` // Product name
	Affected    int    `json:"affected"` // Number of affected hosts
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
	
	// Create a map of software product+version to hosts (from IPProfile)
	softwareToHosts := buildSoftwareToHostsMap(outDir)

	// 1. Read Vulnerabilities
	vulnPath := filepath.Join(outDir, "Vulnerability.ncap.gz")
	if _, err := os.Stat(vulnPath); err == nil {
		if err := processVulnerabilities(vulnPath, vulnMap, hostMap, softwareToHosts); err != nil {
			log.Printf("[WebUI] Warning: Failed to process vulnerabilities: %v", err)
		}
	}

	// 2. Read Exploits
	exploitPath := filepath.Join(outDir, "Exploit.ncap.gz")
	if _, err := os.Stat(exploitPath); err == nil {
		if err := processExploits(exploitPath, exploitMap, hostMap, softwareToHosts); err != nil {
			log.Printf("[WebUI] Warning: Failed to process exploits: %v", err)
		}
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

	return response, nil
}

// buildSoftwareToHostsMap creates a mapping from software product+version to host IPs
func buildSoftwareToHostsMap(outDir string) map[string][]string {
	softwareToHosts := make(map[string][]string)
	
	// Read IPProfile records to find which hosts have which software
	ipProfilePath := filepath.Join(outDir, "IPProfile.ncap.gz")
	if _, err := os.Stat(ipProfilePath); err != nil {
		return softwareToHosts
	}

	reader, err := NewAuditRecordReader(ipProfilePath)
	if err != nil {
		return softwareToHosts
	}
	defer reader.Close()

	if _, err := reader.ReadHeader(); err != nil {
		return softwareToHosts
	}

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

		// Index by application names (which often match software product names)
		for _, app := range ipProfile.Applications {
			if app != "" {
				softwareToHosts[app] = append(softwareToHosts[app], ipProfile.Addr)
			}
		}
	}

	return softwareToHosts
}

func processVulnerabilities(path string, vulnMap map[string]*VulnerabilitySummary, hostMap map[string]*HostVulnerabilitySummary, softwareToHosts map[string][]string) error {
	reader, err := NewAuditRecordReader(path)
	if err != nil {
		return err
	}
	defer reader.Close()

	if _, err := reader.ReadHeader(); err != nil {
		return err
	}

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

		// Update vuln summary
		if _, exists := vulnMap[v.ID]; !exists {
			vulnMap[v.ID] = &VulnerabilitySummary{
				ID:           v.ID,
				Description:  v.Description,
				Severity:     v.Severity,
				V2Score:      v.V2Score,
				AccessVector: v.AccessVector,
				Versions:     v.Versions,
				Software:     v.Software.Product,
				Count:        0,
				Affected:     0,
			}
		}
		vulnMap[v.ID].Count++

		// Count affected hosts based on software device profiles AND software-to-hosts mapping
		if v.Software != nil {
			hostsAffected := make(map[string]bool) // Use map to deduplicate hosts
			
			// Try to get hosts from DeviceProfiles (MAC addresses)
			for _, dev := range v.Software.DeviceProfiles {
				if dev != "" {
					hostsAffected[dev] = true
				}
			}
			
			// Also try to get hosts from software product name
			if v.Software.Product != "" {
				if hosts, found := softwareToHosts[v.Software.Product]; found {
					for _, host := range hosts {
						if host != "" {
							hostsAffected[host] = true
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
			
			vulnMap[v.ID].Affected = len(hostsAffected)
		}
	}
	return nil
}

func processExploits(path string, exploitMap map[string]*ExploitSummary, hostMap map[string]*HostVulnerabilitySummary, softwareToHosts map[string][]string) error {
	reader, err := NewAuditRecordReader(path)
	if err != nil {
		return err
	}
	defer reader.Close()

	if _, err := reader.ReadHeader(); err != nil {
		return err
	}

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

		// Update exploit summary
		if _, exists := exploitMap[e.ID]; !exists {
			exploitMap[e.ID] = &ExploitSummary{
				ID:          e.ID,
				Description: e.Description,
				File:        e.File,
				Date:        e.Date,
				Author:      e.Author,
				Type:        e.Typ,
				Platform:    e.Platform,
				Port:        e.Port,
				Software:    e.Software.Product,
				Count:       0,
				Affected:    0,
			}
		}
		exploitMap[e.ID].Count++

		// Count affected hosts from DeviceProfiles AND software-to-hosts mapping
		if e.Software != nil {
			hostsAffected := make(map[string]bool) // Use map to deduplicate hosts
			
			// Try to get hosts from DeviceProfiles (MAC addresses)
			for _, dev := range e.Software.DeviceProfiles {
				if dev != "" {
					hostsAffected[dev] = true
				}
			}
			
			// Also try to get hosts from software product name
			if e.Software.Product != "" {
				if hosts, found := softwareToHosts[e.Software.Product]; found {
					for _, host := range hosts {
						if host != "" {
							hostsAffected[host] = true
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
			
			exploitMap[e.ID].Affected = len(hostsAffected)
		}
	}
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

