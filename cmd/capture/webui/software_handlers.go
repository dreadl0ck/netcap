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
	"sort"

	"github.com/dreadl0ck/netcap/types"
)

// SoftwareSummary represents aggregated information for software
type SoftwareSummary struct {
	Product     string   `json:"product"`
	Vendor      string   `json:"vendor"`
	Version     string   `json:"version"`
	OS          string   `json:"os"`
	Count       int      `json:"count"`
	Devices     []string `json:"devices"`
	Services    []string `json:"services"`
	DPIResults  []string `json:"dpiResults"`
	FirstSeen   int64    `json:"firstSeen"`
	LastSeen    int64    `json:"lastSeen"`
	SourceNames []string `json:"sourceNames"`
	Flows       []string `json:"flows"`
	// Detection context
	DetectionMethod string `json:"detectionMethod"`
	ConfidenceLevel string `json:"confidenceLevel"`
	// Behavioral fingerprint
	BehaviorProfile string `json:"behaviorProfile"`
	IsHeadless      bool   `json:"isHeadless"`
	IsEmulated      bool   `json:"isEmulated"`
	IsAutomated     bool   `json:"isAutomated"`
	// Risk indicators
	HasKnownVulnerabilities bool   `json:"hasKnownVulnerabilities"`
	IsEndOfLife             bool   `json:"isEndOfLife"`
	SupportStatus           string `json:"supportStatus"`
	// Community ID v1 for cross-tool correlation (Zeek, Suricata, etc.)
	CommunityIDs []string `json:"communityIds"`
}

// SoftwareResponse contains the list of software
type SoftwareResponse struct {
	Software   []SoftwareSummary `json:"software"`
	TotalCount int               `json:"totalCount"`
}

// handleSoftware returns a list of all software detected
func (s *Server) handleSoftware(w http.ResponseWriter, r *http.Request) {
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

	software, err := readSoftware(outDir)
	if err != nil {
		log.Printf("[WebUI] Failed to read software: %v", err)
		http.Error(w, "Failed to read software", http.StatusInternalServerError)
		return
	}

	response := SoftwareResponse{
		Software:   software,
		TotalCount: len(software),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// readSoftware reads and aggregates Software data from the output directory
func readSoftware(outDir string) ([]SoftwareSummary, error) {
	filePath := filepath.Join(outDir, "Software.ncap.gz")

	// Check if file exists
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		log.Printf("[WebUI] Software file not found: %s", filePath)
		return []SoftwareSummary{}, nil
	}

	// Read Software records
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

	// Software aggregation map - keyed by product+vendor+version
	softwareMap := make(map[string]*softwareAggregator)

	// Read all records
	for {
		record, err := reader.NextRecord()
		if err != nil {
			if err == io.EOF {
				break
			}
			log.Printf("[WebUI] Error reading Software record: %v", err)
			continue
		}

		// Type assert to Software
		sw, ok := record.(*types.Software)
		if !ok {
			continue
		}

		// Merge Vendor into Product: if Product is empty, use Vendor instead
		product := sw.Product
		if product == "" && sw.Vendor != "" {
			product = sw.Vendor
		}

		// Create unique key (use merged product, no vendor since it's merged)
		key := product + "|" + sw.Version

		agg, exists := softwareMap[key]
		if !exists {
			agg = &softwareAggregator{
				product:      product,
				vendor:       sw.Vendor,
				version:      sw.Version,
				os:           sw.OS,
				devices:      make(map[string]bool),
				services:     make(map[string]bool),
				dpiResults:   make(map[string]bool),
				sourceNames:  make(map[string]bool),
				flows:        make(map[string]bool),
				communityIDs: make(map[string]bool),
				firstSeen:    sw.Timestamp,
				lastSeen:     sw.Timestamp,
				// Detection context
				detectionMethod: sw.DetectionMethod,
				confidenceLevel: sw.ConfidenceLevel,
				// Behavioral fingerprint
				behaviorProfile: sw.BehaviorProfile,
				isHeadless:      sw.IsHeadless,
				isEmulated:      sw.IsEmulated,
				isAutomated:     sw.IsAutomated,
				// Risk indicators
				hasKnownVulnerabilities: sw.HasKnownVulnerabilities,
				isEndOfLife:             sw.IsEndOfLife,
				supportStatus:           sw.SupportStatus,
			}
			softwareMap[key] = agg
		}

		agg.count++

		// Aggregate devices
		for _, device := range sw.DeviceProfiles {
			if device != "" {
				agg.devices[device] = true
			}
		}

		// Aggregate services
		if sw.Service != "" {
			agg.services[sw.Service] = true
		}

		// Aggregate DPI results
		for _, dpi := range sw.DPIResults {
			if dpi != "" {
				agg.dpiResults[dpi] = true
			}
		}

		// Track source names
		if sw.SourceName != "" {
			agg.sourceNames[sw.SourceName] = true
		}

		// Aggregate flows
		for _, flow := range sw.Flows {
			if flow != "" {
				agg.flows[flow] = true
			}
		}

		// Aggregate community IDs
		for _, cid := range sw.CommunityIDs {
			if cid != "" {
				agg.communityIDs[cid] = true
			}
		}

		if sw.Timestamp < agg.firstSeen {
			agg.firstSeen = sw.Timestamp
		}
		if sw.Timestamp > agg.lastSeen {
			agg.lastSeen = sw.Timestamp
		}
	}

	// Convert map to slice
	software := make([]SoftwareSummary, 0, len(softwareMap))
	for _, agg := range softwareMap {
		devices := make([]string, 0, len(agg.devices))
		for device := range agg.devices {
			devices = append(devices, device)
		}

		services := make([]string, 0, len(agg.services))
		for service := range agg.services {
			services = append(services, service)
		}

		dpiResults := make([]string, 0, len(agg.dpiResults))
		for dpi := range agg.dpiResults {
			dpiResults = append(dpiResults, dpi)
		}

		sourceNames := make([]string, 0, len(agg.sourceNames))
		for source := range agg.sourceNames {
			sourceNames = append(sourceNames, source)
		}

		flows := make([]string, 0, len(agg.flows))
		for flow := range agg.flows {
			flows = append(flows, flow)
		}

		communityIDs := make([]string, 0, len(agg.communityIDs))
		for cid := range agg.communityIDs {
			communityIDs = append(communityIDs, cid)
		}

		software = append(software, SoftwareSummary{
			Product:     agg.product,
			Vendor:      agg.vendor,
			Version:     agg.version,
			OS:          agg.os,
			Count:       agg.count,
			Devices:     devices,
			Services:    services,
			DPIResults:  dpiResults,
			FirstSeen:   agg.firstSeen,
			LastSeen:    agg.lastSeen,
			SourceNames: sourceNames,
			Flows:       flows,
			// Detection context
			DetectionMethod: agg.detectionMethod,
			ConfidenceLevel: agg.confidenceLevel,
			// Behavioral fingerprint
			BehaviorProfile: agg.behaviorProfile,
			IsHeadless:      agg.isHeadless,
			IsEmulated:      agg.isEmulated,
			IsAutomated:     agg.isAutomated,
			// Risk indicators
			HasKnownVulnerabilities: agg.hasKnownVulnerabilities,
			IsEndOfLife:             agg.isEndOfLife,
			SupportStatus:           agg.supportStatus,
			// Community ID for cross-tool correlation
			CommunityIDs: communityIDs,
		})
	}

	// Sort by count descending
	sort.Slice(software, func(i, j int) bool {
		return software[i].Count > software[j].Count
	})

	return software, nil
}

// softwareAggregator holds temporary aggregation data for software
type softwareAggregator struct {
	product      string
	vendor       string
	version      string
	os           string
	count        int
	devices      map[string]bool
	services     map[string]bool
	dpiResults   map[string]bool
	sourceNames  map[string]bool
	flows        map[string]bool
	communityIDs map[string]bool
	firstSeen    int64
	lastSeen     int64
	// Detection context
	detectionMethod string
	confidenceLevel string
	// Behavioral fingerprint
	behaviorProfile string
	isHeadless      bool
	isEmulated      bool
	isAutomated     bool
	// Risk indicators
	hasKnownVulnerabilities bool
	isEndOfLife             bool
	supportStatus           string
}
