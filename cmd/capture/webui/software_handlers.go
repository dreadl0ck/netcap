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

		// Create unique key
		key := sw.Product + "|" + sw.Vendor + "|" + sw.Version

		agg, exists := softwareMap[key]
		if !exists {
			agg = &softwareAggregator{
				product:     sw.Product,
				vendor:      sw.Vendor,
				version:     sw.Version,
				os:          sw.OS,
				devices:     make(map[string]bool),
				services:    make(map[string]bool),
				dpiResults:  make(map[string]bool),
				sourceNames: make(map[string]bool),
				flows:       make(map[string]bool),
				firstSeen:   sw.Timestamp,
				lastSeen:    sw.Timestamp,
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
	product     string
	vendor      string
	version     string
	os          string
	count       int
	devices     map[string]bool
	services    map[string]bool
	dpiResults  map[string]bool
	sourceNames map[string]bool
	flows       map[string]bool
	firstSeen   int64
	lastSeen    int64
}
