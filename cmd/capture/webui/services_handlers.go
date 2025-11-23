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

// ServiceSummary represents aggregated information for a single service
type ServiceSummary struct {
	Timestamp             int64    `json:"timestamp"`
	IP                    string   `json:"ip"`
	Port                  int32    `json:"port"`
	Name                  string   `json:"name"`
	Banner                string   `json:"banner"`
	Protocol              string   `json:"protocol"`
	NumFlows              int      `json:"numFlows"`
	Product               string   `json:"product"`
	Vendor                string   `json:"vendor"`
	Version               string   `json:"version"`
	Notes                 string   `json:"notes"`
	BytesServer           int32    `json:"bytesServer"`
	BytesClient           int32    `json:"bytesClient"`
	Hostname              string   `json:"hostname"`
	OS                    string   `json:"os"`
	Applications          []string `json:"applications"`
	PortName              string   `json:"portName"`
	DetectedProtocolName  string   `json:"detectedProtocolName"`
}

// ServicesResponse contains the list of services
type ServicesResponse struct {
	Services   []ServiceSummary `json:"services"`
	TotalCount int              `json:"totalCount"`
}

// handleServices returns a list of all services
func (s *Server) handleServices(w http.ResponseWriter, r *http.Request) {
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

	services, err := readServices(outDir)
	if err != nil {
		log.Printf("[WebUI] Failed to read services: %v", err)
		http.Error(w, "Failed to read services", http.StatusInternalServerError)
		return
	}

	response := ServicesResponse{
		Services:   services,
		TotalCount: len(services),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// readServices reads and aggregates Service data from the output directory
func readServices(outDir string) ([]ServiceSummary, error) {
	filePath := filepath.Join(outDir, "Service.ncap.gz")

	// Check if file exists
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		log.Printf("[WebUI] Service file not found: %s", filePath)
		return []ServiceSummary{}, nil
	}

	// Read Service records
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

	services := make([]ServiceSummary, 0)

	// Read all records
	for {
		record, err := reader.NextRecord()
		if err != nil {
			if err == io.EOF {
				break
			}
			log.Printf("[WebUI] Error reading Service record: %v", err)
			continue
		}

		// Type assert to Service
		svc, ok := record.(*types.Service)
		if !ok {
			continue
		}

		services = append(services, ServiceSummary{
			Timestamp:            svc.Timestamp,
			IP:                   svc.IP,
			Port:                 svc.Port,
			Name:                 svc.Name,
			Banner:               svc.Banner,
			Protocol:             svc.Protocol,
			NumFlows:             len(svc.Flows),
			Product:              svc.Product,
			Vendor:               svc.Vendor,
			Version:              svc.Version,
			Notes:                svc.Notes,
			BytesServer:          svc.BytesServer,
			BytesClient:          svc.BytesClient,
			Hostname:             svc.Hostname,
			OS:                   svc.OS,
			Applications:         svc.Applications,
			PortName:             svc.PortName,
			DetectedProtocolName: svc.DetectedProtocolName,
		})
	}

	// Sort by bytes (server + client) descending
	sort.Slice(services, func(i, j int) bool {
		totalBytesI := services[i].BytesServer + services[i].BytesClient
		totalBytesJ := services[j].BytesServer + services[j].BytesClient
		return totalBytesI > totalBytesJ
	})

	return services, nil
}

