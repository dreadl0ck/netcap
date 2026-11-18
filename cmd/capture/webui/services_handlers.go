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
	"encoding/json"
	"errors"
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
	Timestamp            int64    `json:"timestamp"`
	IP                   string   `json:"ip"`
	Port                 int32    `json:"port"`
	Name                 string   `json:"name"`
	Banner               string   `json:"banner"`
	Protocol             string   `json:"protocol"`
	NumFlows             int      `json:"numFlows"`
	Product              string   `json:"product"`
	Vendor               string   `json:"vendor"`
	Version              string   `json:"version"`
	Notes                string   `json:"notes"`
	BytesServer          int32    `json:"bytesServer"`
	BytesClient          int32    `json:"bytesClient"`
	Hostname             string   `json:"hostname"`
	OS                   string   `json:"os"`
	Applications         []string `json:"applications"`
	PortName             string   `json:"portName"`
	DetectedProtocolName string   `json:"detectedProtocolName"`
	MatchedProbeID       string   `json:"matchedProbeID"`
}

// ServicesResponse contains the list of services
type ServicesResponse struct {
	Services   []ServiceSummary `json:"services"`
	TotalCount int              `json:"totalCount"`
}

var serviceInventorySlots = make(chan struct{}, 2)

// handleServices returns a list of all services
func (s *Server) handleServices(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	outDir, _ := s.resolveOutDirFromRequest(r)

	if outDir == "" {
		http.Error(w, "No output directory set", http.StatusServiceUnavailable)
		return
	}

	var budget *inventoryAuditBudget
	if r.URL.Query().Get("mcpPage") == "true" {
		ctx := r.Context()
		if ctx.Err() != nil {
			return
		}
		select {
		case serviceInventorySlots <- struct{}{}:
			defer func() { <-serviceInventorySlots }()
		default:
			RespondJSON(w, http.StatusTooManyRequests, map[string]string{"error": "service inventory is busy"})
			return
		}
		budget = &inventoryAuditBudget{ctx: ctx, stored: maxCollectionPageScanBytes, bodies: maxCollectionPageScanBytes, rows: maxCollectionPageRows}
	}
	services, err := readServiceInventory(outDir, budget)
	if err != nil {
		if errors.Is(err, errInventoryAuditLimit) {
			RespondJSON(w, http.StatusRequestEntityTooLarge, map[string]string{"error": err.Error()})
			return
		}
		if errors.Is(err, context.Canceled) {
			return
		}
		log.Printf("[WebUI] Failed to read services: %v", err)
		http.Error(w, "Failed to read services", http.StatusInternalServerError)
		return
	}

	response := ServicesResponse{
		Services:   services,
		TotalCount: len(services),
	}

	w.Header().Set("Content-Type", "application/json")
	if respondCollectionPage(w, r, response.Services, "services") {
		return
	}
	json.NewEncoder(w).Encode(response)
}

// readServices reads and aggregates Service data from the output directory
func readServices(outDir string) ([]ServiceSummary, error) {
	return readServiceInventory(outDir, nil)
}

func readServiceInventory(outDir string, budget *inventoryAuditBudget) ([]ServiceSummary, error) {
	filePath := filepath.Join(outDir, "Service.ncap.gz")

	services := make([]ServiceSummary, 0)
	visit := func(svc *types.Service) {
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
			MatchedProbeID:       svc.MatchedProbeID,
		})
	}
	if budget == nil {
		if err := visitAuditRecords(filePath, "Service", visit); err != nil {
			return nil, err
		}
	} else {
		reader, err := budget.open(filePath, types.Type_NC_Service)
		if errors.Is(err, os.ErrNotExist) {
			return services, nil
		}
		if err != nil {
			return nil, err
		}
		defer reader.Close()
		for {
			record, err := budget.next(reader)
			if err == io.EOF {
				break
			}
			if err != nil {
				return nil, err
			}
			visit(record.(*types.Service))
		}
	}

	// Sort by bytes (server + client) descending
	sort.Slice(services, func(i, j int) bool {
		totalBytesI := services[i].BytesServer + services[i].BytesClient
		totalBytesJ := services[j].BytesServer + services[j].BytesClient
		return totalBytesI > totalBytesJ
	})

	return services, nil
}
