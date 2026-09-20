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
	"log"
	"net/http"
	"path/filepath"
	"sort"

	"github.com/dreadl0ck/netcap/types"
)

// DeviceProfileSummary represents aggregated information for a single device
type DeviceProfileSummary struct {
	MacAddr            string   `json:"macAddr"`
	DeviceManufacturer string   `json:"deviceManufacturer"`
	NumDeviceIPs       int      `json:"numDeviceIPs"`
	NumContacts        int      `json:"numContacts"`
	NumPackets         int64    `json:"numPackets"`
	Bytes              uint64   `json:"bytes"`
	Timestamp          int64    `json:"timestamp"`
	Applications       []string `json:"applications"`
	Devices            []string `json:"devices"`
	DeviceIPs          []string `json:"deviceIPs"`
	Contacts           []string `json:"contacts"`
	Hostnames          []string `json:"hostnames"`
	DeviceTypes        []string `json:"deviceTypes"`
	OS                 string   `json:"os"`
	Roles              []string `json:"roles"`
}

// DevicesResponse contains the list of device profiles
type DevicesResponse struct {
	Devices    []DeviceProfileSummary `json:"devices"`
	TotalCount int                    `json:"totalCount"`
}

// handleDevices returns a list of all device profiles
func (s *Server) handleDevices(w http.ResponseWriter, r *http.Request) {
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

	devices, err := readDeviceProfiles(outDir)
	if err != nil {
		log.Printf("[WebUI] Failed to read device profiles: %v", err)
		http.Error(w, "Failed to read device profiles", http.StatusInternalServerError)
		return
	}

	response := DevicesResponse{
		Devices:    devices,
		TotalCount: len(devices),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// readDeviceProfiles reads and aggregates DeviceProfile data from the output directory
func readDeviceProfiles(outDir string) ([]DeviceProfileSummary, error) {
	filePath := filepath.Join(outDir, "DeviceProfile.ncap.gz")

	devices := make([]DeviceProfileSummary, 0)
	err := visitAuditRecords(filePath, "DeviceProfile", func(deviceProfile *types.DeviceProfile) {
		devices = append(devices, DeviceProfileSummary{
			MacAddr:            deviceProfile.MacAddr,
			DeviceManufacturer: deviceProfile.DeviceManufacturer,
			NumDeviceIPs:       len(deviceProfile.DeviceIPs),
			NumContacts:        len(deviceProfile.Contacts),
			NumPackets:         deviceProfile.NumPackets,
			Bytes:              deviceProfile.Bytes,
			Timestamp:          deviceProfile.Timestamp,
			Applications:       deviceProfile.Applications,
			Devices:            deviceProfile.Devices,
			DeviceIPs:          deviceProfile.DeviceIPs,
			Contacts:           deviceProfile.Contacts,
			Hostnames:          deviceProfile.Hostnames,
			DeviceTypes:        deviceProfile.DeviceTypes,
			OS:                 deviceProfile.OS,
			Roles:              deviceProfile.Roles,
		})
	})
	if err != nil {
		return nil, err
	}

	// Sort by packet count descending
	sort.Slice(devices, func(i, j int) bool {
		return devices[i].NumPackets > devices[j].NumPackets
	})

	return devices, nil
}
