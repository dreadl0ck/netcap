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

	// Check if file exists
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		log.Printf("[WebUI] DeviceProfile file not found: %s", filePath)
		return []DeviceProfileSummary{}, nil
	}

	// Read DeviceProfile records
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

	devices := make([]DeviceProfileSummary, 0)

	// Read all records
	for {
		record, err := reader.NextRecord()
		if err != nil {
			if err == io.EOF {
				break
			}
			log.Printf("[WebUI] Error reading DeviceProfile record: %v", err)
			continue
		}

		// Type assert to DeviceProfile
		deviceProfile, ok := record.(*types.DeviceProfile)
		if !ok {
			continue
		}

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
		})
	}

	// Sort by packet count descending
	sort.Slice(devices, func(i, j int) bool {
		return devices[i].NumPackets > devices[j].NumPackets
	})

	return devices, nil
}

