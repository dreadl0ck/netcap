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
	"sort"
	"time"

	"github.com/dreadl0ck/netcap/decoder/stream/secret"
)

// HarvesterInfo represents information about a credential harvester
type HarvesterInfo struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Ports       []int  `json:"ports"`
}

// HarvestersResponse represents the response with all harvester information
type HarvestersResponse struct {
	Harvesters []HarvesterInfo `json:"harvesters"`
}

// HarvesterPresetInfo represents metadata about a saved harvester configuration preset
type HarvesterPresetInfo struct {
	Name           string    `json:"name"`
	Description    string    `json:"description"`
	CreatedAt      time.Time `json:"created_at"`
	ModifiedAt     time.Time `json:"modified_at"`
	HarvesterCount int       `json:"harvester_count"`
}

// HarvesterPresetListResponse represents the response with all saved presets
type HarvesterPresetListResponse struct {
	Presets []HarvesterPresetInfo `json:"presets"`
}

// handleHarvesters returns information about all available credential harvesters
func (s *Server) handleHarvesters(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Get harvesters from the credentials package (real loaded harvesters with actual port mappings)
	credHarvesters := secret.GetHarvesters()

	// Convert to response format
	harvesters := make([]HarvesterInfo, len(credHarvesters))
	for i, h := range credHarvesters {
		// Sort ports for consistent display
		sort.Ints(h.Ports)
		harvesters[i] = HarvesterInfo{
			Name:        h.Name,
			Description: h.Description,
			Ports:       h.Ports,
		}
	}

	// Sort by name for consistent ordering
	sort.Slice(harvesters, func(i, j int) bool {
		return harvesters[i].Name < harvesters[j].Name
	})

	response := HarvestersResponse{
		Harvesters: harvesters,
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(response); err != nil {
		http.Error(w, fmt.Sprintf("Failed to encode response: %v", err), http.StatusInternalServerError)
	}
}
