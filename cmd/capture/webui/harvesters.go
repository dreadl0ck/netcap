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
	"fmt"
	"net/http"
	"sort"
	"time"

	"github.com/dreadl0ck/netcap/decoder/stream/credentials"
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
	credHarvesters := credentials.GetHarvesters()

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
