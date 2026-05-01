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

	"github.com/dreadl0ck/netcap/decoder/stream/service"
	"github.com/dreadl0ck/netcap/internal/hsmatch"
)

// HyperscanInfo describes the Hyperscan / Vectorscan integration state for
// the web UI. Independent of the build tag — when the binary was compiled
// without `-tags hyperscan` the handler still answers, with Enabled=false
// so the UI can render an explicit "disabled" badge instead of timing out.
type HyperscanInfo struct {
	// Enabled is true when this binary was compiled with -tags hyperscan
	// AND libhs is linked.
	Enabled bool `json:"enabled"`

	// LibVersion is the libhs runtime version string (or "disabled" when
	// the integration is compiled out).
	LibVersion string `json:"lib_version"`

	// BuildTag echoes the Go build tag required to enable HS.
	BuildTag string `json:"build_tag"`

	// DocsURL points to the in-tree docs page so the UI can deep-link.
	DocsURL string `json:"docs_url"`

	// ServiceProbes carries the per-category probe stats for the nmap
	// service-probe matcher. Empty when HS is disabled or no probes have
	// been loaded yet.
	ServiceProbes service.HyperscanStatus `json:"service_probes"`
}

// handleHyperscanInfo returns the integration status as JSON.
//
// GET /api/hyperscan
func (s *Server) handleHyperscanInfo(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	info := HyperscanInfo{
		Enabled:       hsmatch.Enabled,
		LibVersion:    hsmatch.Version(),
		BuildTag:      "hyperscan",
		DocsURL:       "https://github.com/dreadl0ck/netcap/blob/master/docs/hyperscan.md",
		ServiceProbes: service.GetHyperscanStatus(),
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(info); err != nil {
		http.Error(w, fmt.Sprintf("Failed to encode response: %v", err), http.StatusInternalServerError)
	}
}
