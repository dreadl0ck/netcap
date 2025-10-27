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
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/dreadl0ck/netcap/defaults"
	netio "github.com/dreadl0ck/netcap/io"
)

// AuditStatsResponse represents the audit record statistics response
type AuditStatsResponse struct {
	TotalRecords       int64 `json:"totalRecords"`
	ExploitCount       int64 `json:"exploitCount"`
	VulnerabilityCount int64 `json:"vulnerabilityCount"`
	CredentialsCount   int64 `json:"credentialsCount"`
	SoftwareCount      int64 `json:"softwareCount"`
}

// handleAuditStats returns statistics for specific audit record types
func (s *Server) handleAuditStats(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	s.mu.RLock()
	outDir := s.outDir
	s.mu.RUnlock()

	response := AuditStatsResponse{
		TotalRecords:       0,
		ExploitCount:       0,
		VulnerabilityCount: 0,
		CredentialsCount:   0,
		SoftwareCount:      0,
	}

	if outDir == "" {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
		return
	}

	files, err := os.ReadDir(outDir)
	if err != nil {
		log.Printf("[WebUI] Failed to read directory %s for audit stats: %v", outDir, err)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
		return
	}

	// Count records for specific audit types
	for _, file := range files {
		if file.IsDir() {
			continue
		}

		name := file.Name()
		// Check for audit record files (.ncap or .ncap.gz)
		if !strings.HasSuffix(name, defaults.FileExtension) &&
			!strings.HasSuffix(name, defaults.FileExtensionCompressed) {
			continue
		}

		// Extract type name (remove .ncap or .ncap.gz)
		typeName := strings.TrimSuffix(name, defaults.FileExtensionCompressed)
		typeName = strings.TrimSuffix(typeName, defaults.FileExtension)

		fullPath := filepath.Join(outDir, name)

		// Count records for this file
		count, err := netio.Count(fullPath)
		if err != nil {
			log.Printf("[WebUI] Failed to count records for %s: %v", fullPath, err)
			continue
		}

		// Add to total
		response.TotalRecords += count

		// Check if this is one of the specific audit types we're tracking
		switch typeName {
		case "Exploit":
			response.ExploitCount = count
		case "Vulnerability":
			response.VulnerabilityCount = count
		case "Credentials":
			response.CredentialsCount = count
		case "Software":
			response.SoftwareCount = count
		}
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(response); err != nil {
		http.Error(w, "Failed to encode response", http.StatusInternalServerError)
	}
}
