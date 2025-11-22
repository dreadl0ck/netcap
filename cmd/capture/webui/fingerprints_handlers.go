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

// FingerprintSummary represents aggregated fingerprint information
type FingerprintSummary struct {
	Fingerprint string   `json:"fingerprint"`
	Type        string   `json:"type"` // JA3, HASSH, or DHCP
	Count       int      `json:"count"`
	Hosts       []string `json:"hosts"`
	Description string   `json:"description"`
	FirstSeen   int64    `json:"firstSeen"`
	LastSeen    int64    `json:"lastSeen"`
}

// FingerprintsResponse contains the list of fingerprints
type FingerprintsResponse struct {
	Fingerprints []FingerprintSummary `json:"fingerprints"`
	TotalCount   int                  `json:"totalCount"`
}

// handleFingerprints returns a list of all fingerprints (JA3, HASSH, DHCP)
func (s *Server) handleFingerprints(w http.ResponseWriter, r *http.Request) {
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

	fingerprints, err := readFingerprints(outDir)
	if err != nil {
		log.Printf("[WebUI] Failed to read fingerprints: %v", err)
		http.Error(w, "Failed to read fingerprints", http.StatusInternalServerError)
		return
	}

	response := FingerprintsResponse{
		Fingerprints: fingerprints,
		TotalCount:   len(fingerprints),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// readFingerprints reads and aggregates fingerprint data from SSH, IPProfile, and DHCP records
func readFingerprints(outDir string) ([]FingerprintSummary, error) {
	fingerprintMap := make(map[string]*fingerprintAggregator)

	// Read HASSH fingerprints from SSH records
	if err := readHASSHFingerprints(outDir, fingerprintMap); err != nil {
		log.Printf("[WebUI] Warning: Failed to read HASSH fingerprints: %v", err)
	}

	// Read JA3 fingerprints from IPProfile records
	if err := readJA3Fingerprints(outDir, fingerprintMap); err != nil {
		log.Printf("[WebUI] Warning: Failed to read JA3 fingerprints: %v", err)
	}

	// Read DHCP fingerprints from DHCPv4 records
	if err := readDHCPFingerprints(outDir, fingerprintMap); err != nil {
		log.Printf("[WebUI] Warning: Failed to read DHCP fingerprints: %v", err)
	}

	// Convert map to slice
	fingerprints := make([]FingerprintSummary, 0, len(fingerprintMap))
	for _, agg := range fingerprintMap {
		hosts := make([]string, 0, len(agg.hosts))
		for host := range agg.hosts {
			hosts = append(hosts, host)
		}

		fingerprints = append(fingerprints, FingerprintSummary{
			Fingerprint: agg.fingerprint,
			Type:        agg.fpType,
			Count:       agg.count,
			Hosts:       hosts,
			Description: agg.description,
			FirstSeen:   agg.firstSeen,
			LastSeen:    agg.lastSeen,
		})
	}

	// Sort by count descending
	sort.Slice(fingerprints, func(i, j int) bool {
		return fingerprints[i].Count > fingerprints[j].Count
	})

	return fingerprints, nil
}

// readHASSHFingerprints reads HASSH fingerprints from SSH records
func readHASSHFingerprints(outDir string, fingerprintMap map[string]*fingerprintAggregator) error {
	filePath := filepath.Join(outDir, "SSH.ncap.gz")

	// Check if file exists
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		log.Printf("[WebUI] SSH file not found: %s", filePath)
		return nil
	}

	reader, err := NewAuditRecordReader(filePath)
	if err != nil {
		return err
	}
	defer reader.Close()

	// Read header
	_, err = reader.ReadHeader()
	if err != nil {
		return err
	}

	// Read all records
	for {
		record, err := reader.NextRecord()
		if err != nil {
			if err == io.EOF {
				break
			}
			log.Printf("[WebUI] Error reading SSH record: %v", err)
			continue
		}

		ssh, ok := record.(*types.SSH)
		if !ok || ssh.HASSH == "" {
			continue
		}

		key := "HASSH:" + ssh.HASSH
		agg, exists := fingerprintMap[key]
		if !exists {
			agg = &fingerprintAggregator{
				fingerprint: ssh.HASSH,
				fpType:      "HASSH",
				hosts:       make(map[string]bool),
				firstSeen:   ssh.Timestamp,
				lastSeen:    ssh.Timestamp,
			}
			// Use first description if available
			if len(ssh.HASSHDescriptions) > 0 {
				agg.description = ssh.HASSHDescriptions[0]
			}
			fingerprintMap[key] = agg
		}

		agg.count++
		// Extract host from Flow field (format: "src:port-dst:port")
		if ssh.Flow != "" {
			agg.hosts[ssh.Flow] = true
		}

		if ssh.Timestamp < agg.firstSeen {
			agg.firstSeen = ssh.Timestamp
		}
		if ssh.Timestamp > agg.lastSeen {
			agg.lastSeen = ssh.Timestamp
		}
	}

	return nil
}

// readJA3Fingerprints reads JA3 fingerprints from IPProfile records
func readJA3Fingerprints(outDir string, fingerprintMap map[string]*fingerprintAggregator) error {
	filePath := filepath.Join(outDir, "IPProfile.ncap.gz")

	// Check if file exists
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		log.Printf("[WebUI] IPProfile file not found: %s", filePath)
		return nil
	}

	reader, err := NewAuditRecordReader(filePath)
	if err != nil {
		return err
	}
	defer reader.Close()

	// Read header
	_, err = reader.ReadHeader()
	if err != nil {
		return err
	}

	// Read all records
	for {
		record, err := reader.NextRecord()
		if err != nil {
			if err == io.EOF {
				break
			}
			log.Printf("[WebUI] Error reading IPProfile record: %v", err)
			continue
		}

		ipProfile, ok := record.(*types.IPProfile)
		if !ok {
			continue
		}

		// Process JA3 hashes
		for ja3Hash, description := range ipProfile.Ja3Hashes {
			if ja3Hash == "" {
				continue
			}

			key := "JA3:" + ja3Hash
			agg, exists := fingerprintMap[key]
			if !exists {
				agg = &fingerprintAggregator{
					fingerprint: ja3Hash,
					fpType:      "JA3",
					description: description,
					hosts:       make(map[string]bool),
					firstSeen:   ipProfile.TimestampFirst,
					lastSeen:    ipProfile.TimestampLast,
				}
				fingerprintMap[key] = agg
			}

			agg.count++
			agg.hosts[ipProfile.Addr] = true

			if ipProfile.TimestampFirst < agg.firstSeen {
				agg.firstSeen = ipProfile.TimestampFirst
			}
			if ipProfile.TimestampLast > agg.lastSeen {
				agg.lastSeen = ipProfile.TimestampLast
			}
		}

		// Also process JA3 fingerprint matches
		for _, match := range ipProfile.Ja3FingerprintMatches {
			if match == "" {
				continue
			}
			// Store as description for this host's JA3 fingerprints
			for ja3Hash := range ipProfile.Ja3Hashes {
				key := "JA3:" + ja3Hash
				if agg, exists := fingerprintMap[key]; exists {
					if agg.description == "" {
						agg.description = match
					}
				}
			}
		}
	}

	return nil
}

// readDHCPFingerprints reads DHCP fingerprints from DHCPv4 records
func readDHCPFingerprints(outDir string, fingerprintMap map[string]*fingerprintAggregator) error {
	filePath := filepath.Join(outDir, "DHCPv4.ncap.gz")

	// Check if file exists
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		log.Printf("[WebUI] DHCPv4 file not found: %s", filePath)
		return nil
	}

	reader, err := NewAuditRecordReader(filePath)
	if err != nil {
		return err
	}
	defer reader.Close()

	// Read header
	_, err = reader.ReadHeader()
	if err != nil {
		return err
	}

	// Read all records
	for {
		record, err := reader.NextRecord()
		if err != nil {
			if err == io.EOF {
				break
			}
			log.Printf("[WebUI] Error reading DHCPv4 record: %v", err)
			continue
		}

		dhcp, ok := record.(*types.DHCPv4)
		if !ok {
			continue
		}

		// Use the Fingerprint field which contains comma-separated option types
		// e.g., "1,3,6,15,..." created during decoding
		fingerprint := dhcp.Fingerprint

		if fingerprint == "" {
			continue
		}

		key := "DHCP:" + fingerprint
		agg, exists := fingerprintMap[key]
		if !exists {
			agg = &fingerprintAggregator{
				fingerprint: fingerprint,
				fpType:      "DHCP",
				hosts:       make(map[string]bool),
				firstSeen:   dhcp.Timestamp,
				lastSeen:    dhcp.Timestamp,
			}
			fingerprintMap[key] = agg
		}

		agg.count++
		if dhcp.ClientIP != "" {
			agg.hosts[dhcp.ClientIP] = true
		}
		if dhcp.YourClientIP != "" {
			agg.hosts[dhcp.YourClientIP] = true
		}

		if dhcp.Timestamp < agg.firstSeen {
			agg.firstSeen = dhcp.Timestamp
		}
		if dhcp.Timestamp > agg.lastSeen {
			agg.lastSeen = dhcp.Timestamp
		}
	}

	return nil
}

// fingerprintAggregator holds temporary aggregation data for a fingerprint
type fingerprintAggregator struct {
	fingerprint string
	fpType      string
	count       int
	hosts       map[string]bool
	description string
	firstSeen   int64
	lastSeen    int64
}

