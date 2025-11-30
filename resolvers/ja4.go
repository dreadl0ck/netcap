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

package resolvers

import (
	"encoding/json"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"go.uber.org/zap"
)

// JA4DB maps JA4+ fingerprints to their descriptions
// Access to the underlying maps is not locked because after initialization
// the maps are always read and never written again.
var (
	// ja4DB maps JA4 (TLS client) fingerprints to descriptions
	ja4DB = make(map[string]*JA4Entry)

	// ja4sDB maps JA4S (TLS server) fingerprints to descriptions
	ja4sDB = make(map[string]*JA4Entry)

	// ja4hDB maps JA4H (HTTP) fingerprints to descriptions
	ja4hDB = make(map[string]*JA4Entry)

	// ja4xDB maps JA4X (certificate) fingerprints to descriptions
	ja4xDB = make(map[string]*JA4Entry)

	// ja4tDB maps JA4T (TCP) fingerprints to descriptions
	ja4tDB = make(map[string]*JA4Entry)

	// ja4tsDB maps JA4TS (TCP server) fingerprints to descriptions
	ja4tsDB = make(map[string]*JA4Entry)

	// ja4tscanDB maps JA4TScan (TCP scan) fingerprints to descriptions
	ja4tscanDB = make(map[string]*JA4Entry)
)

// JA4Entry represents a single entry from the JA4+ database
type JA4Entry struct {
	Application          string `json:"application"`
	Library              string `json:"library"`
	Device               string `json:"device"`
	OS                   string `json:"os"`
	UserAgentString      string `json:"user_agent_string"`
	CertificateAuthority string `json:"certificate_authority"`
	ObservationCount     int    `json:"observation_count"`
	Verified             bool   `json:"verified"`
	Notes                string `json:"notes"`
	JA4Fingerprint       string `json:"ja4_fingerprint"`
	JA4FingerprintString string `json:"ja4_fingerprint_string"`
	JA4SFingerprint      string `json:"ja4s_fingerprint"`
	JA4HFingerprint      string `json:"ja4h_fingerprint"`
	JA4XFingerprint      string `json:"ja4x_fingerprint"`
	JA4TFingerprint      string `json:"ja4t_fingerprint"`
	JA4TSFingerprint     string `json:"ja4ts_fingerprint"`
	JA4TScanFingerprint  string `json:"ja4tscan_fingerprint"`
}

// GetDescription returns a human-readable description for the entry
func (e *JA4Entry) GetDescription() string {
	var parts []string

	if e.Application != "" {
		parts = append(parts, e.Application)
	}
	if e.Library != "" {
		parts = append(parts, e.Library)
	}
	if e.OS != "" {
		parts = append(parts, e.OS)
	}
	if e.Device != "" {
		parts = append(parts, e.Device)
	}

	desc := strings.Join(parts, " / ")

	if e.Verified {
		desc += " [verified]"
	}

	if e.Notes != "" {
		desc += " (" + e.Notes + ")"
	}

	return desc
}

// LookupJA4 looks up a JA4 fingerprint in the database
func LookupJA4(fingerprint string) string {
	startTime := time.Now()
	cacheHit := false
	defer func() {
		if perfTracker != nil {
			perfTracker.RecordResolver("Ja4", time.Since(startTime), cacheHit)
		}
	}()

	if entry, ok := ja4DB[fingerprint]; ok {
		cacheHit = true
		return entry.GetDescription()
	}
	return ""
}

// LookupJA4Entry looks up a JA4 fingerprint and returns the full entry
func LookupJA4Entry(fingerprint string) *JA4Entry {
	if entry, ok := ja4DB[fingerprint]; ok {
		return entry
	}
	return nil
}

// LookupJA4S looks up a JA4S fingerprint in the database
func LookupJA4S(fingerprint string) string {
	startTime := time.Now()
	cacheHit := false
	defer func() {
		if perfTracker != nil {
			perfTracker.RecordResolver("Ja4s", time.Since(startTime), cacheHit)
		}
	}()

	if entry, ok := ja4sDB[fingerprint]; ok {
		cacheHit = true
		return entry.GetDescription()
	}
	return ""
}

// LookupJA4SEntry looks up a JA4S fingerprint and returns the full entry
func LookupJA4SEntry(fingerprint string) *JA4Entry {
	if entry, ok := ja4sDB[fingerprint]; ok {
		return entry
	}
	return nil
}

// LookupJA4H looks up a JA4H fingerprint in the database
func LookupJA4H(fingerprint string) string {
	if entry, ok := ja4hDB[fingerprint]; ok {
		return entry.GetDescription()
	}
	return ""
}

// LookupJA4HEntry looks up a JA4H fingerprint and returns the full entry
func LookupJA4HEntry(fingerprint string) *JA4Entry {
	if entry, ok := ja4hDB[fingerprint]; ok {
		return entry
	}
	return nil
}

// LookupJA4X looks up a JA4X fingerprint in the database
func LookupJA4X(fingerprint string) string {
	if entry, ok := ja4xDB[fingerprint]; ok {
		return entry.GetDescription()
	}
	return ""
}

// LookupJA4XEntry looks up a JA4X fingerprint and returns the full entry
func LookupJA4XEntry(fingerprint string) *JA4Entry {
	if entry, ok := ja4xDB[fingerprint]; ok {
		return entry
	}
	return nil
}

// LookupJA4T looks up a JA4T fingerprint in the database
func LookupJA4T(fingerprint string) string {
	if entry, ok := ja4tDB[fingerprint]; ok {
		return entry.GetDescription()
	}
	return ""
}

// LookupJA4TEntry looks up a JA4T fingerprint and returns the full entry
func LookupJA4TEntry(fingerprint string) *JA4Entry {
	if entry, ok := ja4tDB[fingerprint]; ok {
		return entry
	}
	return nil
}

// LookupJA4TS looks up a JA4TS fingerprint in the database
func LookupJA4TS(fingerprint string) string {
	if entry, ok := ja4tsDB[fingerprint]; ok {
		return entry.GetDescription()
	}
	return ""
}

// LookupJA4TSEntry looks up a JA4TS fingerprint and returns the full entry
func LookupJA4TSEntry(fingerprint string) *JA4Entry {
	if entry, ok := ja4tsDB[fingerprint]; ok {
		return entry
	}
	return nil
}

// LookupJA4TScan looks up a JA4TScan fingerprint in the database
func LookupJA4TScan(fingerprint string) string {
	if entry, ok := ja4tscanDB[fingerprint]; ok {
		return entry.GetDescription()
	}
	return ""
}

// LookupJA4TScanEntry looks up a JA4TScan fingerprint and returns the full entry
func LookupJA4TScanEntry(fingerprint string) *JA4Entry {
	if entry, ok := ja4tscanDB[fingerprint]; ok {
		return entry
	}
	return nil
}

// initJA4Resolver loads the JA4+ database from the dbs folder
func initJA4Resolver() {
	dbPath := filepath.Join(DataBaseFolderPath, "ja4db.json")

	data, err := os.ReadFile(dbPath)
	if err != nil {
		resolverLog.Warn("failed to load JA4 database",
			zap.String("path", dbPath),
			zap.Error(err),
		)
		return
	}

	var entries []JA4Entry
	if err := json.Unmarshal(data, &entries); err != nil {
		log.Println("failed to parse JA4 database:", err)
		return
	}

	// Populate the various fingerprint maps
	for i := range entries {
		entry := &entries[i]

		// Index JA4 fingerprints (TLS client hello)
		if entry.JA4Fingerprint != "" {
			if existing, ok := ja4DB[entry.JA4Fingerprint]; ok {
				// Merge descriptions if fingerprint already exists
				existingDesc := existing.GetDescription()
				newDesc := entry.GetDescription()
				if !strings.Contains(existingDesc, newDesc) {
					existing.Notes = strings.TrimPrefix(existing.Notes+"; "+newDesc, "; ")
				}
			} else {
				ja4DB[entry.JA4Fingerprint] = entry
			}
		}

		// Index JA4S fingerprints (TLS server hello)
		if entry.JA4SFingerprint != "" {
			if existing, ok := ja4sDB[entry.JA4SFingerprint]; ok {
				existingDesc := existing.GetDescription()
				newDesc := entry.GetDescription()
				if !strings.Contains(existingDesc, newDesc) {
					existing.Notes = strings.TrimPrefix(existing.Notes+"; "+newDesc, "; ")
				}
			} else {
				ja4sDB[entry.JA4SFingerprint] = entry
			}
		}

		// Index JA4H fingerprints (HTTP)
		if entry.JA4HFingerprint != "" {
			if existing, ok := ja4hDB[entry.JA4HFingerprint]; ok {
				existingDesc := existing.GetDescription()
				newDesc := entry.GetDescription()
				if !strings.Contains(existingDesc, newDesc) {
					existing.Notes = strings.TrimPrefix(existing.Notes+"; "+newDesc, "; ")
				}
			} else {
				ja4hDB[entry.JA4HFingerprint] = entry
			}
		}

		// Index JA4X fingerprints (X.509 certificate)
		if entry.JA4XFingerprint != "" {
			if existing, ok := ja4xDB[entry.JA4XFingerprint]; ok {
				existingDesc := existing.GetDescription()
				newDesc := entry.GetDescription()
				if !strings.Contains(existingDesc, newDesc) {
					existing.Notes = strings.TrimPrefix(existing.Notes+"; "+newDesc, "; ")
				}
			} else {
				ja4xDB[entry.JA4XFingerprint] = entry
			}
		}

		// Index JA4T fingerprints (TCP client)
		if entry.JA4TFingerprint != "" {
			if existing, ok := ja4tDB[entry.JA4TFingerprint]; ok {
				existingDesc := existing.GetDescription()
				newDesc := entry.GetDescription()
				if !strings.Contains(existingDesc, newDesc) {
					existing.Notes = strings.TrimPrefix(existing.Notes+"; "+newDesc, "; ")
				}
			} else {
				ja4tDB[entry.JA4TFingerprint] = entry
			}
		}

		// Index JA4TS fingerprints (TCP server)
		if entry.JA4TSFingerprint != "" {
			if existing, ok := ja4tsDB[entry.JA4TSFingerprint]; ok {
				existingDesc := existing.GetDescription()
				newDesc := entry.GetDescription()
				if !strings.Contains(existingDesc, newDesc) {
					existing.Notes = strings.TrimPrefix(existing.Notes+"; "+newDesc, "; ")
				}
			} else {
				ja4tsDB[entry.JA4TSFingerprint] = entry
			}
		}

		// Index JA4TScan fingerprints (TCP scan)
		if entry.JA4TScanFingerprint != "" {
			if existing, ok := ja4tscanDB[entry.JA4TScanFingerprint]; ok {
				existingDesc := existing.GetDescription()
				newDesc := entry.GetDescription()
				if !strings.Contains(existingDesc, newDesc) {
					existing.Notes = strings.TrimPrefix(existing.Notes+"; "+newDesc, "; ")
				}
			} else {
				ja4tscanDB[entry.JA4TScanFingerprint] = entry
			}
		}
	}

	resolverLog.Info("loaded JA4+ database",
		zap.Int("ja4_entries", len(ja4DB)),
		zap.Int("ja4s_entries", len(ja4sDB)),
		zap.Int("ja4h_entries", len(ja4hDB)),
		zap.Int("ja4x_entries", len(ja4xDB)),
		zap.Int("ja4t_entries", len(ja4tDB)),
		zap.Int("ja4ts_entries", len(ja4tsDB)),
		zap.Int("ja4tscan_entries", len(ja4tscanDB)),
		zap.Int("total_records", len(entries)),
		zap.String("from", dbPath),
	)
}

// GetJA4DBSize returns the number of entries in the JA4 database
func GetJA4DBSize() int {
	return len(ja4DB)
}

// GetJA4SDBSize returns the number of entries in the JA4S database
func GetJA4SDBSize() int {
	return len(ja4sDB)
}

// GetJA4HDBSize returns the number of entries in the JA4H database
func GetJA4HDBSize() int {
	return len(ja4hDB)
}

// GetJA4XDBSize returns the number of entries in the JA4X database
func GetJA4XDBSize() int {
	return len(ja4xDB)
}

// GetJA4TDBSize returns the number of entries in the JA4T database
func GetJA4TDBSize() int {
	return len(ja4tDB)
}

// GetJA4TSDBSize returns the number of entries in the JA4TS database
func GetJA4TSDBSize() int {
	return len(ja4tsDB)
}

// GetJA4TScanDBSize returns the number of entries in the JA4TScan database
func GetJA4TScanDBSize() int {
	return len(ja4tscanDB)
}

