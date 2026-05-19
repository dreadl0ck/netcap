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
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/dreadl0ck/netcap/types"
)

// Per-row bounds applied before sending fingerprint summaries to the UI.
// These prevent the browser from being overloaded when a fingerprint is
// associated with very large numbers of distinct community IDs or hosts.
const (
	maxCommunityIDsPerRow = 10
	maxHostsPerRow        = 50

	defaultFingerprintsLimit = 100
	maxFingerprintsLimit     = 1000
)

// FingerprintSummary represents aggregated fingerprint information.
//
// Hosts and CommunityIDs are capped server-side (see maxHostsPerRow and
// maxCommunityIDsPerRow). HostsTotal / CommunityIDsTotal carry the
// pre-cap counts so the UI can display "X of Y" hints.
type FingerprintSummary struct {
	Fingerprint           string   `json:"fingerprint"`
	Type                  string   `json:"type"` // JA4, JA4S, JA4H, JA4X, JA4T, JA4TS, JA4SSH, or DHCP
	Count                 int      `json:"count"`
	Hosts                 []string `json:"hosts"`
	HostsTotal            int      `json:"hostsTotal"`
	HostsTruncated        bool     `json:"hostsTruncated"`
	Description           string   `json:"description"`
	FirstSeen             int64    `json:"firstSeen"`
	LastSeen              int64    `json:"lastSeen"`
	CommunityIDs          []string `json:"communityIds"`
	CommunityIDsTotal     int      `json:"communityIdsTotal"`
	CommunityIDsTruncated bool     `json:"communityIdsTruncated"`
}

// FingerprintsStats summarises the full dataset (independent of the current
// page) so the UI can render summary cards without scanning the entire list
// client-side.
type FingerprintsStats struct {
	TotalFingerprints int            `json:"totalFingerprints"`
	TotalOccurrences  int            `json:"totalOccurrences"`
	CountsByType      map[string]int `json:"countsByType"`
}

// FingerprintsResponse contains the list of fingerprints
type FingerprintsResponse struct {
	Fingerprints []FingerprintSummary `json:"fingerprints"`
	TotalCount   int                  `json:"totalCount"` // post-filter, pre-pagination
	Offset       int                  `json:"offset"`
	Limit        int                  `json:"limit"`
	Stats        FingerprintsStats    `json:"stats"`
}

// handleFingerprints returns a paginated list of fingerprints (JA4, JA4S,
// JA4H, JA4X, JA4T, JA4TS, JA4SSH, DHCP). All filtering, sorting and
// pagination is performed server-side; per-row hosts and community IDs are
// capped so the browser never receives unbounded arrays.
//
// Query parameters:
//
//	limit         - max rows to return (default 100, cap 1000)
//	offset        - row offset for pagination (default 0)
//	type          - one of JA4|JA4S|JA4H|JA4X|JA4T|JA4TS|JA4SSH|DHCP|all
//	search        - case-insensitive substring matched against fingerprint,
//	                type, description and host list
//	communityId   - repeatable; rows are included only if any of their
//	                community IDs is in the set. Matching IDs are also
//	                promoted to the front of the per-row CommunityIDs slice.
//	sortField     - fingerprint|type|count|hosts (default count)
//	sortOrder     - asc|desc (default desc)
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

	all, err := readFingerprints(outDir)
	if err != nil {
		log.Printf("[WebUI] Failed to read fingerprints: %v", err)
		http.Error(w, "Failed to read fingerprints", http.StatusInternalServerError)
		return
	}

	q := r.URL.Query()
	opts := parseFingerprintListOptions(q)

	// Compute global stats over the full unfiltered dataset so the UI summary
	// cards remain meaningful regardless of which slice the user is viewing.
	stats := computeFingerprintStats(all)

	filtered := filterFingerprints(all, opts)
	sortFingerprints(filtered, opts.sortField, opts.sortOrder)

	totalCount := len(filtered)

	// Apply pagination.
	start := opts.offset
	if start > totalCount {
		start = totalCount
	}
	end := start + opts.limit
	if end > totalCount {
		end = totalCount
	}
	page := filtered[start:end]

	// Cap per-row arrays and promote matching community IDs.
	out := make([]FingerprintSummary, 0, len(page))
	for _, fp := range page {
		out = append(out, capFingerprintSummary(fp, opts.communityIDFilter))
	}

	response := FingerprintsResponse{
		Fingerprints: out,
		TotalCount:   totalCount,
		Offset:       opts.offset,
		Limit:        opts.limit,
		Stats:        stats,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// fingerprintListOptions holds the parsed query parameters for the
// /api/fingerprints handler.
type fingerprintListOptions struct {
	limit             int
	offset            int
	typeFilter        string // "" means all
	search            string // lower-cased
	communityIDFilter map[string]struct{}
	sortField         string
	sortOrder         string
}

func parseFingerprintListOptions(q map[string][]string) fingerprintListOptions {
	get := func(key string) string {
		if v, ok := q[key]; ok && len(v) > 0 {
			return v[0]
		}
		return ""
	}

	limit := defaultFingerprintsLimit
	if v := get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			if n > maxFingerprintsLimit {
				n = maxFingerprintsLimit
			}
			limit = n
		}
	}

	offset := 0
	if v := get("offset"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			offset = n
		}
	}

	typeFilter := strings.ToUpper(strings.TrimSpace(get("type")))
	if typeFilter == "ALL" {
		typeFilter = ""
	}

	search := strings.TrimSpace(get("search"))

	var cidSet map[string]struct{}
	if cids, ok := q["communityId"]; ok && len(cids) > 0 {
		cidSet = make(map[string]struct{}, len(cids))
		for _, cid := range cids {
			cid = strings.TrimSpace(cid)
			if cid != "" {
				cidSet[cid] = struct{}{}
			}
		}
		if len(cidSet) == 0 {
			cidSet = nil
		}
	}

	sortField := strings.ToLower(strings.TrimSpace(get("sortField")))
	switch sortField {
	case "fingerprint", "type", "count", "hosts":
	default:
		sortField = "count"
	}

	sortOrder := strings.ToLower(strings.TrimSpace(get("sortOrder")))
	if sortOrder != "asc" && sortOrder != "desc" {
		sortOrder = "desc"
	}

	return fingerprintListOptions{
		limit:             limit,
		offset:            offset,
		typeFilter:        typeFilter,
		search:            search,
		communityIDFilter: cidSet,
		sortField:         sortField,
		sortOrder:         sortOrder,
	}
}

// filterFingerprints returns the subset of in that satisfies all active
// filters in opts. The input slice is not modified.
func filterFingerprints(in []FingerprintSummary, opts fingerprintListOptions) []FingerprintSummary {
	searchTerms := parseSearchQuery(opts.search)

	if opts.typeFilter == "" && len(searchTerms) == 0 && len(opts.communityIDFilter) == 0 {
		out := make([]FingerprintSummary, len(in))
		copy(out, in)
		return out
	}

	out := make([]FingerprintSummary, 0, len(in))
	for _, fp := range in {
		if opts.typeFilter != "" && fp.Type != opts.typeFilter {
			continue
		}
		if len(opts.communityIDFilter) > 0 {
			if !containsAnyCommunityID(fp.CommunityIDs, opts.communityIDFilter) {
				continue
			}
		}
		if len(searchTerms) > 0 && !fingerprintMatchesSearch(fp, searchTerms) {
			continue
		}
		out = append(out, fp)
	}
	return out
}

func containsAnyCommunityID(ids []string, set map[string]struct{}) bool {
	for _, id := range ids {
		if _, ok := set[id]; ok {
			return true
		}
	}
	return false
}

// searchTerm is a single token parsed from a user-supplied search query.
// Tokens may be optionally negated with a leading '!' (e.g. "!JA3" excludes
// rows that mention JA3).
type searchTerm struct {
	term   string // already lower-cased; never empty
	negate bool
}

// parseSearchQuery splits a raw query into whitespace-separated tokens,
// stripping a leading '!' to mark negation. Mirrors the frontend helper at
// cmd/capture/webui/frontend/packages/netcap-ui/src/lib/tableSearch.ts so
// the same syntax users typed before client-side filtering went away keeps
// working against the backend.
func parseSearchQuery(query string) []searchTerm {
	query = strings.TrimSpace(query)
	if query == "" {
		return nil
	}
	tokens := strings.Fields(query)
	out := make([]searchTerm, 0, len(tokens))
	for _, tok := range tokens {
		if tok == "" {
			continue
		}
		if strings.HasPrefix(tok, "!") && len(tok) > 1 {
			out = append(out, searchTerm{term: strings.ToLower(tok[1:]), negate: true})
			continue
		}
		// A lone "!" is treated as a literal positive token (matches the
		// frontend behaviour, which keeps it as a non-negated term).
		out = append(out, searchTerm{term: strings.ToLower(tok), negate: false})
	}
	return out
}

// fingerprintMatchesSearch implements the same OR-on-positives /
// AND-on-negatives semantics as matchesSearchTerms in tableSearch.ts:
// the row matches if none of the negated terms is found anywhere in the
// searchable fields AND, when at least one positive term is present, at
// least one of them is found.
func fingerprintMatchesSearch(fp FingerprintSummary, terms []searchTerm) bool {
	if len(terms) == 0 {
		return true
	}

	// Combine all searchable fields into one lower-cased haystack so a
	// negative term spanning fields also excludes correctly (matches the
	// frontend's combinedValues approach).
	var b strings.Builder
	b.Grow(len(fp.Fingerprint) + len(fp.Type) + len(fp.Description) + 32)
	b.WriteString(strings.ToLower(fp.Fingerprint))
	b.WriteByte(' ')
	b.WriteString(strings.ToLower(fp.Type))
	b.WriteByte(' ')
	if fp.Description != "" {
		b.WriteString(strings.ToLower(fp.Description))
		b.WriteByte(' ')
	}
	for _, h := range fp.Hosts {
		b.WriteString(strings.ToLower(h))
		b.WriteByte(' ')
	}
	haystack := b.String()

	hasPositive := false
	positiveMatch := false
	for _, t := range terms {
		if t.negate {
			if strings.Contains(haystack, t.term) {
				return false
			}
			continue
		}
		hasPositive = true
		if !positiveMatch && strings.Contains(haystack, t.term) {
			positiveMatch = true
		}
	}
	if hasPositive {
		return positiveMatch
	}
	return true
}

// sortFingerprints sorts the slice in place according to field and order.
// A stable secondary sort by fingerprint string keeps results deterministic
// across requests.
func sortFingerprints(in []FingerprintSummary, field, order string) {
	asc := order == "asc"
	sort.SliceStable(in, func(i, j int) bool {
		a, b := in[i], in[j]
		var less bool
		var equal bool
		switch field {
		case "fingerprint":
			cmp := strings.Compare(a.Fingerprint, b.Fingerprint)
			less = cmp < 0
			equal = cmp == 0
		case "type":
			cmp := strings.Compare(a.Type, b.Type)
			less = cmp < 0
			equal = cmp == 0
		case "hosts":
			less = len(a.Hosts) < len(b.Hosts)
			equal = len(a.Hosts) == len(b.Hosts)
		default: // "count"
			less = a.Count < b.Count
			equal = a.Count == b.Count
		}
		if equal {
			// Stable secondary sort by fingerprint.
			return a.Fingerprint < b.Fingerprint
		}
		if asc {
			return less
		}
		return !less
	})
}

// computeFingerprintStats summarises the full dataset so the UI can render
// the per-type summary cards without iterating the (possibly truncated)
// current page.
func computeFingerprintStats(in []FingerprintSummary) FingerprintsStats {
	counts := make(map[string]int, 8)
	totalOcc := 0
	for _, fp := range in {
		counts[fp.Type]++
		totalOcc += fp.Count
	}
	return FingerprintsStats{
		TotalFingerprints: len(in),
		TotalOccurrences:  totalOcc,
		CountsByType:      counts,
	}
}

// capFingerprintSummary returns a copy of fp with Hosts and CommunityIDs
// truncated to per-row limits. When communityIDFilter is non-empty, any
// community IDs present in the filter are promoted to the front of the
// returned slice so the UI surfaces the matching ID at position 0.
func capFingerprintSummary(fp FingerprintSummary, communityIDFilter map[string]struct{}) FingerprintSummary {
	out := fp

	// Hosts: deterministic order + cap.
	hostsTotal := len(fp.Hosts)
	if hostsTotal > 0 {
		sortedHosts := make([]string, hostsTotal)
		copy(sortedHosts, fp.Hosts)
		sort.Strings(sortedHosts)
		if hostsTotal > maxHostsPerRow {
			out.Hosts = sortedHosts[:maxHostsPerRow]
			out.HostsTruncated = true
		} else {
			out.Hosts = sortedHosts
			out.HostsTruncated = false
		}
	} else {
		out.Hosts = []string{}
		out.HostsTruncated = false
	}
	out.HostsTotal = hostsTotal

	// Community IDs: matches first (sorted), then non-matches (sorted), capped.
	cidTotal := len(fp.CommunityIDs)
	out.CommunityIDsTotal = cidTotal
	if cidTotal == 0 {
		out.CommunityIDs = []string{}
		out.CommunityIDsTruncated = false
		return out
	}

	matched := make([]string, 0)
	unmatched := make([]string, 0, cidTotal)
	for _, cid := range fp.CommunityIDs {
		if len(communityIDFilter) > 0 {
			if _, ok := communityIDFilter[cid]; ok {
				matched = append(matched, cid)
				continue
			}
		}
		unmatched = append(unmatched, cid)
	}
	sort.Strings(matched)
	sort.Strings(unmatched)

	merged := make([]string, 0, len(matched)+len(unmatched))
	merged = append(merged, matched...)
	merged = append(merged, unmatched...)

	if len(merged) > maxCommunityIDsPerRow {
		out.CommunityIDs = merged[:maxCommunityIDsPerRow]
		out.CommunityIDsTruncated = true
	} else {
		out.CommunityIDs = merged
		out.CommunityIDsTruncated = false
	}
	return out
}

// readFingerprints reads and aggregates fingerprint data from SSH, IPProfile, HTTP, TCP, TLSCertificate, and DHCP records
func readFingerprints(outDir string) ([]FingerprintSummary, error) {
	fingerprintMap := make(map[string]*fingerprintAggregator)

	// Read JA4SSH fingerprints from SSH records
	if err := readJA4SSHFingerprints(outDir, fingerprintMap); err != nil {
		log.Printf("[WebUI] Warning: Failed to read JA4SSH fingerprints: %v", err)
	}

	// Read JA4 fingerprints from IPProfile records
	if err := readJA4Fingerprints(outDir, fingerprintMap); err != nil {
		log.Printf("[WebUI] Warning: Failed to read JA4 fingerprints: %v", err)
	}

	// Read JA4H fingerprints from HTTP records
	if err := readJA4HFingerprints(outDir, fingerprintMap); err != nil {
		log.Printf("[WebUI] Warning: Failed to read JA4H fingerprints: %v", err)
	}

	// Read JA4X fingerprints from TLSCertificate records
	if err := readJA4XFingerprints(outDir, fingerprintMap); err != nil {
		log.Printf("[WebUI] Warning: Failed to read JA4X fingerprints: %v", err)
	}

	// Read JA4T/JA4TS fingerprints from TCP records
	if err := readJA4TFingerprints(outDir, fingerprintMap); err != nil {
		log.Printf("[WebUI] Warning: Failed to read JA4T fingerprints: %v", err)
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

		communityIDs := make([]string, 0, len(agg.communityIDs))
		for cid := range agg.communityIDs {
			communityIDs = append(communityIDs, cid)
		}

		fingerprints = append(fingerprints, FingerprintSummary{
			Fingerprint:  agg.fingerprint,
			Type:         agg.fpType,
			Count:        agg.count,
			Hosts:        hosts,
			Description:  agg.description,
			FirstSeen:    agg.firstSeen,
			LastSeen:     agg.lastSeen,
			CommunityIDs: communityIDs,
		})
	}

	// Sort by count descending
	sort.Slice(fingerprints, func(i, j int) bool {
		return fingerprints[i].Count > fingerprints[j].Count
	})

	return fingerprints, nil
}

// readJA4SSHFingerprints reads JA4SSH fingerprints from SSH records
func readJA4SSHFingerprints(outDir string, fingerprintMap map[string]*fingerprintAggregator) error {
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
		if !ok || ssh.Ja4Ssh == "" {
			continue
		}

		key := "JA4SSH:" + ssh.Ja4Ssh
		agg, exists := fingerprintMap[key]
		if !exists {
			agg = &fingerprintAggregator{
				fingerprint:  ssh.Ja4Ssh,
				fpType:       "JA4SSH",
				hosts:        make(map[string]bool),
				communityIDs: make(map[string]bool),
				firstSeen:    ssh.Timestamp,
				lastSeen:     ssh.Timestamp,
			}
			// Use session type as description
			if ssh.Ja4SshSessionType != "" {
				agg.description = "Session Type: " + ssh.Ja4SshSessionType
			}
			fingerprintMap[key] = agg
		}

		agg.count++
		// Extract host from Flow field (format: "src:port-dst:port")
		if ssh.Flow != "" {
			agg.hosts[ssh.Flow] = true
		}
		if ssh.CommunityID != "" {
			agg.communityIDs[ssh.CommunityID] = true
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

// readJA4Fingerprints reads JA4 fingerprints from TLSClientHello records
// and JA4S fingerprints from TLSServerHello records (with database descriptions)
func readJA4Fingerprints(outDir string, fingerprintMap map[string]*fingerprintAggregator) error {
	// Read JA4 from TLSClientHello
	if err := readJA4FromTLSClientHello(outDir, fingerprintMap); err != nil {
		log.Printf("[WebUI] Warning: Failed to read JA4 from TLSClientHello: %v", err)
	}

	// Read JA4S from TLSServerHello
	if err := readJA4SFromTLSServerHello(outDir, fingerprintMap); err != nil {
		log.Printf("[WebUI] Warning: Failed to read JA4S from TLSServerHello: %v", err)
	}

	// Also read from IPProfile for additional hosts (but don't overwrite descriptions)
	if err := readJA4FromHost(outDir, fingerprintMap); err != nil {
		log.Printf("[WebUI] Warning: Failed to read JA4 from IPProfile: %v", err)
	}

	return nil
}

// readJA4FromTLSClientHello reads JA4 fingerprints from TLSClientHello records
func readJA4FromTLSClientHello(outDir string, fingerprintMap map[string]*fingerprintAggregator) error {
	filePath := filepath.Join(outDir, "TLSClientHello.ncap.gz")

	// Check if file exists
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		log.Printf("[WebUI] TLSClientHello file not found: %s", filePath)
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
			log.Printf("[WebUI] Error reading TLSClientHello record: %v", err)
			continue
		}

		hello, ok := record.(*types.TLSClientHello)
		if !ok || hello.Ja4 == "" {
			continue
		}

		key := "JA4:" + hello.Ja4
		agg, exists := fingerprintMap[key]
		if !exists {
			agg = &fingerprintAggregator{
				fingerprint:  hello.Ja4,
				fpType:       "JA4",
				hosts:        make(map[string]bool),
				communityIDs: make(map[string]bool),
				firstSeen:    hello.Timestamp,
				lastSeen:     hello.Timestamp,
			}
			// Use Ja4Description from database lookup
			if hello.Ja4Description != "" {
				agg.description = hello.Ja4Description
			}
			fingerprintMap[key] = agg
		}

		agg.count++
		if hello.SrcIP != "" {
			agg.hosts[hello.SrcIP] = true
		}
		if hello.CommunityID != "" {
			agg.communityIDs[hello.CommunityID] = true
		}

		if hello.Timestamp < agg.firstSeen {
			agg.firstSeen = hello.Timestamp
		}
		if hello.Timestamp > agg.lastSeen {
			agg.lastSeen = hello.Timestamp
		}
	}

	return nil
}

// readJA4SFromTLSServerHello reads JA4S fingerprints from TLSServerHello records
func readJA4SFromTLSServerHello(outDir string, fingerprintMap map[string]*fingerprintAggregator) error {
	filePath := filepath.Join(outDir, "TLSServerHello.ncap.gz")

	// Check if file exists
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		log.Printf("[WebUI] TLSServerHello file not found: %s", filePath)
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
			log.Printf("[WebUI] Error reading TLSServerHello record: %v", err)
			continue
		}

		hello, ok := record.(*types.TLSServerHello)
		if !ok || hello.Ja4S == "" {
			continue
		}

		key := "JA4S:" + hello.Ja4S
		agg, exists := fingerprintMap[key]
		if !exists {
			agg = &fingerprintAggregator{
				fingerprint:  hello.Ja4S,
				fpType:       "JA4S",
				hosts:        make(map[string]bool),
				communityIDs: make(map[string]bool),
				firstSeen:    hello.Timestamp,
				lastSeen:     hello.Timestamp,
			}
			// Use Ja4sDescription from database lookup
			if hello.Ja4SDescription != "" {
				agg.description = hello.Ja4SDescription
			}
			fingerprintMap[key] = agg
		}

		agg.count++
		if hello.SrcIP != "" {
			agg.hosts[hello.SrcIP] = true
		}
		if hello.CommunityID != "" {
			agg.communityIDs[hello.CommunityID] = true
		}

		if hello.Timestamp < agg.firstSeen {
			agg.firstSeen = hello.Timestamp
		}
		if hello.Timestamp > agg.lastSeen {
			agg.lastSeen = hello.Timestamp
		}
	}

	return nil
}

// readJA4FromHost reads JA4/JA4S fingerprints from IPProfile records (for additional hosts)
func readJA4FromHost(outDir string, fingerprintMap map[string]*fingerprintAggregator) error {
	filePath := filepath.Join(outDir, "Host.ncap.gz")

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

		ipProfile, ok := record.(*types.Host)
		if !ok {
			continue
		}

		// Process JA4 fingerprints
		for _, ja4fp := range ipProfile.Ja4Fingerprints {
			if ja4fp == "" {
				continue
			}

			key := "JA4:" + ja4fp
			agg, exists := fingerprintMap[key]
			if !exists {
				agg = &fingerprintAggregator{
					fingerprint:  ja4fp,
					fpType:       "JA4",
					hosts:        make(map[string]bool),
					communityIDs: make(map[string]bool),
					firstSeen:    ipProfile.TimestampFirst,
					lastSeen:     ipProfile.TimestampLast,
				}
				fingerprintMap[key] = agg
			}

			// Add host but don't increment count (already counted in TLSClientHello)
			agg.hosts[ipProfile.Addr] = true

			if ipProfile.TimestampFirst < agg.firstSeen {
				agg.firstSeen = ipProfile.TimestampFirst
			}
			if ipProfile.TimestampLast > agg.lastSeen {
				agg.lastSeen = ipProfile.TimestampLast
			}
		}

		// Process JA4S fingerprints
		for _, ja4sfp := range ipProfile.Ja4SFingerprints {
			if ja4sfp == "" {
				continue
			}

			key := "JA4S:" + ja4sfp
			agg, exists := fingerprintMap[key]
			if !exists {
				agg = &fingerprintAggregator{
					fingerprint:  ja4sfp,
					fpType:       "JA4S",
					hosts:        make(map[string]bool),
					communityIDs: make(map[string]bool),
					firstSeen:    ipProfile.TimestampFirst,
					lastSeen:     ipProfile.TimestampLast,
				}
				fingerprintMap[key] = agg
			}

			// Add host but don't increment count (already counted in TLSServerHello)
			agg.hosts[ipProfile.Addr] = true

			if ipProfile.TimestampFirst < agg.firstSeen {
				agg.firstSeen = ipProfile.TimestampFirst
			}
			if ipProfile.TimestampLast > agg.lastSeen {
				agg.lastSeen = ipProfile.TimestampLast
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
				fingerprint:  fingerprint,
				fpType:       "DHCP",
				hosts:        make(map[string]bool),
				communityIDs: make(map[string]bool),
				firstSeen:    dhcp.Timestamp,
				lastSeen:     dhcp.Timestamp,
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
	fingerprint  string
	fpType       string
	count        int
	hosts        map[string]bool
	communityIDs map[string]bool
	description  string
	firstSeen    int64
	lastSeen     int64
}

// readJA4HFingerprints reads JA4H fingerprints from HTTP records
func readJA4HFingerprints(outDir string, fingerprintMap map[string]*fingerprintAggregator) error {
	filePath := filepath.Join(outDir, "HTTP.ncap.gz")

	// Check if file exists
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		log.Printf("[WebUI] HTTP file not found: %s", filePath)
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
			log.Printf("[WebUI] Error reading HTTP record: %v", err)
			continue
		}

		http, ok := record.(*types.HTTP)
		if !ok || http.Ja4H == "" {
			continue
		}

		key := "JA4H:" + http.Ja4H
		agg, exists := fingerprintMap[key]
		if !exists {
			agg = &fingerprintAggregator{
				fingerprint:  http.Ja4H,
				fpType:       "JA4H",
				hosts:        make(map[string]bool),
				communityIDs: make(map[string]bool),
				firstSeen:    http.Timestamp,
				lastSeen:     http.Timestamp,
			}
			// Use Ja4hDescription if available
			if http.Ja4HDescription != "" {
				agg.description = http.Ja4HDescription
			}
			fingerprintMap[key] = agg
		}

		agg.count++
		if http.SrcIP != "" {
			agg.hosts[http.SrcIP] = true
		}
		if http.CommunityID != "" {
			agg.communityIDs[http.CommunityID] = true
		}

		if http.Timestamp < agg.firstSeen {
			agg.firstSeen = http.Timestamp
		}
		if http.Timestamp > agg.lastSeen {
			agg.lastSeen = http.Timestamp
		}
	}

	return nil
}

// readJA4XFingerprints reads JA4X fingerprints from TLSCertificate records
func readJA4XFingerprints(outDir string, fingerprintMap map[string]*fingerprintAggregator) error {
	filePath := filepath.Join(outDir, "TLSCertificate.ncap.gz")

	// Check if file exists
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		log.Printf("[WebUI] TLSCertificate file not found: %s", filePath)
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
			log.Printf("[WebUI] Error reading TLSCertificate record: %v", err)
			continue
		}

		cert, ok := record.(*types.TLSCertificate)
		if !ok || cert.Ja4X == "" {
			continue
		}

		key := "JA4X:" + cert.Ja4X
		agg, exists := fingerprintMap[key]
		if !exists {
			agg = &fingerprintAggregator{
				fingerprint:  cert.Ja4X,
				fpType:       "JA4X",
				hosts:        make(map[string]bool),
				communityIDs: make(map[string]bool),
				firstSeen:    cert.Timestamp,
				lastSeen:     cert.Timestamp,
			}
			// Use Ja4xDescription if available
			if cert.Ja4XDescription != "" {
				agg.description = cert.Ja4XDescription
			} else if cert.SubjectCommonName != "" {
				// Use certificate subject as description if no JA4X description
				agg.description = "Subject: " + cert.SubjectCommonName
			}
			fingerprintMap[key] = agg
		}

		agg.count++
		if cert.SrcIP != "" {
			agg.hosts[cert.SrcIP] = true
		}
		if cert.DstIP != "" {
			agg.hosts[cert.DstIP] = true
		}
		if cert.CommunityID != "" {
			agg.communityIDs[cert.CommunityID] = true
		}

		if cert.Timestamp < agg.firstSeen {
			agg.firstSeen = cert.Timestamp
		}
		if cert.Timestamp > agg.lastSeen {
			agg.lastSeen = cert.Timestamp
		}
	}

	return nil
}

// readJA4TFingerprints reads JA4T and JA4TS fingerprints from TCP records
func readJA4TFingerprints(outDir string, fingerprintMap map[string]*fingerprintAggregator) error {
	filePath := filepath.Join(outDir, "TCP.ncap.gz")

	// Check if file exists
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		log.Printf("[WebUI] TCP file not found: %s", filePath)
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
			log.Printf("[WebUI] Error reading TCP record: %v", err)
			continue
		}

		tcp, ok := record.(*types.TCP)
		if !ok {
			continue
		}

		// Process JA4T fingerprint (client SYN)
		if tcp.Ja4T != "" {
			key := "JA4T:" + tcp.Ja4T
			agg, exists := fingerprintMap[key]
			if !exists {
				agg = &fingerprintAggregator{
					fingerprint:  tcp.Ja4T,
					fpType:       "JA4T",
					hosts:        make(map[string]bool),
					communityIDs: make(map[string]bool),
					firstSeen:    tcp.Timestamp,
					lastSeen:     tcp.Timestamp,
				}
				// Use Ja4tDescription if available
				if tcp.Ja4TDescription != "" {
					agg.description = tcp.Ja4TDescription
				}
				fingerprintMap[key] = agg
			}

			agg.count++
			if tcp.SrcIP != "" {
				agg.hosts[tcp.SrcIP] = true
			}
			if tcp.CommunityID != "" {
				agg.communityIDs[tcp.CommunityID] = true
			}

			if tcp.Timestamp < agg.firstSeen {
				agg.firstSeen = tcp.Timestamp
			}
			if tcp.Timestamp > agg.lastSeen {
				agg.lastSeen = tcp.Timestamp
			}
		}

		// Process JA4TS fingerprint (server SYN-ACK)
		if tcp.Ja4Ts != "" {
			key := "JA4TS:" + tcp.Ja4Ts
			agg, exists := fingerprintMap[key]
			if !exists {
				agg = &fingerprintAggregator{
					fingerprint:  tcp.Ja4Ts,
					fpType:       "JA4TS",
					hosts:        make(map[string]bool),
					communityIDs: make(map[string]bool),
					firstSeen:    tcp.Timestamp,
					lastSeen:     tcp.Timestamp,
				}
				// Use Ja4tsDescription if available
				if tcp.Ja4TsDescription != "" {
					agg.description = tcp.Ja4TsDescription
				}
				fingerprintMap[key] = agg
			}

			agg.count++
			if tcp.SrcIP != "" {
				agg.hosts[tcp.SrcIP] = true
			}
			if tcp.CommunityID != "" {
				agg.communityIDs[tcp.CommunityID] = true
			}

			if tcp.Timestamp < agg.firstSeen {
				agg.firstSeen = tcp.Timestamp
			}
			if tcp.Timestamp > agg.lastSeen {
				agg.lastSeen = tcp.Timestamp
			}
		}
	}

	return nil
}
