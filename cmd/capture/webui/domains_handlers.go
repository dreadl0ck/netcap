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
	"strings"

	"github.com/dreadl0ck/netcap/types"
)

// DomainSummary represents aggregated information for a single domain
type DomainSummary struct {
	Domain         string   `json:"domain"`
	QueryCount     int      `json:"queryCount"`
	UniqueClients  int      `json:"uniqueClients"`
	RecordTypes    []string `json:"recordTypes"`
	ResponseCodes  []int32  `json:"responseCodes"`
	FirstSeen      int64    `json:"firstSeen"`
	LastSeen       int64    `json:"lastSeen"`
	IsSubdomain    bool     `json:"isSubdomain"`
	ParentDomain   string   `json:"parentDomain"`
	ResolvedIPs    []string `json:"resolvedIPs"`
}

// DomainsResponse contains the list of domains
type DomainsResponse struct {
	Domains    []DomainSummary `json:"domains"`
	TotalCount int             `json:"totalCount"`
}

// handleDomains returns a list of all domains extracted from DNS records
func (s *Server) handleDomains(w http.ResponseWriter, r *http.Request) {
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

	domains, err := readDomains(outDir)
	if err != nil {
		log.Printf("[WebUI] Failed to read domains: %v", err)
		http.Error(w, "Failed to read domains", http.StatusInternalServerError)
		return
	}

	response := DomainsResponse{
		Domains:    domains,
		TotalCount: len(domains),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// readDomains reads and aggregates domain data from DNS records
func readDomains(outDir string) ([]DomainSummary, error) {
	filePath := filepath.Join(outDir, "DNS.ncap.gz")

	// Check if file exists
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		log.Printf("[WebUI] DNS file not found: %s", filePath)
		return []DomainSummary{}, nil
	}

	// Read DNS records
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

	// Domain aggregation map
	domainMap := make(map[string]*domainAggregator)

	// Read all records
	for {
		record, err := reader.NextRecord()
		if err != nil {
			if err == io.EOF {
				break
			}
			log.Printf("[WebUI] Error reading DNS record: %v", err)
			continue
		}

		// Type assert to DNS
		dns, ok := record.(*types.DNS)
		if !ok {
			continue
		}

		// Extract domains from questions
		for _, question := range dns.Questions {
			if question.Name == "" {
				continue
			}
			
			domain := strings.ToLower(strings.TrimSuffix(question.Name, "."))
			if domain == "" {
				continue
			}

			agg, exists := domainMap[domain]
			if !exists {
				agg = &domainAggregator{
					domain:        domain,
					clients:       make(map[string]bool),
					recordTypes:   make(map[int32]bool),   // Use int32
					responseCodes: make(map[int32]bool),
					ips:           make(map[string]bool),
					firstSeen:     dns.Timestamp,
					lastSeen:      dns.Timestamp,
				}
				domainMap[domain] = agg
			}

			agg.queryCount++
			agg.clients[dns.SrcIP] = true
			agg.recordTypes[question.Type] = true
			agg.responseCodes[dns.ResponseCode] = true

			if dns.Timestamp < agg.firstSeen {
				agg.firstSeen = dns.Timestamp
			}
			if dns.Timestamp > agg.lastSeen {
				agg.lastSeen = dns.Timestamp
			}
		}

		// Extract resolved IPs from answers
		for _, answer := range dns.Answers {
			if answer.IP != "" {
				// Find the domain this answer belongs to
				for _, question := range dns.Questions {
					domain := strings.ToLower(strings.TrimSuffix(question.Name, "."))
					if agg, exists := domainMap[domain]; exists {
						agg.ips[answer.IP] = true
					}
				}
			}
		}
	}

	// Convert map to slice
	domains := make([]DomainSummary, 0, len(domainMap))
	for _, agg := range domainMap {
		// Convert maps to slices
		recordTypes := make([]string, 0, len(agg.recordTypes))
		for rt := range agg.recordTypes {
			// Convert DNS type codes to strings
			rtString := dnsTypeToString(rt)
			recordTypes = append(recordTypes, rtString)
		}

		responseCodes := make([]int32, 0, len(agg.responseCodes))
		for rc := range agg.responseCodes {
			responseCodes = append(responseCodes, rc)
		}

		resolvedIPs := make([]string, 0, len(agg.ips))
		for ip := range agg.ips {
			resolvedIPs = append(resolvedIPs, ip)
		}

		// Determine if subdomain and parent domain
		isSubdomain := false
		parentDomain := ""
		parts := strings.Split(agg.domain, ".")
		if len(parts) > 2 {
			isSubdomain = true
			parentDomain = strings.Join(parts[len(parts)-2:], ".")
		}

		domains = append(domains, DomainSummary{
			Domain:         agg.domain,
			QueryCount:     agg.queryCount,
			UniqueClients:  len(agg.clients),
			RecordTypes:    recordTypes,
			ResponseCodes:  responseCodes,
			FirstSeen:      agg.firstSeen,
			LastSeen:       agg.lastSeen,
			IsSubdomain:    isSubdomain,
			ParentDomain:   parentDomain,
			ResolvedIPs:    resolvedIPs,
		})
	}

	// Sort by query count descending
	sort.Slice(domains, func(i, j int) bool {
		return domains[i].QueryCount > domains[j].QueryCount
	})

	return domains, nil
}

// dnsTypeToString converts DNS type codes to human-readable strings
func dnsTypeToString(dnsType int32) string {
	switch dnsType {
	case 1:
		return "A"
	case 2:
		return "NS"
	case 5:
		return "CNAME"
	case 6:
		return "SOA"
	case 12:
		return "PTR"
	case 15:
		return "MX"
	case 16:
		return "TXT"
	case 28:
		return "AAAA"
	case 33:
		return "SRV"
	case 255:
		return "ANY"
	default:
		return "TYPE" + string(rune(dnsType+'0'))
	}
}

// domainAggregator holds temporary aggregation data for a domain
type domainAggregator struct {
	domain        string
	queryCount    int
	clients       map[string]bool
	recordTypes   map[int32]bool   // Use int32 as DNS type is int32
	responseCodes map[int32]bool
	ips           map[string]bool
	firstSeen     int64
	lastSeen      int64
}

