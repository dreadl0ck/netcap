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

package packet

import (
	"fmt"
	"net"
	"regexp"
	"strings"

	"github.com/dreadl0ck/netcap/types"
)

// Known SIP attack tool User-Agent patterns (case-insensitive matching)
var knownSIPAttackTools = []string{
	"sipvicious",
	"sip-scan",
	"friendly-scanner",
	"sundayddr",
	"iwar",
	"sipsak",
	"sipcli",
	"sippts",
	"sip-scan",
	"voiphopper",
	"svmap",
	"svwar",
	"svcrack",
}

// SDP parsing patterns
var (
	// SDP connection line: c=IN IP4 192.168.1.100
	reSDPConnection = regexp.MustCompile(`c=IN IP[46]\s+([^\s\r\n]+)`)
	// SDP media line: m=audio 5004 RTP/AVP 0
	reSDPMedia = regexp.MustCompile(`m=(\w+)\s+(\d+)\s+([^\r\n]+)`)
	// Via header IP extraction: Via: SIP/2.0/UDP 192.168.1.100:5060;branch=...
	reViaIP = regexp.MustCompile(`(?:SIP/2\.0/(?:UDP|TCP|TLS|SCTP|WS|WSS)\s+)([^:;\s]+)`)
)

// Maximum header length before considering it oversized (potential buffer overflow)
const maxHeaderLength = 256

// analyzeSIPSecurity performs comprehensive security analysis on a SIP message
func analyzeSIPSecurity(msg *types.SIP) {
	var riskFactors []string
	riskScore := 0

	// 1. Check for known attack tools in User-Agent
	if msg.UserAgent != "" {
		if isKnownSIPAttackTool(msg.UserAgent) {
			msg.HasKnownAttackTool = true
			riskFactors = append(riskFactors, fmt.Sprintf("known_attack_tool_ua_%s", sanitizeForLog(msg.UserAgent)))
			riskScore += 50
		}
	}

	// 2. Check for Via header spoofing (internal IP from external source)
	if msg.Via != "" {
		if viaIP := extractViaIP(msg.Via); viaIP != "" {
			if isSIPPrivateIP(viaIP) && !isSIPPrivateIP(msg.SrcIP) {
				msg.HasViaSpoofing = true
				riskFactors = append(riskFactors, fmt.Sprintf("via_spoofing_internal_ip_%s_from_external_%s", viaIP, msg.SrcIP))
				riskScore += 35
			}
		}
	}

	// 3. Check for oversized headers (potential buffer overflow)
	if len(msg.CallID) > maxHeaderLength {
		msg.HasOversizedHeaders = true
		riskFactors = append(riskFactors, fmt.Sprintf("oversized_callid_%d_bytes", len(msg.CallID)))
		riskScore += 40
	}
	if len(msg.From) > maxHeaderLength {
		msg.HasOversizedHeaders = true
		riskFactors = append(riskFactors, fmt.Sprintf("oversized_from_%d_bytes", len(msg.From)))
		riskScore += 40
	}
	if len(msg.To) > maxHeaderLength {
		msg.HasOversizedHeaders = true
		riskFactors = append(riskFactors, fmt.Sprintf("oversized_to_%d_bytes", len(msg.To)))
		riskScore += 40
	}
	if len(msg.Contact) > maxHeaderLength {
		msg.HasOversizedHeaders = true
		riskFactors = append(riskFactors, fmt.Sprintf("oversized_contact_%d_bytes", len(msg.Contact)))
		riskScore += 40
	}
	if len(msg.UserAgent) > maxHeaderLength {
		msg.HasOversizedHeaders = true
		riskFactors = append(riskFactors, fmt.Sprintf("oversized_useragent_%d_bytes", len(msg.UserAgent)))
		riskScore += 40
	}

	// 4. Check Max-Forwards for topology mapping (value 0 or very small)
	if msg.MaxForwards == 0 && !msg.IsResponse {
		riskFactors = append(riskFactors, "max_forwards_zero_topology_mapping")
		riskScore += 20
	} else if msg.MaxForwards > 0 && msg.MaxForwards <= 2 && !msg.IsResponse {
		riskFactors = append(riskFactors, fmt.Sprintf("max_forwards_low_%d_topology_mapping", msg.MaxForwards))
		riskScore += 15
	}

	// 5. Analyze SDP body for media hijacking (private IP leakage)
	if len(msg.Body) > 0 && strings.Contains(msg.ContentType, "sdp") {
		analyzeSDPSecurity(msg, &riskFactors, &riskScore)
	}

	// 6. Check for From header domain spoofing indicators
	// (External source claiming internal domain - basic check)
	if msg.From != "" && !msg.IsResponse {
		fromDomain := extractSIPDomain(msg.From)
		if fromDomain != "" && isInternalDomain(fromDomain) && !isSIPPrivateIP(msg.SrcIP) {
			riskFactors = append(riskFactors, fmt.Sprintf("from_domain_spoofing_%s_from_external_%s", fromDomain, msg.SrcIP))
			riskScore += 30
		}
	}

	// Update anomaly flags
	if len(riskFactors) > 0 {
		msg.IsAnomalous = true
		msg.AnomalyReason = strings.Join(riskFactors, "; ")
	}

	// Normalize risk score to 0-100
	if riskScore > 100 {
		riskScore = 100
	}
	msg.RiskScore = int32(riskScore)
	msg.RiskFactors = riskFactors
}

// analyzeSDPSecurity analyzes SDP body for security issues
func analyzeSDPSecurity(msg *types.SIP, riskFactors *[]string, riskScore *int) {
	body := string(msg.Body)

	// Extract SDP connection IP (c= line)
	if matches := reSDPConnection.FindStringSubmatch(body); len(matches) > 1 {
		msg.SDPConnectionIP = matches[1]

		// Check for private IP leakage from external source
		if isSIPPrivateIP(msg.SDPConnectionIP) && !isSIPPrivateIP(msg.SrcIP) {
			msg.HasSDPPrivateIPLeak = true
			*riskFactors = append(*riskFactors, fmt.Sprintf("sdp_private_ip_leak_%s_from_external_%s", msg.SDPConnectionIP, msg.SrcIP))
			*riskScore += 25
		}
	}

	// Extract SDP media type (m= line)
	if matches := reSDPMedia.FindStringSubmatch(body); len(matches) > 1 {
		msg.SDPMediaType = matches[1]
	}
}

// isKnownSIPAttackTool checks if User-Agent matches known attack tools
func isKnownSIPAttackTool(ua string) bool {
	uaLower := strings.ToLower(ua)
	for _, tool := range knownSIPAttackTools {
		if strings.Contains(uaLower, tool) {
			return true
		}
	}
	return false
}

// extractViaIP extracts the IP address from a Via header
func extractViaIP(via string) string {
	if matches := reViaIP.FindStringSubmatch(via); len(matches) > 1 {
		return matches[1]
	}
	// Fallback: try to find any IP-like pattern
	// Via: SIP/2.0/UDP 192.168.1.100:5060
	parts := strings.Fields(via)
	for _, part := range parts {
		// Remove port if present
		host := strings.Split(part, ":")[0]
		if ip := net.ParseIP(host); ip != nil {
			return host
		}
	}
	return ""
}

// isSIPPrivateIP checks if an IP address is in RFC1918 private ranges or other internal ranges
// This is a more comprehensive check than the basic isPrivateIP in connection.go
func isSIPPrivateIP(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}

	// Check IPv4 private ranges
	privateRanges := []struct {
		network *net.IPNet
	}{
		{mustParseCIDR("10.0.0.0/8")},
		{mustParseCIDR("172.16.0.0/12")},
		{mustParseCIDR("192.168.0.0/16")},
		{mustParseCIDR("127.0.0.0/8")},      // Loopback
		{mustParseCIDR("169.254.0.0/16")},   // Link-local
		{mustParseCIDR("100.64.0.0/10")},    // Carrier-grade NAT
	}

	for _, r := range privateRanges {
		if r.network.Contains(ip) {
			return true
		}
	}

	// Check IPv6 private/local ranges
	if ip.To4() == nil {
		privateRangesV6 := []struct {
			network *net.IPNet
		}{
			{mustParseCIDR("::1/128")},     // Loopback
			{mustParseCIDR("fc00::/7")},    // Unique local
			{mustParseCIDR("fe80::/10")},   // Link-local
		}
		for _, r := range privateRangesV6 {
			if r.network.Contains(ip) {
				return true
			}
		}
	}

	return false
}

// mustParseCIDR parses a CIDR string and panics on error
func mustParseCIDR(s string) *net.IPNet {
	_, ipNet, err := net.ParseCIDR(s)
	if err != nil {
		panic(err)
	}
	return ipNet
}

// extractSIPDomain extracts the domain from a SIP URI in From/To header
// e.g., "Display Name" <sip:user@domain.com>;tag=xxx -> domain.com
func extractSIPDomain(sipAddr string) string {
	// Find the @ symbol
	atIdx := strings.Index(sipAddr, "@")
	if atIdx == -1 {
		return ""
	}

	// Extract domain part (after @, before > or ; or end)
	rest := sipAddr[atIdx+1:]

	// Remove trailing > if present
	if gtIdx := strings.Index(rest, ">"); gtIdx != -1 {
		rest = rest[:gtIdx]
	}

	// Remove parameters (after ;)
	if semiIdx := strings.Index(rest, ";"); semiIdx != -1 {
		rest = rest[:semiIdx]
	}

	// Remove port if present
	if colonIdx := strings.Index(rest, ":"); colonIdx != -1 {
		rest = rest[:colonIdx]
	}

	return strings.TrimSpace(rest)
}

// isInternalDomain checks if a domain looks like an internal/private domain
// This is a heuristic check for common internal domain patterns
func isInternalDomain(domain string) bool {
	domainLower := strings.ToLower(domain)

	// Common internal domain patterns
	internalPatterns := []string{
		".local",
		".internal",
		".corp",
		".lan",
		".private",
		".home",
		".localdomain",
		".intranet",
	}

	for _, pattern := range internalPatterns {
		if strings.HasSuffix(domainLower, pattern) {
			return true
		}
	}

	// Check if it's a private IP address used as domain
	if isSIPPrivateIP(domain) {
		return true
	}

	return false
}

// sanitizeForLog removes/escapes potentially dangerous characters for logging
func sanitizeForLog(s string) string {
	// Replace newlines, tabs, and other control characters
	s = strings.ReplaceAll(s, "\n", "\\n")
	s = strings.ReplaceAll(s, "\r", "\\r")
	s = strings.ReplaceAll(s, "\t", "\\t")

	// Truncate long strings
	if len(s) > 100 {
		s = s[:100] + "..."
	}

	return s
}

