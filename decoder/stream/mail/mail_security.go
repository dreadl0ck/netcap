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

package mail

import (
	"math"
	"regexp"
	"sort"
	"strings"

	"github.com/dreadl0ck/netcap/types"
)

// MailSecurityAnalysis contains security analysis results for an email
type MailSecurityAnalysis struct {
	// SPF/DKIM/DMARC results
	SPFResult   string
	SPFDomain   string
	DKIMResult  string
	DKIMDomain  string
	DMARCResult string
	DMARCPolicy string

	// Phishing indicators
	SenderDisplayNameMismatch bool
	HasSuspiciousReplyTo      bool
	URLCount                  int32
	AttachmentCount           int32
	AttachmentTypes           []string
	HasExecutableAttachment   bool
	HasMacroEnabledAttachment bool
	SubjectEntropy            float64
	HasUrgencyKeywords        bool
	ReceivedHopCount          int32
	IsForwarded               bool
	ReplyTo                   string
	FromDomain                string
}

// Regular expressions for parsing authentication results
var (
	// SPF result patterns
	reSPFResult = regexp.MustCompile(`(?i)spf=(\w+)`)
	reSPFDomain = regexp.MustCompile(`(?i)smtp\.mailfrom=([^\s;]+)`)

	// DKIM result patterns
	reDKIMResult = regexp.MustCompile(`(?i)dkim=(\w+)`)
	reDKIMDomain = regexp.MustCompile(`(?i)header\.d=([^\s;]+)`)

	// DMARC result patterns
	reDMARCResult = regexp.MustCompile(`(?i)dmarc=(\w+)`)
	reDMARCPolicy = regexp.MustCompile(`(?i)p=(\w+)`)

	// URL pattern
	reURL = regexp.MustCompile(`https?://[^\s<>"]+`)

	// Email address pattern
	reEmailAddr     = regexp.MustCompile(`<([^>]+)>`)
	reEmailDomain   = regexp.MustCompile(`@([^\s>]+)`)
	reDKIMSigDomain = regexp.MustCompile(`d=([^\s;]+)`)

	// Urgency keywords
	urgencyKeywords = []string{
		"urgent", "immediate", "action required", "verify your",
		"suspended", "disabled", "locked", "confirm your",
		"password expire", "account expire", "security alert",
		"unauthorized", "suspicious activity", "click here",
		"act now", "limited time", "final notice", "last warning",
	}

	// Executable extensions
	executableExtensions = map[string]bool{
		".exe": true, ".dll": true, ".scr": true, ".pif": true,
		".bat": true, ".cmd": true, ".com": true, ".vbs": true,
		".vbe": true, ".js": true, ".jse": true, ".ws": true,
		".wsh": true, ".ps1": true, ".psm1": true, ".msi": true,
		".msp": true, ".hta": true, ".cpl": true, ".jar": true,
	}

	// Macro-enabled Office extensions
	macroExtensions = map[string]bool{
		".docm": true, ".dotm": true, ".xlsm": true, ".xltm": true,
		".xlam": true, ".pptm": true, ".potm": true, ".ppam": true,
		".ppsm": true, ".sldm": true,
	}
)

// AnalyzeMail performs security analysis on an email
func AnalyzeMail(mail *types.Mail, headers map[string]string, body string) *MailSecurityAnalysis {
	analysis := &MailSecurityAnalysis{}

	// Parse authentication results headers
	parseAuthenticationResults(headers, analysis)

	// Extract Reply-To header
	analysis.ReplyTo = headers["Reply-To"]

	// Extract From domain
	analysis.FromDomain = extractDomain(mail.From)

	// Check for display name mismatch
	analysis.SenderDisplayNameMismatch = checkDisplayNameMismatch(mail.From)

	// Check for suspicious Reply-To
	if analysis.ReplyTo != "" {
		replyToDomain := extractDomain(analysis.ReplyTo)
		fromDomain := analysis.FromDomain
		if fromDomain != "" && replyToDomain != "" && replyToDomain != fromDomain {
			analysis.HasSuspiciousReplyTo = true
		}
	}

	// Count URLs in body
	analysis.URLCount = int32(len(reURL.FindAllString(body, -1)))

	// Analyze attachments
	analyzeAttachments(mail, analysis)

	// Calculate subject entropy
	if mail.Subject != "" {
		analysis.SubjectEntropy = calculateStringEntropy(mail.Subject)
	}

	// Check for urgency keywords
	subjectLower := strings.ToLower(mail.Subject)
	bodyLower := strings.ToLower(body)
	for _, keyword := range urgencyKeywords {
		if strings.Contains(subjectLower, keyword) || strings.Contains(bodyLower, keyword) {
			analysis.HasUrgencyKeywords = true
			break
		}
	}

	// Count Received headers (hop count)
	analysis.ReceivedHopCount = countReceivedHeaders(headers)

	// Check if forwarded
	if headers["X-Forwarded-To"] != "" || headers["X-Forwarded-For"] != "" ||
		strings.HasPrefix(strings.ToLower(mail.Subject), "fwd:") ||
		strings.HasPrefix(strings.ToLower(mail.Subject), "fw:") {
		analysis.IsForwarded = true
	}

	return analysis
}

// parseAuthenticationResults extracts SPF/DKIM/DMARC results from headers
func parseAuthenticationResults(headers map[string]string, analysis *MailSecurityAnalysis) {
	// Check Authentication-Results header
	authResults := headers["Authentication-Results"]
	if authResults == "" {
		authResults = headers["authentication-results"]
	}

	if authResults != "" {
		// Parse SPF
		if matches := reSPFResult.FindStringSubmatch(authResults); len(matches) > 1 {
			analysis.SPFResult = strings.ToLower(matches[1])
		}
		if matches := reSPFDomain.FindStringSubmatch(authResults); len(matches) > 1 {
			analysis.SPFDomain = matches[1]
		}

		// Parse DKIM
		if matches := reDKIMResult.FindStringSubmatch(authResults); len(matches) > 1 {
			analysis.DKIMResult = strings.ToLower(matches[1])
		}
		if matches := reDKIMDomain.FindStringSubmatch(authResults); len(matches) > 1 {
			analysis.DKIMDomain = matches[1]
		}

		// Parse DMARC
		if matches := reDMARCResult.FindStringSubmatch(authResults); len(matches) > 1 {
			analysis.DMARCResult = strings.ToLower(matches[1])
		}
		if matches := reDMARCPolicy.FindStringSubmatch(authResults); len(matches) > 1 {
			analysis.DMARCPolicy = strings.ToLower(matches[1])
		}
	}

	// Also check individual headers
	if spf := headers["Received-SPF"]; spf != "" {
		parts := strings.Fields(spf)
		if len(parts) > 0 {
			analysis.SPFResult = strings.ToLower(parts[0])
		}
	}

	if dkim := headers["DKIM-Signature"]; dkim != "" && analysis.DKIMDomain == "" {
		// Extract domain from DKIM-Signature header
		if matches := reDKIMSigDomain.FindStringSubmatch(dkim); len(matches) > 1 {
			analysis.DKIMDomain = matches[1]
		}
	}
}

// checkDisplayNameMismatch checks if the display name suggests a different domain than the actual sender
func checkDisplayNameMismatch(from string) bool {
	if from == "" {
		return false
	}

	// Extract email address and display name
	// Format: "Display Name <email@domain.com>" or just "email@domain.com"

	emailMatch := reEmailAddr.FindStringSubmatch(from)
	if len(emailMatch) < 2 {
		return false // No angle brackets, can't have display name mismatch
	}

	actualEmail := emailMatch[1]
	displayName := strings.TrimSpace(strings.TrimSuffix(from, emailMatch[0]))

	if displayName == "" {
		return false
	}

	// Check if display name contains an email address that differs from actual
	if strings.Contains(displayName, "@") {
		displayEmailDomain := extractDomain(displayName)
		actualDomain := extractDomain(actualEmail)
		if displayEmailDomain != "" && actualDomain != "" && displayEmailDomain != actualDomain {
			return true
		}
	}

	return false
}

// extractDomain extracts the domain from an email address
func extractDomain(email string) string {
	// Handle "Display Name <email@domain.com>" format
	if matches := reEmailAddr.FindStringSubmatch(email); len(matches) > 1 {
		email = matches[1]
	}

	// Extract domain
	if matches := reEmailDomain.FindStringSubmatch(email); len(matches) > 1 {
		domain := strings.TrimRight(matches[1], ">")
		return strings.ToLower(domain)
	}

	return ""
}

// analyzeAttachments analyzes attachments in the mail
func analyzeAttachments(mail *types.Mail, analysis *MailSecurityAnalysis) {
	for _, part := range mail.Body {
		if part.Filename != "" || strings.Contains(part.Header["Content-Disposition"], "attachment") {
			analysis.AttachmentCount++

			// Get content type
			contentType := part.Header["Content-Type"]
			if contentType != "" {
				// Extract just the MIME type without parameters
				if idx := strings.Index(contentType, ";"); idx > 0 {
					contentType = strings.TrimSpace(contentType[:idx])
				}
				analysis.AttachmentTypes = append(analysis.AttachmentTypes, contentType)
			}

			// Check for executable extensions
			filename := strings.ToLower(part.Filename)
			for ext := range executableExtensions {
				if strings.HasSuffix(filename, ext) {
					analysis.HasExecutableAttachment = true
					break
				}
			}

			// Check for macro-enabled extensions
			for ext := range macroExtensions {
				if strings.HasSuffix(filename, ext) {
					analysis.HasMacroEnabledAttachment = true
					break
				}
			}
		}
	}
}

// calculateStringEntropy calculates Shannon entropy of a string
func calculateStringEntropy(s string) float64 {
	if len(s) == 0 {
		return 0
	}

	freq := make(map[rune]int)
	for _, r := range s {
		freq[r]++
	}

	// Summing in map order would vary the floating point rounding per run.
	runes := make([]rune, 0, len(freq))
	for r := range freq {
		runes = append(runes, r)
	}
	sort.Slice(runes, func(i, j int) bool { return runes[i] < runes[j] })

	var entropy float64
	length := float64(len(s))

	for _, r := range runes {
		if count := freq[r]; count > 0 {
			p := float64(count) / length
			entropy -= p * math.Log2(p)
		}
	}

	return entropy
}

// countReceivedHeaders counts the number of Received headers (hop count)
func countReceivedHeaders(headers map[string]string) int32 {
	count := int32(0)

	// Check for Received header
	if received := headers["Received"]; received != "" {
		// Count semicolons as an approximation - each hop adds a Received header
		// which typically contains a semicolon before the timestamp
		count = int32(strings.Count(received, ";"))
		if count == 0 && received != "" {
			count = 1
		}
	}

	// Also count numbered Received headers (some parsers split them)
	for key := range headers {
		if strings.HasPrefix(strings.ToLower(key), "received") {
			count++
		}
	}

	// Normalize - we might have counted the main one twice
	if count > 0 {
		return count
	}

	return 0
}
