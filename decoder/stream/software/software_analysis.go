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

package software

import (
	"regexp"
	"strings"

	"github.com/dreadl0ck/netcap/types"
)

// Software behavioral profiles
const (
	BehaviorServer  = "server"
	BehaviorClient  = "client"
	BehaviorProxy   = "proxy"
	BehaviorScanner = "scanner"
	BehaviorBot     = "bot"
	BehaviorCrawler = "crawler"
	BehaviorUnknown = "unknown"
)

// Detection confidence levels
const (
	ConfidenceHigh   = "high"
	ConfidenceMedium = "medium"
	ConfidenceLow    = "low"
)

// Support status values
const (
	SupportActive      = "active"
	SupportMaintenance = "maintenance"
	SupportEOL         = "eol"
	SupportUnknown     = "unknown"
)

// Headless browser indicators
var headlessIndicators = []string{
	"headless", "phantomjs", "puppeteer", "selenium",
	"webdriver", "chromedriver", "geckodriver",
	"nightmare", "playwright", "cypress",
}

// Bot/crawler user agents
var botIndicators = []string{
	"bot", "crawler", "spider", "scraper",
	"googlebot", "bingbot", "yandexbot", "baiduspider",
	"slurp", "duckduckbot", "facebookexternalhit",
	"twitterbot", "linkedinbot", "pinterestbot",
	"ia_archiver", "mediapartners", "adsbot",
}

// Scanner indicators
var scannerIndicators = []string{
	"nmap", "masscan", "zmap", "nikto", "burp",
	"sqlmap", "wfuzz", "dirbuster", "gobuster",
	"nuclei", "wpscan", "acunetix", "nessus",
	"qualys", "openvas", "w3af", "arachni",
}

// Known automation tools
var automationIndicators = []string{
	"python-requests", "python-urllib", "curl",
	"wget", "httpie", "axios", "got", "node-fetch",
	"okhttp", "java", "libwww-perl", "lwp",
	"mechanize", "scrapy", "httpclient",
}

// Proxy indicators
var proxyIndicators = []string{
	"proxy", "squid", "nginx", "haproxy", "varnish",
	"traefik", "envoy", "caddy", "apache traffic server",
}

// Known EOL software patterns
var eolPatterns = map[*regexp.Regexp]bool{
	regexp.MustCompile(`(?i)windows\s*(xp|vista|7|8|8\.1)`):              true,
	regexp.MustCompile(`(?i)internet\s*explorer\s*(6|7|8|9|10|11)`):      true,
	regexp.MustCompile(`(?i)python\s*(2\.[0-7])`):                        true,
	regexp.MustCompile(`(?i)php\s*(5\.[0-6]|7\.[0-3])`):                  true,
	regexp.MustCompile(`(?i)apache\s*(1\.|2\.[0-2])`):                    true,
	regexp.MustCompile(`(?i)nginx\s*(0\.|1\.[0-9]\.)`):                   true,
	regexp.MustCompile(`(?i)openssl\s*(0\.|1\.0\.[0-1])`):                true,
	regexp.MustCompile(`(?i)java\s*(1\.[0-7]|8|9|10|11)`):                true, // Java 8-11 LTS still supported but older
	regexp.MustCompile(`(?i)node\s*(0\.|4\.|6\.|8\.|10\.|12\.|14\.)`):    true, // Node older versions
	regexp.MustCompile(`(?i)ruby\s*(1\.|2\.[0-5])`):                      true,
	regexp.MustCompile(`(?i)perl\s*(5\.(8|10|12|14|16|18|20|22|24|26))`): true,
}

// EnhanceSoftwareRecord adds detection context and behavioral fields to a Software record
func EnhanceSoftwareRecord(s *types.Software) {
	if s == nil {
		return
	}

	// Set detection method based on SourceName
	s.DetectionMethod = mapSourceNameToMethod(s.SourceName)

	// Set confidence level based on detection method
	s.ConfidenceLevel = determineConfidence(s)

	// Determine behavior profile
	s.BehaviorProfile = determineBehaviorProfile(s)

	// Check for headless/automated browsers
	s.IsHeadless = isHeadless(s)
	s.IsAutomated = isAutomated(s)

	// Check for emulated environment
	s.IsEmulated = isEmulated(s)

	// Check for EOL status
	s.IsEndOfLife, s.SupportStatus = checkEOLStatus(s)
}

// mapSourceNameToMethod maps the source name to a detection method
func mapSourceNameToMethod(sourceName string) string {
	sourceNameLower := strings.ToLower(sourceName)

	switch {
	case strings.Contains(sourceNameLower, "useragent"):
		return "user_agent"
	case strings.Contains(sourceNameLower, "banner"):
		return "banner"
	case strings.Contains(sourceNameLower, "hassh"):
		return "hassh"
	case strings.Contains(sourceNameLower, "ja3"):
		return "ja3"
	case strings.Contains(sourceNameLower, "server"):
		return "http_header"
	case strings.Contains(sourceNameLower, "x-powered"):
		return "http_header"
	case strings.Contains(sourceNameLower, "x-mailer"):
		return "http_header"
	case strings.Contains(sourceNameLower, "tls"):
		return "tls_cert"
	case strings.Contains(sourceNameLower, "dpi"):
		return "dpi"
	case strings.Contains(sourceNameLower, "cms"):
		return "cms_detection"
	default:
		return sourceName
	}
}

// determineConfidence determines confidence level based on detection method
func determineConfidence(s *types.Software) string {
	method := strings.ToLower(s.DetectionMethod)

	// High confidence methods
	if method == "banner" || method == "hassh" || method == "ja3" ||
		method == "tls_cert" || method == "dpi" {
		return ConfidenceHigh
	}

	// Medium confidence methods
	if method == "user_agent" || method == "http_header" || method == "cms_detection" {
		// User agents can be spoofed, but usually accurate
		return ConfidenceMedium
	}

	return ConfidenceLow
}

// determineBehaviorProfile determines the behavior profile of the software
func determineBehaviorProfile(s *types.Software) string {
	productLower := strings.ToLower(s.Product)
	vendorLower := strings.ToLower(s.Vendor)
	notesLower := strings.ToLower(s.Notes)
	sourceDataLower := strings.ToLower(s.SourceData)
	combined := productLower + " " + vendorLower + " " + notesLower + " " + sourceDataLower

	// Check for scanners
	for _, indicator := range scannerIndicators {
		if strings.Contains(combined, indicator) {
			return BehaviorScanner
		}
	}

	// Check for bots/crawlers
	for _, indicator := range botIndicators {
		if strings.Contains(combined, indicator) {
			return BehaviorBot
		}
	}

	// Check for proxies
	for _, indicator := range proxyIndicators {
		if strings.Contains(combined, indicator) {
			return BehaviorProxy
		}
	}

	// Check if it's a server or client based on service
	service := strings.ToLower(s.Service)
	switch {
	case strings.Contains(service, "server"):
		return BehaviorServer
	case strings.Contains(productLower, "server"):
		return BehaviorServer
	case strings.Contains(productLower, "apache"):
		return BehaviorServer
	case strings.Contains(productLower, "nginx"):
		return BehaviorServer
	case strings.Contains(productLower, "iis"):
		return BehaviorServer
	case strings.Contains(productLower, "client"):
		return BehaviorClient
	case strings.Contains(productLower, "chrome"):
		return BehaviorClient
	case strings.Contains(productLower, "firefox"):
		return BehaviorClient
	case strings.Contains(productLower, "safari"):
		return BehaviorClient
	case strings.Contains(productLower, "edge"):
		return BehaviorClient
	}

	return BehaviorUnknown
}

// isHeadless checks if the software is a headless browser
func isHeadless(s *types.Software) bool {
	combined := strings.ToLower(s.Product + " " + s.SourceData + " " + s.Notes)

	for _, indicator := range headlessIndicators {
		if strings.Contains(combined, indicator) {
			return true
		}
	}

	// Check for headless Chrome/Firefox indicators in user agent
	if strings.Contains(combined, "headlesschrome") ||
		strings.Contains(combined, "headless chrome") {
		return true
	}

	return false
}

// isAutomated checks if the software is an automation tool
func isAutomated(s *types.Software) bool {
	combined := strings.ToLower(s.Product + " " + s.SourceData + " " + s.Notes)

	// Check for automation tools
	for _, indicator := range automationIndicators {
		if strings.Contains(combined, indicator) {
			return true
		}
	}

	// Check for headless (headless browsers are automated)
	if s.IsHeadless {
		return true
	}

	return false
}

// isEmulated checks if the software is running in an emulated environment
func isEmulated(s *types.Software) bool {
	combined := strings.ToLower(s.Product + " " + s.SourceData + " " + s.Notes + " " + s.OS)

	emulationIndicators := []string{
		"emulator", "simulator", "virtual", "sandbox",
		"wine", "crossover", "parallels", "vmware",
		"virtualbox", "qemu", "hyper-v", "docker",
		"android sdk", "ios simulator",
	}

	for _, indicator := range emulationIndicators {
		if strings.Contains(combined, indicator) {
			return true
		}
	}

	return false
}

// checkEOLStatus checks if the software version is end-of-life
func checkEOLStatus(s *types.Software) (bool, string) {
	combined := s.Product + " " + s.Version

	for pattern := range eolPatterns {
		if pattern.MatchString(combined) {
			return true, SupportEOL
		}
	}

	// Check for very old versions (version starts with 0. or 1.)
	if strings.HasPrefix(s.Version, "0.") {
		return false, SupportMaintenance // Pre-1.0 versions might be in development
	}

	return false, SupportUnknown
}

// CheckVulnerabilities sets the HasKnownVulnerabilities flag
// This should be called after vulnerability lookup
func CheckVulnerabilities(s *types.Software, hasVulns bool) {
	s.HasKnownVulnerabilities = hasVulns
}
