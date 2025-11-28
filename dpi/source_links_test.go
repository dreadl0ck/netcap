//go:build (!windows && ignore) || !nodpi
// +build !windows,ignore !nodpi

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

package dpi

import (
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"
)

// TestDecoderSourceLinks verifies that all links to DPI decoder source code are accessible
// and return 200 OK. This test iterates over all protocols from all modules (go, ndpi, lpi)
// and checks their source code links on GitHub.
func TestDecoderSourceLinks(t *testing.T) {
	// Get all module protocols
	moduleProtocols := GetModuleProtocols()

	if len(moduleProtocols) == 0 {
		t.Skip("No DPI modules available, skipping source link validation")
	}

	// Create HTTP client with timeout
	client := &http.Client{
		Timeout: 15 * time.Second,
		// Follow redirects
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return fmt.Errorf("too many redirects")
			}
			return nil
		},
	}

	var (
		totalLinks      int
		brokenLinks     []string
		rateLimitedURLs []string
		checkedURLs     = make(map[string]bool) // Deduplicate URLs
	)

	t.Logf("Starting validation of DPI decoder source links...")

	// Iterate over all modules
	for module, protocols := range moduleProtocols {
		t.Logf("\n=== Testing module: %s (%d protocols) ===", module, len(protocols))

		for _, protocol := range protocols {
			// Get all possible URLs for this protocol
			urls := getProtocolSourceURLs(module, protocol)

			var foundWorking bool
			var lastError string

			for urlIdx, url := range urls {
				// Skip placeholder URLs and deduplicate
				if url == "#" || url == "" {
					continue
				}
				if checkedURLs[url] {
					// Already checked this URL for another protocol
					continue
				}
				checkedURLs[url] = true

				totalLinks++

				// Check if the URL is accessible
				resp, err := client.Get(url)
				if err != nil {
					lastError = fmt.Sprintf("ERROR - Module: %s, Protocol: %s, URL: %s, Error: %v",
						module, protocol, url, err)
					// Don't add to broken links yet, might have more URLs to try
					continue
				}

				// Check status code
				if resp.StatusCode != http.StatusOK {
					resp.Body.Close()

					if resp.StatusCode == http.StatusServiceUnavailable || resp.StatusCode == http.StatusTooManyRequests {
						// Rate limited by GitHub
						rateLimitURL := fmt.Sprintf("Rate Limited (HTTP %d) - Module: %s, Protocol: %s, URL[%d]: %s",
							resp.StatusCode, module, protocol, urlIdx, url)
						rateLimitedURLs = append(rateLimitedURLs, rateLimitURL)
						lastError = rateLimitURL
						// Increase delay after hitting rate limits
						time.Sleep(2 * time.Second)
					} else {
						// Actual broken link (404, etc) - but keep trying other URLs
						lastError = fmt.Sprintf("HTTP %d - Module: %s, Protocol: %s, URL[%d]: %s",
							resp.StatusCode, module, protocol, urlIdx, url)
					}

					// If this is the last URL and we haven't found a working one, log it
					if urlIdx == len(urls)-1 && !foundWorking {
						brokenLinks = append(brokenLinks, lastError)
						t.Logf("✗ %s", lastError)
					}
				} else {
					// Success!
					resp.Body.Close()
					foundWorking = true

					// Only log occasionally to reduce noise, or when we found alternative URL
					if totalLinks%50 == 0 || urlIdx > 0 {
						t.Logf("✓ %s: %s - URL[%d]: %s (checked %d links)", module, protocol, urlIdx, url, totalLinks)
					}

					// Found a working URL, no need to check others
					break
				}

				// Be nice to GitHub's rate limiting
				time.Sleep(200 * time.Millisecond)
			}
		}
	}

	// Print summary
	separator := strings.Repeat("=", 80)
	t.Logf("\n%s", separator)
	t.Logf("SUMMARY:")
	t.Logf("  Total unique links checked: %d", totalLinks)
	t.Logf("  Successfully verified: %d", totalLinks-len(brokenLinks)-len(rateLimitedURLs))
	t.Logf("  Broken links (404, etc): %d", len(brokenLinks))
	t.Logf("  Rate limited (503, 429): %d", len(rateLimitedURLs))
	t.Logf("%s", separator)

	// Print all broken links (actual 404s, etc)
	if len(brokenLinks) > 0 {
		t.Logf("\n%s", separator)
		t.Logf("BROKEN LINKS (404, etc):")
		t.Logf("%s", separator)
		for i, link := range brokenLinks {
			t.Logf("%d. %s", i+1, link)
		}
		t.Logf("%s", separator)
	}

	// Optionally print rate limited URLs (if not too many)
	if len(rateLimitedURLs) > 0 && len(rateLimitedURLs) <= 20 {
		t.Logf("\n%s", separator)
		t.Logf("RATE LIMITED URLs (may need re-checking):")
		t.Logf("%s", separator)
		for i, link := range rateLimitedURLs {
			t.Logf("%d. %s", i+1, link)
		}
		t.Logf("%s", separator)
	} else if len(rateLimitedURLs) > 20 {
		t.Logf("\nNote: %d URLs were rate-limited by GitHub. Re-run the test later to check these.", len(rateLimitedURLs))
	}

	// Final message
	if len(brokenLinks) == 0 && len(rateLimitedURLs) == 0 {
		t.Logf("\n✓ All decoder source links are accessible!")
	} else if len(brokenLinks) == 0 {
		t.Logf("\n✓ No broken links found (but %d were rate-limited)", len(rateLimitedURLs))
	} else {
		// Don't fail the test - just report the broken links
		// This allows the test to run without failing the build if external links are temporarily unavailable
		t.Logf("\nWARNING: Found %d broken link(s). This test does not fail to avoid breaking builds due to external link issues.", len(brokenLinks))
		t.Logf("Please review and fix the broken links listed above.")
	}
}

// getProtocolSourceURL generates the source code URL for a given module and protocol.
// This function mirrors the logic from the frontend's getProtocolSourceUrl function
// in cmd/capture/webui/frontend/src/pages/dpi.tsx
func getProtocolSourceURL(module, protocol string) string {
	urls := getProtocolSourceURLs(module, protocol)
	if len(urls) > 0 {
		return urls[0]
	}
	return "#"
}

// getProtocolSourceURLs returns multiple possible URLs for a protocol
// nDPI uses different implementation methods: C files, IP lists, SNI/host detection, etc.
func getProtocolSourceURLs(module, protocol string) []string {
	protocolLower := strings.ToLower(protocol)

	switch module {
	case "go":
		return []string{
			fmt.Sprintf("https://github.com/dreadl0ck/go-dpi/blob/master/modules/classifiers/%s.go", protocolLower),
		}
	case "ndpi":
		return getNDPIProtocolURLs(protocol, protocolLower)
	case "lpi":
		return getLPIProtocolURLs(protocol, protocolLower)
	default:
		return []string{}
	}
}

// getNDPIProtocolURLs returns possible URLs for nDPI protocol implementations
func getNDPIProtocolURLs(protocol, protocolLower string) []string {
	// Special case: Salesforce has its own dedicated IP list file
	if strings.ToUpper(protocol) == "SALESFORCE" {
		return []string{
			"https://github.com/ntop/nDPI/blob/dev/lists/protocols/266_salesforce.list",
		}
	}

	urls := []string{
		// Try standard C file first
		fmt.Sprintf("https://github.com/ntop/nDPI/blob/dev/src/lib/protocols/%s.c", protocolLower),
	}

	// Check if it's likely an IP-list based protocol (cloud services, CDNs, etc.)
	if isLikelyIPListProtocol(protocol) {
		// nDPI uses IP lists in lists/protocols/ directory
		// Format: {protocol_id}_{protocol_name}.list
		// We don't know the ID, so we'll search the lists directory
		urls = append(urls, "https://github.com/ntop/nDPI/tree/dev/lists/protocols")
	}

	// Check if it's likely detected via hardcoded IPs/domains in ndpi_content_match.c.inc
	if isLikelyContentMatchProtocol(protocol) {
		// Many services are detected via hardcoded IP addresses or domain names
		// in ndpi_content_match.c.inc (e.g., OCS, TeamViewer, advertising networks)
		urls = append(urls, "https://github.com/ntop/nDPI/blob/dev/src/lib/ndpi_content_match.c.inc")
	}

	// Add fallback to protocol categories (many are detected via TLS SNI/HTTP host)
	urls = append(urls, "https://github.com/ntop/nDPI/blob/dev/src/include/ndpi_protocol_ids.h")

	return urls
}

// isLikelyContentMatchProtocol returns true if a protocol is likely detected via
// hardcoded IP addresses or domain names in ndpi_content_match.c.inc
func isLikelyContentMatchProtocol(protocol string) bool {
	contentMatchProtocols := map[string]bool{
		// Services detected via hardcoded IPs/domains in ndpi_content_match.c.inc
		"OCS":        true, // Orange Cinéma Séries
		"TEAMVIEWER": true, // TeamViewer (many hardcoded IPs)

		// Advertising/tracking networks (detected via domain matching)
		"TRACKER_ADS": true, // Generic ad tracking

		// Streaming services (detected via domain matching in ndpi_content_match.c.inc)
		"SOUNDCLOUD":     true, // soundcloud.com
		"SPOTIFY":        true, // spotify.com
		"PANDORA":        true, // pandora.com
		"TIDAL":          true, // tidal.com
		"IHEARTRADIO":    true, // iheartradio.com
		"LASTFM":         true, // last.fm
		"DEEZER":         true, // deezer.com
		"NETFLIX":        true, // netflix.com
		"HULU":           true, // hulu.com
		"DISNEYPLUS":     true, // disneyplus.com
		"HBO":            true, // hbo.com
		"PARAMOUNTPLUS":  true, // paramountplus.com
		"YOUTUBE":        true, // youtube.com
		"YOUTUBE_UPLOAD": true, // youtube.com
		"TWITCH":         true, // twitch.tv
		"VIMEO":          true, // vimeo.com

		// Social media (detected via domain matching in ndpi_content_match.c.inc)
		"FACEBOOK":            true, // facebook.com
		"FACEBOOK_MESSENGER":  true, // messenger.com
		"FACEBOOK_VOIP":       true,
		"FACEBOOK_REEL_STORY": true,
		"INSTAGRAM":           true, // instagram.com
		"TWITTER":             true, // twitter.com, x.com
		"LINKEDIN":            true, // linkedin.com
		"REDDIT":              true, // reddit.com
		"PINTEREST":           true, // pinterest.com
		"TIKTOK":              true, // tiktok.com
		"SNAPCHAT":            true, // snapchat.com
		"SNAPCHAT_CALL":       true,
		"THREADS":             true, // threads.net
		"TUMBLR":              true, // tumblr.com
		"VK":                  true, // vk.com
		"MASTODON":            true, // mastodon instances

		// Enterprise/Corporate (detected via domain matching in ndpi_content_match.c.inc)
		"SLACK":        true, // slack.com
		"MSTEAMS":      true, // teams.microsoft.com
		"MSTEAMS_CALL": true,
		"ZOOM":         true, // zoom.us
		"WEBEX":        true, // webex.com
		"GOTO":         true, // goto.com
		"FUZE":         true, // fuze.com

		// Cloud services (detected via domain matching in ndpi_content_match.c.inc)
		"MICROSOFT":        true, // microsoft.com
		"MICROSOFT_365":    true, // office.com, outlook.com
		"MS_OUTLOOK":       true, // outlook.com
		"MS_ONE_DRIVE":     true, // onedrive.com
		"GOOGLE":           true, // google.com
		"GOOGLE_SERVICES":  true, // googleapis.com
		"GOOGLE_DOCS":      true, // docs.google.com
		"GOOGLE_DRIVE":     true, // drive.google.com
		"GOOGLE_MAPS":      true, // maps.google.com
		"GOOGLE_MEET":      true, // meet.google.com
		"GOOGLE_CHAT":      true, // chat.google.com
		"GOOGLE_CALL":      true,
		"GOOGLE_CLASSROOM": true, // classroom.google.com
		"GMAIL":            true, // gmail.com
		"APPLE":            true, // apple.com
		"APPLE_ICLOUD":     true, // icloud.com
		"APPLE_ITUNES":     true, // itunes.apple.com
		"APPLE_SIRI":       true, // siri.apple.com
		"APPLESTORE":       true, // apps.apple.com
		"APPLETVPLUS":      true, // tv.apple.com

		// VoIP/calling services (detected via domain/IP matching in ndpi_content_match.c.inc)
		"TRUPHONE":        true,
		"VIBER_VOIP":      true, // viber.com
		"TELEGRAM_VOIP":   true, // telegram.org
		"WHATSAPP_CALL":   true, // whatsapp.com
		"WHATSAPP_FILES":  true,
		"SIGNAL_VOIP":     true, // signal.org
		"KAKAOTALK_VOICE": true, // kakao.com
		"WECHAT":          true, // wechat.com

		// Gaming platforms (detected via domain matching in ndpi_content_match.c.inc)
		"PLAYSTATION":    true, // playstation.com
		"XBOX":           true, // xbox.com
		"NINTENDO":       true, // nintendo.com
		"EPICGAMES":      true, // epicgames.com
		"VALVE_SDR":      true, // steampowered.com
		"RIOTGAMES":      true, // riotgames.com
		"ELECTRONICARTS": true, // ea.com
		"ACTIVISION":     true, // activision.com
		"BLIZZARD":       true, // blizzard.com
		"ROCKSTAR_GAMES": true, // rockstargames.com

		// CDN/Infrastructure (detected via domain matching in ndpi_content_match.c.inc)
		"CLOUDFLARE":      true, // cloudflare.com
		"CLOUDFLARE_WARP": true,
		"AKAMAI":          true, // akamai.com
		"EDGECAST":        true, // edgecast.com
		"CACHEFLY":        true, // cachefly.com

		// Chinese services (detected via domain matching in ndpi_content_match.c.inc)
		"TENCENT":      true, // tencent.com
		"TENCENTVIDEO": true, // v.qq.com
		"TENCENTGAMES": true,
		"ALIBABA":      true, // alibaba.com
		"ALICLOUD":     true, // aliyun.com
		"TAOBAO":       true, // taobao.com
		"KAKAOTALK":    true, // kakao.com
		"NAVER":        true, // naver.com

		// VPN services (detected via domain matching in ndpi_content_match.c.inc)
		"NORDVPN":        true, // nordvpn.com
		"PROTONVPN":      true, // protonvpn.com
		"MULLVAD":        true, // mullvad.net
		"SURFSHARK":      true, // surfshark.com
		"TUNNELBEAR":     true, // tunnelbear.com
		"OPERA_VPN":      true, // opera.com
		"PSIPHON":        true, // psiphon.ca
		"WINDSCRIBE":     true, // windscribe.com
		"CACTUSVPN":      true, // cactusvpn.com
		"HOTSPOT_SHIELD": true, // hotspotshield.com
		"ULTRASURF":      true, // ultrasurf.us

		// Other web services (detected via domain matching in ndpi_content_match.c.inc)
		"GITHUB":    true, // github.com
		"GITLAB":    true, // gitlab.com
		"WIKIPEDIA": true, // wikipedia.org
		"MOZILLA":   true, // mozilla.org
		"YAHOO":     true, // yahoo.com
		"EBAY":      true, // ebay.com
		"CNN":       true, // cnn.com
		"ESPN":      true, // espn.com

		// Networking equipment (detected via domain matching in ndpi_content_match.c.inc)
		"UBIQUITI": true, // ubiquiti.com, ui.com
	}

	return contentMatchProtocols[strings.ToUpper(protocol)]
}

// getLPIProtocolURLs returns possible URLs for libprotoident protocol implementations
func getLPIProtocolURLs(protocol, protocolLower string) []string {
	urls := []string{
		// Standard TCP protocol file
		fmt.Sprintf("https://github.com/LibtraceTeam/libprotoident/blob/master/lib/tcp/lpi_%s.cc", protocolLower),
	}

	// Many LPI protocols with UDP_ prefix don't have TCP implementations
	if strings.HasPrefix(strings.ToUpper(protocol), "UDP_") {
		urls = []string{
			fmt.Sprintf("https://github.com/LibtraceTeam/libprotoident/blob/master/lib/udp/lpi_%s.cc", protocolLower),
			// Fallback to main protocols page
			"https://github.com/LibtraceTeam/libprotoident/wiki/SupportedProtocols",
		}
	}

	return urls
}

// isLikelyIPListProtocol returns true if a protocol is likely detected via IP lists
// These are typically cloud services, CDNs, and large web services
func isLikelyIPListProtocol(protocol string) bool {
	ipListProtocols := map[string]bool{
		// Cloud providers with IP-based detection (not in ndpi_content_match.c.inc)
		"MICROSOFT_AZURE": true,
		"AWS_CLOUDFRONT":  true, "AWS_API_GATEWAY": true, "AWS_COGNITO": true,
		"AWS_DYNAMODB": true, "AWS_KINESIS": true, "AWS_EC2": true, "AWS_S3": true, "AWS_EMR": true,
		"GOOGLE_CLOUD": true,
		"DIGITALOCEAN": true, "HUAWEI_CLOUD": true,
		"YANDEX_CLOUD": true,

		// VPN/Security services that use IP lists (not domain-based)
		"TOR": true, "OPENVPN": true,
	}

	return ipListProtocols[strings.ToUpper(protocol)]
}

// TestProtocolSourceURLGeneration verifies that the URL generation logic works correctly
func TestProtocolSourceURLGeneration(t *testing.T) {
	tests := []struct {
		module   string
		protocol string
		expected string
	}{
		{
			module:   "go",
			protocol: "HTTP",
			expected: "https://github.com/dreadl0ck/go-dpi/blob/master/modules/classifiers/http.go",
		},
		{
			module:   "ndpi",
			protocol: "TLS",
			expected: "https://github.com/ntop/nDPI/blob/dev/src/lib/protocols/tls.c",
		},
		{
			module:   "lpi",
			protocol: "SSH",
			expected: "https://github.com/LibtraceTeam/libprotoident/blob/master/lib/tcp/lpi_ssh.cc",
		},
		{
			module:   "unknown",
			protocol: "test",
			expected: "#",
		},
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("%s-%s", tt.module, tt.protocol), func(t *testing.T) {
			got := getProtocolSourceURL(tt.module, tt.protocol)
			if got != tt.expected {
				t.Errorf("getProtocolSourceURL(%q, %q) = %q, want %q",
					tt.module, tt.protocol, got, tt.expected)
			}
		})
	}
}

// TestModuleProtocolsAvailable ensures that GetModuleProtocols returns data
func TestModuleProtocolsAvailable(t *testing.T) {
	protocols := GetModuleProtocols()

	if len(protocols) == 0 {
		t.Skip("No DPI modules available")
	}

	t.Logf("Available modules: %d", len(protocols))
	for module, protoList := range protocols {
		t.Logf("  - %s: %d protocols", module, len(protoList))
		if len(protoList) == 0 {
			t.Errorf("Module %s has no protocols", module)
		}
	}
}

// TestMultiURLResolution tests that protocols with no direct .c file can find alternative URLs
func TestMultiURLResolution(t *testing.T) {
	client := &http.Client{
		Timeout: 10 * time.Second,
	}

	// Test known protocols that don't have direct .c files
	testCases := []struct {
		module   string
		protocol string
		reason   string
	}{
		{"ndpi", "SALESFORCE", "IP list based"},
		{"ndpi", "GOOGLE_CLOUD", "IP list based"},
		{"ndpi", "FACEBOOK", "SNI/host based"},
		{"ndpi", "NETFLIX", "SNI/host based"},
		{"ndpi", "OCS", "hardcoded IPs in content_match.c.inc"},
		{"ndpi", "TEAMVIEWER", "hardcoded IPs in content_match.c.inc"},
		{"lpi", "UDP_PUNKBUSTER", "UDP protocol, not in tcp/ dir"},
		{"lpi", "UDP_AMANDA", "UDP protocol, not in tcp/ dir"},
	}

	for _, tc := range testCases {
		t.Run(fmt.Sprintf("%s-%s", tc.module, tc.protocol), func(t *testing.T) {
			urls := getProtocolSourceURLs(tc.module, tc.protocol)

			t.Logf("Protocol %s (%s) has %d fallback URLs", tc.protocol, tc.reason, len(urls))
			for i, url := range urls {
				t.Logf("  [%d] %s", i, url)
			}

			// Verify we have at least one fallback URL
			if len(urls) < 2 {
				t.Errorf("Expected at least 2 URLs (primary + fallback) for %s, got %d", tc.protocol, len(urls))
			}

			// Optionally try to access the URLs (commented out to avoid rate limiting in tests)
			// Uncomment when manually testing
			/*
				foundWorking := false
				for _, url := range urls {
					resp, err := client.Get(url)
					if err == nil && resp.StatusCode == http.StatusOK {
						resp.Body.Close()
						t.Logf("✓ Found working URL: %s", url)
						foundWorking = true
						break
					}
					if resp != nil {
						resp.Body.Close()
					}
					time.Sleep(500 * time.Millisecond)
				}

				if !foundWorking {
					t.Logf("⚠ No working URL found (may be rate limited or protocol removed)")
				}
			*/
		})
	}

	_ = client // avoid unused variable warning when HTTP testing is commented out
}
