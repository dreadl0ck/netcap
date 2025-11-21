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

package filter

import (
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Network Helper Functions

// InSubnet checks if an IP address is within a given CIDR subnet.
func InSubnet(ip, cidr string) bool {
	_, subnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return false
	}

	ipAddr := net.ParseIP(ip)
	if ipAddr == nil {
		return false
	}

	return subnet.Contains(ipAddr)
}

// IsPrivateIP checks if an IP address is in a private range.
func IsPrivateIP(ip string) bool {
	ipAddr := net.ParseIP(ip)
	if ipAddr == nil {
		return false
	}

	// Check for private and special-use ranges (RFC 1918, 6598, 5737, etc.)
	private := []string{
		// IPv4 Private and Special-Use Ranges
		"0.0.0.0/8",          // RFC 1122 - "This" Network
		"10.0.0.0/8",         // RFC 1918 - Private-Use
		"100.64.0.0/10",      // RFC 6598 - Shared Address Space (CGN)
		"127.0.0.0/8",        // RFC 1122 - Loopback
		"169.254.0.0/16",     // RFC 3927 - Link-Local
		"172.16.0.0/12",      // RFC 1918 - Private-Use
		"192.0.0.0/24",       // RFC 6890 - IETF Protocol Assignments
		"192.0.2.0/24",       // RFC 5737 - TEST-NET-1
		"192.168.0.0/16",     // RFC 1918 - Private-Use
		"198.18.0.0/15",      // RFC 2544 - Benchmarking
		"198.51.100.0/24",    // RFC 5737 - TEST-NET-2
		"203.0.113.0/24",     // RFC 5737 - TEST-NET-3
		"224.0.0.0/4",        // RFC 5771 - Multicast
		"240.0.0.0/4",        // RFC 1112 - Reserved
		"255.255.255.255/32", // RFC 919 - Limited Broadcast
		// IPv6 Private and Special-Use Ranges
		"::1/128",       // IPv6 loopback
		"::/128",        // IPv6 unspecified
		"fe80::/10",     // IPv6 link-local
		"fc00::/7",      // IPv6 unique local addr
		"ff00::/8",      // IPv6 multicast
		"2001:db8::/32", // RFC 3849 - Documentation
	}

	for _, cidr := range private {
		if InSubnet(ip, cidr) {
			return true
		}
	}

	return false
}

// IsPublicIP checks if an IP address is a public (non-private) address.
func IsPublicIP(ip string) bool {
	ipAddr := net.ParseIP(ip)
	if ipAddr == nil {
		return false
	}

	return !IsPrivateIP(ip)
}

// ParsePort converts a port string to an integer.
// Returns 0 if the string cannot be parsed.
func ParsePort(port string) int {
	p, err := strconv.Atoi(port)
	if err != nil {
		return 0
	}
	if p < 0 || p > 65535 {
		return 0
	}
	return p
}

// PortInRange checks if a port is within a given range (inclusive).
func PortInRange(port, start, end int) bool {
	return port >= start && port <= end
}

// Time Helper Functions

// TimeInRange checks if a timestamp (nanoseconds) is within a given range.
func TimeInRange(ts, start, end int64) bool {
	return ts >= start && ts <= end
}

// DurationSince returns the duration in nanoseconds since a given timestamp.
func DurationSince(ts int64) int64 {
	return time.Now().UnixNano() - ts
}

// FormatTime formats a timestamp (nanoseconds) according to the provided format string.
// Uses Go's time format layout (e.g., "2006-01-02 15:04:05").
func FormatTime(ts int64, format string) string {
	t := time.Unix(0, ts)
	return t.Format(format)
}

// String Helper Functions

// ContainsAny checks if a string contains any of the provided substrings.
func ContainsAny(str string, substrs []string) bool {
	for _, substr := range substrs {
		if strings.Contains(str, substr) {
			return true
		}
	}
	return false
}

// MatchesPattern checks if a string matches a regular expression pattern.
func MatchesPattern(str, pattern string) bool {
	matched, err := regexp.MatchString(pattern, str)
	if err != nil {
		return false
	}
	return matched
}

