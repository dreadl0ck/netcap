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

	// Check for private ranges
	private := []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"127.0.0.0/8",
		"169.254.0.0/16",
		"fc00::/7",
		"fe80::/10",
		"::1/128",
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

