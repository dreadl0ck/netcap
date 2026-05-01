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

package filter

import (
	"net"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
)

// privateCIDRs contains pre-parsed private/special-use CIDR networks.
// Parsed once at init to avoid re-parsing on every IsPrivateIP call.
var privateCIDRs []*net.IPNet

func init() {
	cidrs := []string{
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
	privateCIDRs = make([]*net.IPNet, 0, len(cidrs))
	for _, cidr := range cidrs {
		_, network, _ := net.ParseCIDR(cidr)
		privateCIDRs = append(privateCIDRs, network)
	}
}

// regexCache caches compiled regexes to avoid recompilation on every MatchesPattern call.
var regexCache sync.Map

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

	for _, network := range privateCIDRs {
		if network.Contains(ipAddr) {
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
// Compiled regexes are cached to avoid recompilation on repeated calls.
//
// When the binary is built with `-tags hyperscan` and the pattern is
// one Hyperscan accepts, the boolean answer is taken directly from a
// per-pattern Hyperscan database (single-pattern block-mode DBs return
// the same true/false predicate as RE2 for the HS-supported subset of
// PCRE). Patterns Hyperscan refuses to compile transparently fall
// through to the existing RE2 cache path so behaviour is preserved.
func MatchesPattern(str, pattern string) bool {
	// Optional Hyperscan fast path. In stub builds this always reports
	// "no decision" so the function falls through to RE2.
	if matched, decided := hsMatchesPatternPrecheck(str, pattern); decided {
		return matched
	}

	var re *regexp.Regexp
	if cached, ok := regexCache.Load(pattern); ok {
		re = cached.(*regexp.Regexp)
	} else {
		compiled, err := regexp.Compile(pattern)
		if err != nil {
			return false
		}
		regexCache.Store(pattern, compiled)
		re = compiled
	}
	return re.MatchString(str)
}

// Contains checks if a slice contains a specific value.
// Supports []string, []int, and []int32 (common in protobuf).
func Contains(slice any, value any) bool {
	switch s := slice.(type) {
	case []string:
		target, ok := value.(string)
		if !ok {
			return false
		}
		if slices.Contains(s, target) {
			return true
		}
	case []int:
		target, ok := value.(int)
		if !ok {
			return false
		}
		if slices.Contains(s, target) {
			return true
		}
	case []int32:
		target, ok := value.(int32)
		if !ok {
			return false
		}
		if slices.Contains(s, target) {
			return true
		}
	}
	return false
}

// HasKey checks if a map contains a specific key.
// Supports map[string]string and map[string]interface{}.
func HasKey(m any, key string) bool {
	switch mp := m.(type) {
	case map[string]string:
		_, exists := mp[key]
		return exists
	case map[string]any:
		_, exists := mp[key]
		return exists
	}
	return false
}
