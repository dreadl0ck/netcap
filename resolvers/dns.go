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
	"context"
	"log"
	"net"
	"sync"
	"time"

	"go.uber.org/zap"
)

const (
	// maxDNSCacheSize is the maximum number of entries in the DNS cache.
	// When exceeded, the cache is cleared to prevent unbounded memory growth.
	maxDNSCacheSize = 100000
)

var (
	timeout           = 2 * time.Second // reduced from 10s to avoid blocking workers
	dnsNamesDB        = make(map[string][]string)
	dnsNamesMu        sync.Mutex
	privateIPBlocks   []*net.IPNet
	disableReverseDNS = true
)

// setup private address space
// source: https://stackoverflow.com/questions/41240761/go-check-if-ip-address-is-in-private-network-space
func init() {
	for _, cidr := range []string{
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
	} {
		_, block, err := net.ParseCIDR(cidr)
		if err != nil {
			log.Fatalf("failed to parse cidr notation %q: %v\n", cidr, err)
		}
		privateIPBlocks = append(privateIPBlocks, block)
	}
}

// IsPrivateIP can be used whether an address belongs to private address space.
func IsPrivateIP(ip net.IP) bool {
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return true
	}

	for _, block := range privateIPBlocks {
		if block.Contains(ip) {
			return true
		}
	}
	return false
}

// LookupDNSNames retrieves the DNS names associated with an IP address.
func LookupDNSNames(ip string) []string {
	startTime := time.Now()
	defer func() {
		if perfTracker != nil {
			perfTracker.RecordResolver("DNS", time.Since(startTime), false)
		}
	}()

	if disableReverseDNS {
		return []string{}
	}

	// check if ip is valid
	i := net.ParseIP(ip)
	if i == nil {
		return nil
	}

	// check if ip is private
	if IsPrivateIP(i) {
		return nil
	}

	// check if ip has already been resolved
	dnsNamesMu.Lock()
	if res, ok := dnsNamesDB[ip]; ok {
		dnsNamesMu.Unlock()

		// Record cache hit
		if perfTracker != nil {
			perfTracker.RecordResolver("DNS", time.Since(startTime), true)
		}

		return res
	}
	dnsNamesMu.Unlock()

	// resolve
	ctx, cancelCtx := context.WithTimeout(context.TODO(), timeout)
	defer cancelCtx()

	var r net.Resolver

	names, err := r.LookupAddr(ctx, ip)
	if err != nil {
		resolverLog.Error("net.LookupAddr failed:", zap.Error(err))
	} // failed values are added to the DB as well so we don't try to resolve them again

	// add to DB
	dnsNamesMu.Lock()
	// evict cache if it grows too large to prevent unbounded memory usage
	if len(dnsNamesDB) >= maxDNSCacheSize {
		dnsNamesDB = make(map[string][]string, maxDNSCacheSize/2)
	}
	dnsNamesDB[ip] = names
	dnsNamesMu.Unlock()

	return names
}
