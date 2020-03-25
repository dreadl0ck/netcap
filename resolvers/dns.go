package resolvers

import (
	"context"
	"fmt"
	"sync"
	"net"
	"time"
)
 
var (
	timeout = 10 * time.Second
	dnsNamesDB = make(map[string][]string)
	dnsNamesMu sync.Mutex
)

// TODO: make configurable
var DisableReverseDNS = true

var privateIPBlocks []*net.IPNet

// setup private address space
// source: https://stackoverflow.com/questions/41240761/go-check-if-ip-address-is-in-private-network-space
func init() {
	for _, cidr := range []string{
		"127.0.0.0/8",    // IPv4 loopback
		"10.0.0.0/8",     // RFC1918
		"172.16.0.0/12",  // RFC1918
		"192.168.0.0/16", // RFC1918
		"169.254.0.0/16", // RFC3927 link-local
		"::1/128",        // IPv6 loopback
		"fe80::/10",      // IPv6 link-local
		"fc00::/7",       // IPv6 unique local addr
	} {
		_, block, err := net.ParseCIDR(cidr)
		if err != nil {
			panic(fmt.Errorf("parse error on %q: %v", cidr, err))
		}
		privateIPBlocks = append(privateIPBlocks, block)
	}
}

// isPrivateIP can be used whether an address belongs to private address space
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

// LookupDNSNames retrieves the DNS names associated with an IP addr
func LookupDNSNames(ip string) []string {

	if DisableReverseDNS {
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
		return res
	}
	dnsNamesMu.Unlock()

	// resolve
	ctx, cancelCtx := context.WithTimeout(context.TODO(), timeout)
	defer cancelCtx()

	var r net.Resolver
	names, err := r.LookupAddr(ctx, ip)
	if err != nil {
		//fmt.Println("net.LookupAddr failed:", err)
		// failed values are added to the DB as well so we don't try to resolve them again
	}

	// add to DB
	dnsNamesMu.Lock()
	dnsNamesDB[ip] = names
	dnsNamesMu.Unlock()

	return names
}
