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

package bgp

import (
	"encoding/binary"
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/dreadl0ck/netcap/types"
)

// Additional BGP Path Attribute Type Codes for security analysis
const (
	BGPAttrMPReachNLRI    = 14 // MP_REACH_NLRI (RFC 4760)
	BGPAttrMPUnreachNLRI  = 15 // MP_UNREACH_NLRI (RFC 4760)
	BGPAttrExtCommunities = 16 // Extended Communities (RFC 4360)
	BGPAttrAS4Path        = 17 // AS4_PATH (RFC 6793)
	BGPAttrAS4Aggregator  = 18 // AS4_AGGREGATOR (RFC 6793)
	BGPAttrLargeCommunity = 32 // Large Communities (RFC 8092)
)

// AS Path Segment Types
const (
	ASSegTypeSet         = 1 // AS_SET (unordered set of ASes)
	ASSegTypeSequence    = 2 // AS_SEQUENCE (ordered list)
	ASSegTypeConfedSeq   = 3 // AS_CONFED_SEQUENCE
	ASSegTypeConfedSet   = 4 // AS_CONFED_SET
)

// Well-known community values
const (
	CommNoExport         = 0xFFFFFF01 // NO_EXPORT (RFC 1997)
	CommNoAdvertise      = 0xFFFFFF02 // NO_ADVERTISE (RFC 1997)
	CommNoExportSubConfed = 0xFFFFFF03 // NO_EXPORT_SUBCONFED (RFC 1997)
	CommNoPeer           = 0xFFFFFF04 // NOPEER (RFC 3765)
	CommBlackhole        = 0xFFFF029A // BLACKHOLE (RFC 7999) - 65535:666
)

// analyzeBGPSecurity performs comprehensive security analysis on a BGP message
func analyzeBGPSecurity(msg *types.BGP) {
	var riskFactors []string
	riskScore := 0

	// AS Path Security Analysis
	if len(msg.ASPath) > 0 {
		analyzeASPath(msg, &riskFactors, &riskScore)
	}

	// Prefix Security Analysis
	if len(msg.NLRI) > 0 || len(msg.WithdrawnRoutes) > 0 {
		analyzePrefixes(msg, &riskFactors, &riskScore)
	}

	// Community Analysis
	analyzeCommunities(msg, &riskFactors, &riskScore)

	// Hold Time Analysis - RFC 4271 requires minimum of 3 seconds if not 0
	// Values between 1-2 are technically invalid
	if msg.HoldTime > 0 && msg.HoldTime < 3 {
		riskFactors = append(riskFactors, fmt.Sprintf("invalid_hold_time_%d", msg.HoldTime))
		riskScore += 10
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

// analyzeASPath performs security analysis on the AS path
func analyzeASPath(msg *types.BGP, riskFactors *[]string, riskScore *int) {
	msg.ASPathLength = int32(len(msg.ASPath))

	// Get origin AS (first AS in path from origin's perspective, last in our list)
	if len(msg.ASPath) > 0 {
		msg.OriginAS = msg.ASPath[len(msg.ASPath)-1]
	}

	// Check for AS path loops - always a problem
	seen := make(map[uint32]bool)
	for _, as := range msg.ASPath {
		if seen[as] {
			msg.HasASPathLoop = true
			*riskFactors = append(*riskFactors, fmt.Sprintf("as_path_loop_as_%d", as))
			*riskScore += 40
			break
		}
		seen[as] = true
	}

	// Check for private AS numbers - should be stripped at border
	for _, as := range msg.ASPath {
		if isPrivateAS(as) {
			msg.HasPrivateAS = true
			*riskFactors = append(*riskFactors, fmt.Sprintf("private_as_%d", as))
			*riskScore += 20
			break
		}
	}

	// Check for bogon AS numbers - definitely suspicious
	for _, as := range msg.ASPath {
		if isBogonAS(as) {
			msg.HasBogonAS = true
			*riskFactors = append(*riskFactors, fmt.Sprintf("bogon_as_%d", as))
			*riskScore += 35
			break
		}
	}

	// Check for unusually long AS paths (potential path prepending attack or manipulation)
	// Paths > 25 hops are extremely rare in practice
	if msg.ASPathLength > 25 {
		*riskFactors = append(*riskFactors, fmt.Sprintf("excessive_path_length_%d", msg.ASPathLength))
		*riskScore += 15
	}
}

// analyzePrefixes performs security analysis on announced/withdrawn prefixes
func analyzePrefixes(msg *types.BGP, riskFactors *[]string, riskScore *int) {
	msg.PrefixCount = int32(len(msg.NLRI))
	msg.WithdrawnCount = int32(len(msg.WithdrawnRoutes))

	minLen := 32
	maxLen := 0

	// Analyze announced prefixes
	for _, prefix := range msg.NLRI {
		ip, prefixLen := parsePrefix(prefix)
		if ip == nil {
			continue
		}

		if prefixLen < minLen {
			minLen = prefixLen
		}
		if prefixLen > maxLen {
			maxLen = prefixLen
		}

		// Check for default route - significant event
		if isDefaultRoute(prefix) {
			msg.HasDefaultRoute = true
			*riskFactors = append(*riskFactors, "default_route_announced")
			*riskScore += 25
		}

		// Check for bogon prefix - definitely malicious
		if isBogonPrefix(ip) {
			msg.HasBogonPrefix = true
			msg.BogonPrefixes = append(msg.BogonPrefixes, prefix)
			*riskFactors = append(*riskFactors, fmt.Sprintf("bogon_prefix_%s", prefix))
			*riskScore += 40
		}
	}

	if minLen < 32 {
		msg.SmallestPrefixLen = int32(minLen)
	}
	if maxLen > 0 {
		msg.LargestPrefixLen = int32(maxLen)
	}

	// Very large number of prefixes in single update (potential DoS or route leak)
	if msg.PrefixCount > 500 {
		*riskFactors = append(*riskFactors, fmt.Sprintf("bulk_announcement_%d_prefixes", msg.PrefixCount))
		*riskScore += 15
	}

	// Very large number of withdrawals (potential instability or attack)
	if msg.WithdrawnCount > 500 {
		*riskFactors = append(*riskFactors, fmt.Sprintf("bulk_withdrawal_%d_prefixes", msg.WithdrawnCount))
		*riskScore += 15
	}
}

// analyzeCommunities analyzes BGP communities for security relevance
func analyzeCommunities(msg *types.BGP, riskFactors *[]string, riskScore *int) {
	for _, comm := range msg.Communities {
		// Parse community string "high:low"
		parts := strings.Split(comm, ":")
		if len(parts) != 2 {
			continue
		}
		high, _ := strconv.ParseUint(parts[0], 10, 16)
		low, _ := strconv.ParseUint(parts[1], 10, 16)
		commVal := uint32(high)<<16 | uint32(low)

		switch commVal {
		case CommNoExport:
			msg.HasNoExportComm = true
		case CommNoAdvertise:
			msg.HasNoAdvertiseComm = true
		case CommNoPeer:
			msg.HasNoPeerComm = true
		case CommBlackhole:
			msg.HasBlackholeComm = true
			*riskFactors = append(*riskFactors, "blackhole_community_present")
			*riskScore += 5 // Informational, not necessarily bad
		}

		// Check for blackhole community patterns (various forms like ASN:666)
		if low == 666 {
			msg.HasBlackholeComm = true
		}
	}
}

// parsePrefix parses a prefix string like "192.168.1.0/24" into IP and prefix length
func parsePrefix(prefix string) (net.IP, int) {
	_, ipNet, err := net.ParseCIDR(prefix)
	if err != nil {
		return nil, 0
	}
	ones, _ := ipNet.Mask.Size()
	return ipNet.IP, ones
}

// isDefaultRoute checks if prefix is a default route
func isDefaultRoute(prefix string) bool {
	return prefix == "0.0.0.0/0" || prefix == "::/0"
}

// isPrivateAS checks if an AS number is in the private range
func isPrivateAS(as uint32) bool {
	// RFC 6996: Private AS ranges
	// 16-bit: 64512 - 65534
	// 32-bit: 4200000000 - 4294967294
	return (as >= 64512 && as <= 65534) ||
		(as >= 4200000000 && as <= 4294967294)
}

// isBogonAS checks if an AS number is reserved/bogon
func isBogonAS(as uint32) bool {
	// AS 0 is reserved
	if as == 0 {
		return true
	}
	// AS 23456 is AS_TRANS (RFC 6793)
	if as == 23456 {
		return true
	}
	// Documentation ASes (RFC 5398): 64496-64511, 65536-65551
	if (as >= 64496 && as <= 64511) || (as >= 65536 && as <= 65551) {
		return true
	}
	// Last 16-bit AS: 65535 is reserved
	if as == 65535 {
		return true
	}
	// Last 32-bit AS: 4294967295 is reserved
	if as == 4294967295 {
		return true
	}
	return false
}

// isBogonPrefix checks if an IP is a bogon/martian address
func isBogonPrefix(ip net.IP) bool {
	ip4 := ip.To4()
	if ip4 != nil {
		// IPv4 bogon ranges
		bogonRanges := []struct {
			network *net.IPNet
		}{
			{mustParseCIDR("0.0.0.0/8")},         // "This" Network
			{mustParseCIDR("10.0.0.0/8")},        // Private-Use (RFC 1918)
			{mustParseCIDR("100.64.0.0/10")},     // Shared Address Space (RFC 6598)
			{mustParseCIDR("127.0.0.0/8")},       // Loopback
			{mustParseCIDR("169.254.0.0/16")},    // Link Local
			{mustParseCIDR("172.16.0.0/12")},     // Private-Use (RFC 1918)
			{mustParseCIDR("192.0.0.0/24")},      // IETF Protocol Assignments
			{mustParseCIDR("192.0.2.0/24")},      // Documentation (TEST-NET-1)
			{mustParseCIDR("192.168.0.0/16")},    // Private-Use (RFC 1918)
			{mustParseCIDR("198.18.0.0/15")},     // Benchmarking
			{mustParseCIDR("198.51.100.0/24")},   // Documentation (TEST-NET-2)
			{mustParseCIDR("203.0.113.0/24")},    // Documentation (TEST-NET-3)
			{mustParseCIDR("224.0.0.0/4")},       // Multicast
			{mustParseCIDR("240.0.0.0/4")},       // Reserved for Future Use
		}

		for _, bogon := range bogonRanges {
			if bogon.network.Contains(ip4) {
				return true
			}
		}
	} else {
		// IPv6 bogon ranges
		ip6 := ip.To16()
		if ip6 != nil {
			bogonRangesV6 := []struct {
				network *net.IPNet
			}{
				{mustParseCIDR("::/128")},          // Unspecified
				{mustParseCIDR("::1/128")},         // Loopback
				{mustParseCIDR("::ffff:0:0/96")},   // IPv4-mapped
				{mustParseCIDR("64:ff9b::/96")},    // IPv4/IPv6 Translation
				{mustParseCIDR("100::/64")},        // Discard-Only
				{mustParseCIDR("2001::/32")},       // Teredo
				{mustParseCIDR("2001:2::/48")},     // Benchmarking
				{mustParseCIDR("2001:db8::/32")},   // Documentation
				{mustParseCIDR("2001:10::/28")},    // ORCHID
				{mustParseCIDR("2002::/16")},       // 6to4
				{mustParseCIDR("fc00::/7")},        // Unique Local
				{mustParseCIDR("fe80::/10")},       // Link-Local
				{mustParseCIDR("ff00::/8")},        // Multicast
			}

			for _, bogon := range bogonRangesV6 {
				if bogon.network.Contains(ip6) {
					return true
				}
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

// parseExtendedCommunities parses extended communities (RFC 4360)
func parseExtendedCommunities(data []byte) []string {
	var communities []string

	// Each extended community is 8 bytes
	for i := 0; i+8 <= len(data); i += 8 {
		typeHigh := data[i]
		typeLow := data[i+1]
		value := data[i+2 : i+8]

		var comm string
		switch typeHigh {
		case 0x00, 0x40: // Two-octet AS specific
			as := binary.BigEndian.Uint16(value[0:2])
			localAdmin := binary.BigEndian.Uint32(value[2:6])
			comm = fmt.Sprintf("RT:%d:%d", as, localAdmin)
		case 0x01, 0x41: // IPv4 address specific
			ip := net.IP(value[0:4])
			localAdmin := binary.BigEndian.Uint16(value[4:6])
			comm = fmt.Sprintf("RT:%s:%d", ip, localAdmin)
		case 0x02, 0x42: // Four-octet AS specific
			as := binary.BigEndian.Uint32(value[0:4])
			localAdmin := binary.BigEndian.Uint16(value[4:6])
			comm = fmt.Sprintf("RT:%d:%d", as, localAdmin)
		case 0x03: // Opaque
			comm = fmt.Sprintf("Opaque:%x", value)
		case 0x80: // Generic transitive experimental
			if typeLow == 0x06 { // Flowspec traffic rate
				comm = "Flowspec:traffic-rate"
			} else if typeLow == 0x07 { // Flowspec traffic action
				comm = "Flowspec:traffic-action"
			} else if typeLow == 0x08 { // Flowspec redirect
				comm = "Flowspec:redirect"
			} else if typeLow == 0x09 { // Flowspec traffic marking
				comm = "Flowspec:traffic-marking"
			} else {
				comm = fmt.Sprintf("Experimental:%02x:%02x:%x", typeHigh, typeLow, value)
			}
		default:
			comm = fmt.Sprintf("ExtComm:%02x:%02x:%x", typeHigh, typeLow, value)
		}
		communities = append(communities, comm)
	}

	return communities
}

// parseLargeCommunities parses large communities (RFC 8092)
func parseLargeCommunities(data []byte) []string {
	var communities []string

	// Each large community is 12 bytes (3 x 4-byte values)
	for i := 0; i+12 <= len(data); i += 12 {
		globalAdmin := binary.BigEndian.Uint32(data[i : i+4])
		localData1 := binary.BigEndian.Uint32(data[i+4 : i+8])
		localData2 := binary.BigEndian.Uint32(data[i+8 : i+12])
		communities = append(communities, fmt.Sprintf("%d:%d:%d", globalAdmin, localData1, localData2))
	}

	return communities
}

// parseAggregator parses the AGGREGATOR attribute
func parseAggregator(data []byte, is4ByteAS bool) (string, string) {
	if is4ByteAS && len(data) >= 8 {
		// 4-byte AS + 4-byte IP
		as := binary.BigEndian.Uint32(data[0:4])
		ip := net.IP(data[4:8])
		return fmt.Sprintf("%d", as), ip.String()
	} else if len(data) >= 6 {
		// 2-byte AS + 4-byte IP
		as := binary.BigEndian.Uint16(data[0:2])
		ip := net.IP(data[2:6])
		return fmt.Sprintf("%d", as), ip.String()
	}
	return "", ""
}

// isKnownCapability checks if a BGP capability code is known/standard
func isKnownCapability(code uint8) bool {
	// IANA-assigned capability codes
	knownCaps := map[uint8]bool{
		1:   true, // Multiprotocol Extensions
		2:   true, // Route Refresh
		3:   true, // Outbound Route Filtering
		4:   true, // Multiple routes to a destination
		5:   true, // Extended Next Hop Encoding
		6:   true, // BGP Extended Message
		64:  true, // Graceful Restart
		65:  true, // 4-octet AS Number
		67:  true, // Dynamic Capability
		68:  true, // Multisession BGP
		69:  true, // ADD-PATH
		70:  true, // Enhanced Route Refresh
		71:  true, // Long-Lived Graceful Restart
		72:  true, // Routing Policy Distribution
		73:  true, // FQDN Capability
		128: true, // Route Refresh (Old)
		130: true, // Outbound Route Filtering (Old)
	}
	return knownCaps[code]
}

// isWellKnownAttribute checks if an attribute is well-known
func isWellKnownAttribute(typeCode uint8) bool {
	// Well-known mandatory: ORIGIN, AS_PATH, NEXT_HOP
	// Well-known discretionary: LOCAL_PREF, ATOMIC_AGGREGATE
	wellKnown := map[uint8]bool{
		1: true, // ORIGIN
		2: true, // AS_PATH
		3: true, // NEXT_HOP
		4: true, // MULTI_EXIT_DISC
		5: true, // LOCAL_PREF
		6: true, // ATOMIC_AGGREGATE
		7: true, // AGGREGATOR
	}
	return wellKnown[typeCode]
}

// isMandatoryAttribute checks if an attribute is mandatory
func isMandatoryAttribute(typeCode uint8) bool {
	// Well-known mandatory: ORIGIN, AS_PATH, NEXT_HOP
	mandatory := map[uint8]bool{
		1: true, // ORIGIN
		2: true, // AS_PATH
		3: true, // NEXT_HOP
	}
	return mandatory[typeCode]
}

// getKnownAttributeNames returns the known attribute type code names
func getKnownAttributeTypes() map[uint8]bool {
	return map[uint8]bool{
		1:  true, // ORIGIN
		2:  true, // AS_PATH
		3:  true, // NEXT_HOP
		4:  true, // MULTI_EXIT_DISC
		5:  true, // LOCAL_PREF
		6:  true, // ATOMIC_AGGREGATE
		7:  true, // AGGREGATOR
		8:  true, // COMMUNITY
		9:  true, // ORIGINATOR_ID
		10: true, // CLUSTER_LIST
		14: true, // MP_REACH_NLRI
		15: true, // MP_UNREACH_NLRI
		16: true, // EXTENDED_COMMUNITIES
		17: true, // AS4_PATH
		18: true, // AS4_AGGREGATOR
		22: true, // PMSI_TUNNEL
		23: true, // Tunnel Encapsulation
		24: true, // Traffic Engineering
		25: true, // IPv6 Extended Communities
		26: true, // AIGP
		27: true, // PE Distinguisher Labels
		28: true, // BGP-LS
		29: true, // Large Community
		32: true, // LARGE_COMMUNITY (RFC 8092)
		33: true, // BGPsec_Path
		34: true, // Only to Customer
		35: true, // BGP Domain Path
		36: true, // SFP attribute
		37: true, // BFD Discriminator
		40: true, // BGP Prefix-SID
	}
}

