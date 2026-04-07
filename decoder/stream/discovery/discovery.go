/*
 * NETCAP - Traffic Analysis Framework
 * Copyright (c) Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
 * License: GNU General Public License v3.0
 */

package discovery

import (
	"strconv"
	"time"

	"github.com/gopacket/gopacket"
)

// DiscoveryResult contains device information extracted from network discovery protocols.
type DiscoveryResult struct {
	Hostnames   []string // device hostnames (mDNS, NBNS)
	DeviceTypes []string // device types (UPnP: "Router/Gateway", WSD: "Printer")
	OS          string   // OS/firmware from UPnP server strings
	Roles       []string // network roles from NBNS (File Server, Master Browser, etc.)
	SourceIP    string   // IP of the device that was discovered
}

// discoveryExtractor is a function that extracts device information from network data.
type discoveryExtractor func(data []byte, ident string, ts time.Time) *DiscoveryResult

// portMapping maps well-known ports to their discovery extractors.
var portMapping = map[int]discoveryExtractor{
	5353: mdnsExtract,  // mDNS
	137:  nbnsExtract,  // NBNS
	1900: upnpExtract,  // UPnP/SSDP
	3702: wsdExtract,   // WSD
}

// RunDiscovery runs network discovery extractors on conversation data and returns results.
// It uses port-based dispatch to select the appropriate extractor.
func RunDiscovery(banner []byte, transport gopacket.Flow, ident string, firstPacket time.Time, srcIP string) []DiscoveryResult {
	if len(banner) == 0 {
		return nil
	}

	dstPort, _ := strconv.Atoi(transport.Dst().String())
	srcPort, _ := strconv.Atoi(transport.Src().String())

	var results []DiscoveryResult

	// Try destination port first
	if extractor, ok := portMapping[dstPort]; ok {
		if r := extractor(banner, ident, firstPacket); r != nil {
			if r.SourceIP == "" {
				r.SourceIP = srcIP
			}
			results = append(results, *r)
		}
	}

	// Also try source port (for responses)
	if extractor, ok := portMapping[srcPort]; ok {
		if _, alreadyTried := portMapping[dstPort]; !alreadyTried || srcPort != dstPort {
			if r := extractor(banner, ident, firstPacket); r != nil {
				if r.SourceIP == "" {
					r.SourceIP = srcIP
				}
				results = append(results, *r)
			}
		}
	}

	return results
}
