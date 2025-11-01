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

package webui

import "strings"

// Protocol categories by layer
var (
	linkLayerProtocols = []string{
		"ARP", "CiscoDiscovery", "Dot11", "Dot1Q", "Ethernet",
		"EthernetCTP", "EthernetCTPReply", "FDDI", "LLC",
		"LinkLayerDiscovery", "NortelDiscovery", "SNAP", "USB",
	}

	networkLayerProtocols = []string{
		"GRE", "ICMPv4", "ICMPv6", "IGMP", "IPSecAH", "IPSecESP",
		"IPv4", "IPv6", "IPv6Fragment", "IPv6HopByHop", "MPLS",
	}

	transportLayerProtocols = []string{
		"SCTP", "TCP", "UDP",
	}

	applicationLayerProtocols = []string{
		"Connection", "DHCPv4", "DHCPv6", "DNS", "DeviceProfile",
		"Geneve", "IPProfile", "NTP", "SIP", "TLSClientHello",
		"TLSServerHello", "VXLAN",
	}

	streamDecoders = []string{
		"HTTP", "POP3", "SMTP", "SSH",
	}

	abstractDecoders = []string{
		"Alert", "Credentials", "Exploit", "File", "Mail",
		"Service", "Software", "Vulnerability",
	}
)

// GetLayerType returns the layer type for a given audit record type
func GetLayerType(auditType string) LayerType {
	for _, p := range linkLayerProtocols {
		if strings.EqualFold(auditType, p) {
			return LayerLink
		}
	}

	for _, p := range networkLayerProtocols {
		if strings.EqualFold(auditType, p) {
			return LayerNetwork
		}
	}

	for _, p := range transportLayerProtocols {
		if strings.EqualFold(auditType, p) {
			return LayerTransport
		}
	}

	for _, p := range applicationLayerProtocols {
		if strings.EqualFold(auditType, p) {
			return LayerApplication
		}
	}

	for _, p := range streamDecoders {
		if strings.EqualFold(auditType, p) {
			return LayerStream
		}
	}

	for _, p := range abstractDecoders {
		if strings.EqualFold(auditType, p) {
			return LayerAbstract
		}
	}

	return LayerUnknown
}

// SortAuditFiles sorts audit files hierarchically by layer type
// Link → Network → Transport → Application → Stream → Abstract → Unknown
func SortAuditFiles(files []AuditFileInfo) {
	// Sort using stable sort to maintain alphabetical order within layers
	for i := 0; i < len(files); i++ {
		for j := i + 1; j < len(files); j++ {
			layerI := GetLayerType(files[i].Type)
			layerJ := GetLayerType(files[j].Type)

			// Compare by layer first
			if layerI > layerJ {
				files[i], files[j] = files[j], files[i]
			} else if layerI == layerJ {
				// Within same layer, sort alphabetically
				if files[i].Type > files[j].Type {
					files[i], files[j] = files[j], files[i]
				}
			}
		}
	}
}

// GetLayerName returns a human-readable name for the layer type
func GetLayerName(layer LayerType) string {
	switch layer {
	case LayerLink:
		return "Link Layer"
	case LayerNetwork:
		return "Network Layer"
	case LayerTransport:
		return "Transport Layer"
	case LayerApplication:
		return "Application Layer"
	case LayerStream:
		return "Stream Decoders"
	case LayerAbstract:
		return "Abstract Decoders"
	default:
		return "Other"
	}
}
