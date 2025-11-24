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
		"ARP", "CiscoDiscovery", "CiscoDiscoveryInfo", "Dot11", "Dot11QOS", 
		"Dot11HTControl", "Dot11HTControlVHT", "Dot11HTControlHT", 
		"Dot11HTControlMFB", "Dot11LinkAdapationControl", "Dot11ASEL",
		"Dot1Q", "EAP", "EAPOL", "EAPOLKey", "Ethernet",
		"EthernetCTP", "EthernetCTPReply", "FDDI", "LLC",
		"LinkLayerDiscovery", "LinkLayerDiscoveryInfo", "LinkLayerDiscoveryValue",
		"LLDPChassisID", "LLDPPortID", "LLDPSysCapabilities", "LLDPCapabilities",
		"LLDPMgmtAddress", "LLDPOrgSpecificTLV",
		"NortelDiscovery", "SNAP", "USB", "USBRequestBlockSetup",
	}

	networkLayerProtocols = []string{
		"BFD", "GRE", "ICMPv4", "ICMPv6", "ICMPv6Echo", 
		"ICMPv6NeighborAdvertisement", "ICMPv6NeighborSolicitation",
		"ICMPv6RouterAdvertisement", "ICMPv6RouterSolicitation", "ICMPv6Option",
		"IGMP", "IGMPv3GroupRecord", "IPSecAH", "IPSecESP",
		"IPv4", "IPv4Option", "IPv6", "IPv6Fragment", "IPv6HopByHop", 
		"IPv6HopByHopOption", "IPv6HopByHopOptionAlignment",
		"MPLS", "OSPFv2", "OSPFv3", "VRRPv2",
	}

	transportLayerProtocols = []string{
		"SCTP", "TCP", "TCPOption", "TLSClientHello", "TLSServerHello", "UDP",
	}

	applicationLayerProtocols = []string{
		"CIP", "DHCPv4", "DHCPv6", "DHCPOption", "DHCPv6Option",
		"Diameter", "DNS", "DNSQuestion", "DNSResourceRecord", "DNSSOA", "DNSSRV", "DNSMX",
		"ENIP", "Geneve", 
		"HTTP", "LCM", "Modbus", "NTP", "POP3", "SIP", "SMTP", "SSH", "VXLAN",
	}

	streamDecoders = []string{
		// Stream decoders are now shown under Application Layer
	}

	abstractDecoders = []string{
		"Alert", "Connection", "Credentials", "DeviceProfile", 
		"Exploit", "File", "IPProfile", "Mail", "Service", 
		"Software", "Vulnerability",
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
