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
		"NortelDiscovery", "PPP", "PPPoE", "SNAP", "STP", "USB", "USBRequestBlockSetup",
	}

	networkLayerProtocols = []string{
		"BFD", "GRE", "ICMPv4", "ICMPv6", "ICMPv6Echo",
		"ICMPv6NeighborAdvertisement", "ICMPv6NeighborSolicitation",
		"ICMPv6RouterAdvertisement", "ICMPv6RouterSolicitation", "ICMPv6Option",
		"IGMP", "IGMPv3GroupRecord", "IPSecAH", "IPSecESP",
		"IPv4", "IPv4Option", "IPv6", "IPv6Fragment", "IPv6HopByHop",
		"IPv6HopByHopOption", "IPv6HopByHopOptionAlignment",
		"MLDv2MulticastListenerQuery", "MLDv2MulticastListenerReport",
		"MPLS", "OSPFv2", "OSPFv3", "VRRPv2",
	}

	transportLayerProtocols = []string{
		"QUIC", "QUICClientHello", "SCTP", "TCP", "TCPOption", "TLSClientHello", "TLSServerHello", "UDP",
	}

	applicationLayerProtocols = []string{
		"BACnetIP", "BGP", "CIP", "DHCPv4", "DHCPv6", "DHCPOption", "DHCPv6Option",
		"Diameter", "DNP3", "DNS", "DNSQuestion", "DNSResourceRecord", "DNSSOA", "DNSSRV", "DNSMX",
		"ENIP", "FTP", "Geneve", "GTP",
		"HTTP", "IEC62351", "IMAP", "IRC", "LCM", "Modbus", "MQTTSN", "NTP", "OPCUA", "POP3", "PROFINET",
		"RADIUS", "RDP", "RMCP", "S7Comm", "SIP", "SMB", "SMTP", "SOCKS", "SSH", "Syslog",
		"TLSCertificate", "VXLAN",
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
	for i := range files {
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
