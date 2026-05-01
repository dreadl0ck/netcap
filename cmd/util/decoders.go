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

package util

import (
	"fmt"
	"sort"
	"strings"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"

	"github.com/dreadl0ck/netcap/decoder/packet"
	"github.com/dreadl0ck/netcap/io"
	"github.com/dreadl0ck/netcap/types"
)

// DecoderInfo contains information about a decoder
type DecoderInfo struct {
	Name        string
	Type        types.Type
	Description string
	Layer       string
}

// printDecoders displays a tree view of all supported audit record types and their encapsulation levels
func printDecoders() {
	io.PrintLogo()
	fmt.Println()
	fmt.Println("Supported Audit Record Types by Encapsulation Level")
	fmt.Println("====================================================")
	fmt.Println()

	// Organize decoders by layer
	decodersByLayer := organizeDecodersByLayer()

	// Print hierarchical tree view
	printHierarchicalLayers(decodersByLayer)

	fmt.Println()
	fmt.Printf("Total Audit Record Types: %d\n", countTotalDecoders(decodersByLayer))
}

// organizeDecodersByLayer collects and organizes all decoders by their encapsulation level
func organizeDecodersByLayer() map[string][]DecoderInfo {
	decodersByLayer := make(map[string][]DecoderInfo)
	seenDecoders := make(map[string]bool)

	// Add gopacket decoders
	addGoPacketDecoders(decodersByLayer, seenDecoders)

	// Add packet decoders
	addPacketDecoders(decodersByLayer, seenDecoders)

	// Add stream decoders
	addStreamDecoders(decodersByLayer, seenDecoders)

	// Add abstract decoders
	addAbstractDecoders(decodersByLayer, seenDecoders)

	// Sort each layer's decoders
	for layer := range decodersByLayer {
		sort.Slice(decodersByLayer[layer], func(i, j int) bool {
			return decodersByLayer[layer][i].Name < decodersByLayer[layer][j].Name
		})
	}

	return decodersByLayer
}

// addGoPacketDecoders adds all gopacket layer decoders
func addGoPacketDecoders(decodersByLayer map[string][]DecoderInfo, seenDecoders map[string]bool) {
	// Map layer types to audit record types and layers
	layerMappings := map[gopacket.LayerType]struct {
		typeName string
		layer    string
	}{
		// Link Layer
		layers.LayerTypeEthernet:           {typeName: "Ethernet", layer: "Link Layer"},
		layers.LayerTypeARP:                {typeName: "ARP", layer: "Link Layer"},
		layers.LayerTypeDot1Q:              {typeName: "Dot1Q", layer: "Link Layer"},
		layers.LayerTypeDot11:              {typeName: "Dot11", layer: "Link Layer"},
		layers.LayerTypeLLC:                {typeName: "LLC", layer: "Link Layer"},
		layers.LayerTypeSNAP:               {typeName: "SNAP", layer: "Link Layer"},
		layers.LayerTypeLinkLayerDiscovery: {typeName: "LinkLayerDiscovery", layer: "Link Layer"},
		layers.LayerTypeEthernetCTP:        {typeName: "EthernetCTP", layer: "Link Layer"},
		layers.LayerTypeEthernetCTPReply:   {typeName: "EthernetCTPReply", layer: "Link Layer"},
		layers.LayerTypeFDDI:               {typeName: "FDDI", layer: "Link Layer"},
		layers.LayerTypeUSB:                {typeName: "USB", layer: "Link Layer"},
		layers.LayerTypeCiscoDiscovery:     {typeName: "CiscoDiscovery", layer: "Link Layer"},
		layers.LayerTypeNortelDiscovery:    {typeName: "NortelDiscovery", layer: "Link Layer"},
		layers.LayerTypePPPoE:              {typeName: "PPPoE", layer: "Link Layer"},
		layers.LayerTypePPP:                {typeName: "PPP", layer: "Link Layer"},
		layers.LayerTypeSTP:                {typeName: "STP", layer: "Link Layer"},

		// Network Layer
		layers.LayerTypeIPv4:                         {typeName: "IPv4", layer: "Network Layer"},
		layers.LayerTypeIPv6:                         {typeName: "IPv6", layer: "Network Layer"},
		layers.LayerTypeICMPv4:                       {typeName: "ICMPv4", layer: "Network Layer"},
		layers.LayerTypeICMPv6:                       {typeName: "ICMPv6", layer: "Network Layer"},
		layers.LayerTypeIPSecAH:                      {typeName: "IPSecAH", layer: "Network Layer"},
		layers.LayerTypeIPSecESP:                     {typeName: "IPSecESP", layer: "Network Layer"},
		layers.LayerTypeIPv6HopByHop:                 {typeName: "IPv6HopByHop", layer: "Network Layer"},
		layers.LayerTypeIPv6Fragment:                 {typeName: "IPv6Fragment", layer: "Network Layer"},
		layers.LayerTypeIGMP:                         {typeName: "IGMP", layer: "Network Layer"},
		layers.LayerTypeMPLS:                         {typeName: "MPLS", layer: "Network Layer"},
		layers.LayerTypeGRE:                          {typeName: "GRE", layer: "Network Layer"},
		layers.LayerTypeMLDv2MulticastListenerQuery:  {typeName: "MLDv2MulticastListenerQuery", layer: "Network Layer"},
		layers.LayerTypeMLDv2MulticastListenerReport: {typeName: "MLDv2MulticastListenerReport", layer: "Network Layer"},

		// Transport Layer
		layers.LayerTypeTCP:  {typeName: "TCP", layer: "Transport Layer"},
		layers.LayerTypeUDP:  {typeName: "UDP", layer: "Transport Layer"},
		layers.LayerTypeSCTP: {typeName: "SCTP", layer: "Transport Layer"},

		// Application Layer
		layers.LayerTypeDNS:    {typeName: "DNS", layer: "Application Layer"},
		layers.LayerTypeDHCPv4: {typeName: "DHCPv4", layer: "Application Layer"},
		layers.LayerTypeDHCPv6: {typeName: "DHCPv6", layer: "Application Layer"},
		layers.LayerTypeNTP:    {typeName: "NTP", layer: "Application Layer"},
		layers.LayerTypeSIP:    {typeName: "SIP", layer: "Application Layer"},
		layers.LayerTypeGeneve: {typeName: "Geneve", layer: "Application Layer"},
		layers.LayerTypeVXLAN:  {typeName: "VXLAN", layer: "Application Layer"},
		layers.LayerTypeRMCP:   {typeName: "RMCP", layer: "Application Layer"},
	}

	for _, mapping := range layerMappings {
		if !seenDecoders[mapping.typeName] {
			seenDecoders[mapping.typeName] = true
			decodersByLayer[mapping.layer] = append(decodersByLayer[mapping.layer], DecoderInfo{
				Name:        mapping.typeName,
				Type:        getTypeForName(mapping.typeName),
				Description: fmt.Sprintf("%s protocol decoder", mapping.typeName),
				Layer:       mapping.layer,
			})
		}
	}
}

// addPacketDecoders adds custom packet decoders
func addPacketDecoders(decodersByLayer map[string][]DecoderInfo, seenDecoders map[string]bool) {
	// Get all packet decoders
	allPacketDecoders := packet.GetPacketDecoders()

	for _, dec := range allPacketDecoders {
		name := dec.GetName()
		if !seenDecoders[name] {
			seenDecoders[name] = true
			layer := determineLayer(name)

			decodersByLayer[layer] = append(decodersByLayer[layer], DecoderInfo{
				Name:        name,
				Type:        dec.GetType(),
				Description: dec.GetDescription(),
				Layer:       layer,
			})
		}
	}
}

// addStreamDecoders adds TCP/UDP stream decoders
func addStreamDecoders(decodersByLayer map[string][]DecoderInfo, seenDecoders map[string]bool) {
	streamDecoders := []struct {
		name        string
		typeName    string
		description string
	}{
		{"HTTP", "HTTP", "HTTP protocol stream decoder"},
		{"SSH", "SSH", "SSH protocol stream decoder"},
		{"SMTP", "SMTP", "SMTP protocol stream decoder"},
		{"POP3", "POP3", "POP3 protocol stream decoder"},
		{"OPCUA", "OPCUA", "OPC UA ICS/SCADA stream decoder"},
		{"S7Comm", "S7Comm", "S7Comm ICS/SCADA stream decoder"},
		{"MQTTSN", "MQTTSN", "MQTT-SN IoT/sensor network stream decoder"},
	}

	for _, sd := range streamDecoders {
		if !seenDecoders[sd.name] {
			seenDecoders[sd.name] = true
			decodersByLayer["Stream Decoders"] = append(decodersByLayer["Stream Decoders"], DecoderInfo{
				Name:        sd.name,
				Type:        getTypeForName(sd.typeName),
				Description: sd.description,
				Layer:       "Stream Decoders",
			})
		}
	}
}

// addAbstractDecoders adds high-level abstract decoders
func addAbstractDecoders(decodersByLayer map[string][]DecoderInfo, seenDecoders map[string]bool) {
	abstractDecoders := []struct {
		name        string
		typeName    string
		description string
	}{
		{"Connection", "Connection", "Network connection tracking"},
		{"DeviceProfile", "DeviceProfile", "Device profiling and fingerprinting"},
		{"File", "File", "File extraction and analysis"},
		{"Service", "Service", "Service identification"},
		{"Software", "Software", "Software detection"},
		{"Secret", "Secret", "Secret harvesting"},
		{"Vulnerability", "Vulnerability", "Vulnerability detection"},
		{"Exploit", "Exploit", "Exploit detection"},
		{"IPProfile", "IPProfile", "IP address profiling"},
		{"Mail", "Mail", "Email message analysis"},
		{"Alert", "Alert", "Security alerts and events"},
		{"TLSClientHello", "TLSClientHello", "TLS client hello analysis"},
		{"TLSServerHello", "TLSServerHello", "TLS server hello analysis"},
	}

	for _, ad := range abstractDecoders {
		if !seenDecoders[ad.name] {
			seenDecoders[ad.name] = true
			decodersByLayer["Abstract Decoders"] = append(decodersByLayer["Abstract Decoders"], DecoderInfo{
				Name:        ad.name,
				Type:        getTypeForName(ad.typeName),
				Description: ad.description,
				Layer:       "Abstract Decoders",
			})
		}
	}
}

// determineLayer determines the OSI layer for a decoder based on its name
func determineLayer(name string) string {
	name = strings.ToLower(name)

	// Link Layer protocols
	linkLayerProtocols := []string{"ethernet", "arp", "dot1q", "dot11", "llc", "snap",
		"linklayerdiscovery", "ethernetctp", "fddi", "usb", "cisco", "nortel",
		"ppp", "pppoe", "stp"}
	for _, proto := range linkLayerProtocols {
		if strings.Contains(name, proto) {
			return "Link Layer"
		}
	}

	// Network Layer protocols
	networkLayerProtocols := []string{"ipv4", "ipv6", "icmp", "ipsec", "igmp", "mpls", "gre", "mld"}
	for _, proto := range networkLayerProtocols {
		if strings.Contains(name, proto) {
			return "Network Layer"
		}
	}

	// Transport Layer protocols
	transportLayerProtocols := []string{"tcp", "udp", "sctp"}
	for _, proto := range transportLayerProtocols {
		if strings.Contains(name, proto) {
			return "Transport Layer"
		}
	}

	// Application Layer protocols
	applicationLayerProtocols := []string{"dns", "dhcp", "http", "tls", "ntp", "sip",
		"smtp", "pop3", "ssh", "lcm", "modbus", "ospf", "bfd", "eap", "cip", "enip",
		"geneve", "vxlan", "vrrp", "diameter", "rmcp", "opcua", "s7comm", "mqttsn"}
	for _, proto := range applicationLayerProtocols {
		if strings.Contains(name, proto) {
			return "Application Layer"
		}
	}

	return "Application Layer"
}

// getTypeForName returns the types.Type for a given name
func getTypeForName(name string) types.Type {
	typeMap := map[string]types.Type{
		"Header":                       types.Type_NC_Header,
		"Batch":                        types.Type_NC_Batch,
		"Connection":                   types.Type_NC_Connection,
		"Ethernet":                     types.Type_NC_Ethernet,
		"ARP":                          types.Type_NC_ARP,
		"Dot1Q":                        types.Type_NC_Dot1Q,
		"Dot11":                        types.Type_NC_Dot11,
		"LinkLayerDiscovery":           types.Type_NC_LinkLayerDiscovery,
		"EthernetCTP":                  types.Type_NC_EthernetCTP,
		"EthernetCTPReply":             types.Type_NC_EthernetCTPReply,
		"FDDI":                         types.Type_NC_FDDI,
		"USB":                          types.Type_NC_USB,
		"CiscoDiscovery":               types.Type_NC_CiscoDiscovery,
		"NortelDiscovery":              types.Type_NC_NortelDiscovery,
		"IPv4":                         types.Type_NC_IPv4,
		"IPv6":                         types.Type_NC_IPv6,
		"ICMPv4":                       types.Type_NC_ICMPv4,
		"ICMPv6":                       types.Type_NC_ICMPv6,
		"IPSecAH":                      types.Type_NC_IPSecAH,
		"IPSecESP":                     types.Type_NC_IPSecESP,
		"IPv6HopByHop":                 types.Type_NC_IPv6HopByHop,
		"IPv6Fragment":                 types.Type_NC_IPv6Fragment,
		"IGMP":                         types.Type_NC_IGMP,
		"MPLS":                         types.Type_NC_MPLS,
		"GRE":                          types.Type_NC_GRE,
		"TCP":                          types.Type_NC_TCP,
		"UDP":                          types.Type_NC_UDP,
		"SCTP":                         types.Type_NC_SCTP,
		"DNS":                          types.Type_NC_DNS,
		"DHCPv4":                       types.Type_NC_DHCPv4,
		"DHCPv6":                       types.Type_NC_DHCPv6,
		"NTP":                          types.Type_NC_NTP,
		"SIP":                          types.Type_NC_SIP,
		"HTTP":                         types.Type_NC_HTTP,
		"TLSClientHello":               types.Type_NC_TLSClientHello,
		"TLSServerHello":               types.Type_NC_TLSServerHello,
		"SMTP":                         types.Type_NC_SMTP,
		"POP3":                         types.Type_NC_POP3,
		"SSH":                          types.Type_NC_SSH,
		"LCM":                          types.Type_NC_LCM,
		"Modbus":                       types.Type_NC_Modbus,
		"OSPFv2":                       types.Type_NC_OSPFv2,
		"OSPFv3":                       types.Type_NC_OSPFv3,
		"BFD":                          types.Type_NC_BFD,
		"EAP":                          types.Type_NC_EAP,
		"EAPOL":                        types.Type_NC_EAPOL,
		"EAPOLKey":                     types.Type_NC_EAPOLKey,
		"CIP":                          types.Type_NC_CIP,
		"ENIP":                         types.Type_NC_ENIP,
		"Geneve":                       types.Type_NC_Geneve,
		"VXLAN":                        types.Type_NC_VXLAN,
		"VRRPv2":                       types.Type_NC_VRRPv2,
		"LLC":                          types.Type_NC_LLC,
		"SNAP":                         types.Type_NC_SNAP,
		"DeviceProfile":                types.Type_NC_DeviceProfile,
		"File":                         types.Type_NC_File,
		"Service":                      types.Type_NC_Service,
		"Software":                     types.Type_NC_Software,
		"Secret":                       types.Type_NC_Secret,
		"Vulnerability":                types.Type_NC_Vulnerability,
		"Exploit":                      types.Type_NC_Exploit,
		"IPProfile":                    types.Type_NC_IPProfile,
		"Mail":                         types.Type_NC_Mail,
		"Alert":                        types.Type_NC_Alert,
		"Diameter":                     types.Type_NC_Diameter,
		"PPPoE":                        types.Type_NC_PPPoE,
		"PPP":                          types.Type_NC_PPP,
		"RMCP":                         types.Type_NC_RMCP,
		"STP":                          types.Type_NC_STP,
		"MLDv2MulticastListenerQuery":  types.Type_NC_MLDv2MulticastListenerQuery,
		"MLDv2MulticastListenerReport": types.Type_NC_MLDv2MulticastListenerReport,
		"OPCUA":                        types.Type_NC_OPCUA,
		"S7Comm":                       types.Type_NC_S7Comm,
		"MQTTSN":                       types.Type_NC_MQTTSN,
	}

	if t, ok := typeMap[name]; ok {
		return t
	}

	return types.Type_NC_Header
}

// printHierarchicalLayers prints layers in a hierarchical tree structure
func printHierarchicalLayers(decodersByLayer map[string][]DecoderInfo) {
	// Print Link Layer
	fmt.Println("├── Link Layer")
	if decoders, ok := decodersByLayer["Link Layer"]; ok {
		printDecoderList(decoders, "│   ", false, true) // hasChildLayer=true because Network Layer follows
	}

	// Print Network Layer as child of Link Layer
	fmt.Println("│   └── Network Layer")
	if decoders, ok := decodersByLayer["Network Layer"]; ok {
		printDecoderList(decoders, "│       ", false, true) // hasChildLayer=true because Transport Layer follows
	}

	// Print Transport Layer as child of Network Layer
	fmt.Println("│       └── Transport Layer")
	if decoders, ok := decodersByLayer["Transport Layer"]; ok {
		printDecoderList(decoders, "│           ", false, true) // hasChildLayer=true because Application Layer follows
	}

	// Print Application Layer as child of Transport Layer
	fmt.Println("│           └── Application Layer")
	if decoders, ok := decodersByLayer["Application Layer"]; ok {
		printDecoderList(decoders, "│               ", true, false) // hasChildLayer=false, this is the end
	}

	// Print Stream Decoders at root level
	fmt.Println("│")
	fmt.Println("├── Stream Decoders")
	if decoders, ok := decodersByLayer["Stream Decoders"]; ok {
		printDecoderList(decoders, "│   ", false, false) // hasChildLayer=false
	}

	// Print Abstract Decoders at root level (last one)
	fmt.Println("│")
	fmt.Println("└── Abstract Decoders")
	if decoders, ok := decodersByLayer["Abstract Decoders"]; ok {
		printDecoderList(decoders, "    ", true, false) // hasChildLayer=false
	}
}

// printDecoderList prints a list of decoders with the given indent
// hasChildLayer indicates if a child layer follows the decoder list
func printDecoderList(decoders []DecoderInfo, indent string, isLast bool, hasChildLayer bool) {
	for i, decoder := range decoders {
		isLastDecoder := i == len(decoders)-1
		prefix := indent + "├──"
		// Only use └── if it's the last decoder AND there's no child layer following
		if isLastDecoder && !hasChildLayer {
			prefix = indent + "└──"
		}

		fmt.Printf("%s %s (Type: %s)\n", prefix, decoder.Name, decoder.Type.String())
		if decoder.Description != "" {
			descPrefix := indent + "│   "
			// Use spaces for description indent only if this is truly the last item
			if isLastDecoder && !hasChildLayer {
				descPrefix = indent + "    "
			}
			fmt.Printf("%s    └─ %s\n", descPrefix, decoder.Description)
		}
	}
}

// printLayerWithIndent prints a layer and its decoders with specified indentation level
func printLayerWithIndent(layerName string, decoders []DecoderInfo, indentLevel int, isLastRoot bool) {
	// Build indent prefix based on level
	indent := ""
	for range indentLevel {
		indent += "│   "
	}

	fmt.Printf("%s├── %s\n", indent, layerName)

	// After branching with ├──, use spaces for items within this layer
	itemIndent := indent + "    "

	for i, decoder := range decoders {
		isLast := i == len(decoders)-1
		prefix := itemIndent + "├──"
		if isLast {
			prefix = itemIndent + "└──"
		}

		fmt.Printf("%s %s (Type: %s)\n", prefix, decoder.Name, decoder.Type.String())
		if decoder.Description != "" {
			descPrefix := itemIndent + "│   "
			if isLast {
				descPrefix = itemIndent + "    "
			}
			fmt.Printf("%s    └─ %s\n", descPrefix, decoder.Description)
		}
	}

	// Add spacing between sections, but not after the last root-level section
	if !isLastRoot {
		fmt.Printf("%s│\n", indent)
	}
}

// printLayer prints a layer and its decoders in tree format (legacy function kept for compatibility)
func printLayer(layerName string, decoders []DecoderInfo) {
	printLayerWithIndent(layerName, decoders, 0, false)
}

// countTotalDecoders counts the total number of decoders across all layers
func countTotalDecoders(decodersByLayer map[string][]DecoderInfo) int {
	total := 0
	for _, decoders := range decodersByLayer {
		total += len(decoders)
	}
	return total
}
