/*
 * NETCAP - Traffic Analysis Framework
 * Copyright (c) Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
 * License: GNU General Public License v3.0
 *
 * JA4D - DHCP Client Fingerprint
 * Inspired by the JA4+ fingerprinting suite from FoxIO-LLC
 *
 * This implementation follows the JA4+ methodology to create DHCP fingerprints
 * based on DHCP options, particularly the Parameter Request List (Option 55).
 *
 * DHCP fingerprinting is commonly used for device identification and network
 * profiling. The Parameter Request List is one of the most distinctive
 * features of DHCP clients as it reveals the options the client is requesting.
 *
 * Reference: https://github.com/FoxIO-LLC/ja4
 */

package ja4

import (
	"fmt"
	"sort"
	"strings"
)

// DHCP Option Types
const (
	DHCPOptionPad               = 0
	DHCPOptionSubnetMask        = 1
	DHCPOptionRouter            = 3
	DHCPOptionDNS               = 6
	DHCPOptionHostname          = 12
	DHCPOptionDomainName        = 15
	DHCPOptionBroadcast         = 28
	DHCPOptionNTPServers        = 42
	DHCPOptionRequestedIP       = 50
	DHCPOptionLeaseTime         = 51
	DHCPOptionMessageType       = 53
	DHCPOptionServerID          = 54
	DHCPOptionParamRequestList  = 55
	DHCPOptionMaxMsgSize        = 57
	DHCPOptionRenewalTime       = 58
	DHCPOptionRebindingTime     = 59
	DHCPOptionVendorClassID     = 60
	DHCPOptionClientID          = 61
	DHCPOptionDomainSearch      = 119
	DHCPOptionClasslessStaticRT = 121
	DHCPOptionEnd               = 255
)

// DHCP Message Types
const (
	DHCPMsgTypeDiscover = 1
	DHCPMsgTypeOffer    = 2
	DHCPMsgTypeRequest  = 3
	DHCPMsgTypeDecline  = 4
	DHCPMsgTypeAck      = 5
	DHCPMsgTypeNak      = 6
	DHCPMsgTypeRelease  = 7
	DHCPMsgTypeInform   = 8
)

// DHCPv4Data contains the data needed to compute a JA4D fingerprint
type DHCPv4Data struct {
	MessageType      uint8    // DHCP message type (DISCOVER, REQUEST, etc.)
	HardwareType     uint8    // Hardware type (1=Ethernet, 6=IEEE802, etc.)
	Options          []uint8  // All DHCP option types present (in wire order)
	ParamRequestList []uint8  // Parameter Request List (Option 55) values
	VendorClass      string   // Vendor Class Identifier (Option 60)
	Hostname         string   // Hostname (Option 12)
	ClientMAC        string   // Client MAC address (for tracking)
}

// ComputeJA4D computes the JA4D fingerprint for a DHCPv4 packet
// Format: {ja4d_a}_{ja4d_b}_{ja4d_c}
// Example: d011412msh_8a2f3b4c5d6e_1234567890ab
//
// ja4d_a (10 chars): {msg_type:1}{hw_type:2d}{prl_count:2d}{opt_count:2d}{vendor:2}{hostname:1}
// ja4d_b: 12-char truncated SHA256 of Parameter Request List values (comma-separated)
// ja4d_c: 12-char truncated SHA256 of sorted DHCP options (comma-separated)
func ComputeJA4D(data *DHCPv4Data) string {
	ja4da := computeJA4Da(data)
	ja4db := computeJA4Db(data.ParamRequestList)
	ja4dc := computeJA4Dc(data.Options)

	return fmt.Sprintf("%s_%s_%s", ja4da, ja4db, ja4dc)
}

// ComputeJA4DRaw returns the unhashed JA4D fingerprint for debugging
func ComputeJA4DRaw(data *DHCPv4Data) string {
	ja4da := computeJA4Da(data)

	// Parameter Request List values (comma-separated)
	var prlStrs []string
	for _, opt := range data.ParamRequestList {
		prlStrs = append(prlStrs, fmt.Sprintf("%d", opt))
	}
	prlStr := strings.Join(prlStrs, ",")

	// Sorted options (excluding PRL, MessageType, Pad, End)
	filtered := filterDHCPOptions(data.Options)
	sort.Slice(filtered, func(i, j int) bool {
		return filtered[i] < filtered[j]
	})
	var optStrs []string
	for _, opt := range filtered {
		optStrs = append(optStrs, fmt.Sprintf("%d", opt))
	}
	optStr := strings.Join(optStrs, ",")

	return fmt.Sprintf("%s_%s_%s", ja4da, prlStr, optStr)
}

// computeJA4Da computes the first part of JA4D (10 characters)
// Format: {msg_type:1}{hw_type:2d}{prl_count:2d}{opt_count:2d}{vendor:2}{hostname:1}
func computeJA4Da(data *DHCPv4Data) string {
	// Message type (single character)
	msgType := dhcpMsgTypeChar(data.MessageType)

	// Hardware type (2 digits, capped at 99)
	hwType := int(data.HardwareType)
	if hwType > 99 {
		hwType = 99
	}

	// Parameter Request List count, capped at 99
	prlCount := len(data.ParamRequestList)
	if prlCount > 99 {
		prlCount = 99
	}

	// Total option count (excluding Pad and End), capped at 99
	optCount := countSignificantOptions(data.Options)
	if optCount > 99 {
		optCount = 99
	}

	// Vendor Class: first 2 alphanumeric chars (lowercase) or "00" if not present
	vendor := extractVendorCode(data.VendorClass)

	// Hostname: "h" if present, "0" if not
	hostname := "0"
	if data.Hostname != "" {
		hostname = "h"
	}

	return fmt.Sprintf("%s%02d%02d%02d%s%s", msgType, hwType, prlCount, optCount, vendor, hostname)
}

// computeJA4Db computes the second part of JA4D (12 characters)
// Truncated SHA256 hash of Parameter Request List values (comma-separated in order)
func computeJA4Db(paramRequestList []uint8) string {
	if len(paramRequestList) == 0 {
		return "000000000000"
	}

	var strs []string
	for _, opt := range paramRequestList {
		strs = append(strs, fmt.Sprintf("%d", opt))
	}

	return truncatedSHA256(strings.Join(strs, ","))
}

// computeJA4Dc computes the third part of JA4D (12 characters)
// Truncated SHA256 hash of sorted DHCP options (excluding PRL, MessageType, Pad, End)
func computeJA4Dc(options []uint8) string {
	filtered := filterDHCPOptions(options)
	if len(filtered) == 0 {
		return "000000000000"
	}

	// Sort numerically
	sort.Slice(filtered, func(i, j int) bool {
		return filtered[i] < filtered[j]
	})

	var strs []string
	for _, opt := range filtered {
		strs = append(strs, fmt.Sprintf("%d", opt))
	}

	return truncatedSHA256(strings.Join(strs, ","))
}

// dhcpMsgTypeChar returns a single character representing the DHCP message type
func dhcpMsgTypeChar(msgType uint8) string {
	switch msgType {
	case DHCPMsgTypeDiscover:
		return "d" // DISCOVER
	case DHCPMsgTypeOffer:
		return "o" // OFFER
	case DHCPMsgTypeRequest:
		return "r" // REQUEST
	case DHCPMsgTypeDecline:
		return "n" // decliNe (d already used)
	case DHCPMsgTypeAck:
		return "a" // ACK
	case DHCPMsgTypeNak:
		return "k" // naK
	case DHCPMsgTypeRelease:
		return "l" // reLease
	case DHCPMsgTypeInform:
		return "i" // INFORM
	default:
		return "x" // Unknown
	}
}

// extractVendorCode extracts a 2-character code from the vendor class identifier
// Returns "00" if empty or not alphanumeric
func extractVendorCode(vendorClass string) string {
	if vendorClass == "" {
		return "00"
	}

	// Extract first 2 alphanumeric characters, lowercase
	var result strings.Builder
	for _, c := range strings.ToLower(vendorClass) {
		if (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') {
			result.WriteRune(c)
			if result.Len() >= 2 {
				break
			}
		}
	}

	code := result.String()
	if len(code) == 0 {
		return "00"
	}
	if len(code) == 1 {
		return code + "0"
	}
	return code
}

// countSignificantOptions counts DHCP options excluding Pad (0) and End (255)
func countSignificantOptions(options []uint8) int {
	count := 0
	for _, opt := range options {
		if opt != DHCPOptionPad && opt != DHCPOptionEnd {
			count++
		}
	}
	return count
}

// filterDHCPOptions filters out PRL (55), MessageType (53), Pad (0), and End (255)
// These are excluded from the option hash to focus on distinctive options
func filterDHCPOptions(options []uint8) []uint8 {
	var filtered []uint8
	for _, opt := range options {
		if opt != DHCPOptionPad &&
			opt != DHCPOptionEnd &&
			opt != DHCPOptionMessageType &&
			opt != DHCPOptionParamRequestList {
			filtered = append(filtered, opt)
		}
	}
	return filtered
}

// ValidateJA4D checks if a JA4D fingerprint has the correct format
// Format: {10 chars}_{12 chars}_{12 chars}
func ValidateJA4D(fingerprint string) bool {
	parts := strings.Split(fingerprint, "_")
	if len(parts) != 3 {
		return false
	}
	// JA4D_a: 10 chars, JA4D_b and JA4D_c: 12 chars each
	return len(parts[0]) == 10 && len(parts[1]) == 12 && len(parts[2]) == 12
}

// ParseJA4D parses a JA4D fingerprint into its components
// Format: {msg_type:1}{hw_type:2d}{prl_count:2d}{opt_count:2d}{vendor:2}{hostname:1}
func ParseJA4D(fingerprint string) (msgType string, hwType int, prlCount, optCount int, vendor, hostname, prlHash, optHash string, err error) {
	parts := strings.Split(fingerprint, "_")
	if len(parts) != 3 {
		err = fmt.Errorf("invalid JA4D format: expected 3 parts, got %d", len(parts))
		return
	}

	if len(parts[0]) != 10 {
		err = fmt.Errorf("invalid JA4D_a length: expected 10, got %d", len(parts[0]))
		return
	}

	a := parts[0]
	msgType = string(a[0])

	_, err = fmt.Sscanf(a[1:3], "%d", &hwType)
	if err != nil {
		return
	}

	_, err = fmt.Sscanf(a[3:5], "%d", &prlCount)
	if err != nil {
		return
	}

	_, err = fmt.Sscanf(a[5:7], "%d", &optCount)
	if err != nil {
		return
	}

	vendor = a[7:9]
	hostname = string(a[9])

	prlHash = parts[1]
	optHash = parts[2]
	return
}

// DHCPMsgTypeName returns the human-readable name of a DHCP message type
func DHCPMsgTypeName(msgType uint8) string {
	switch msgType {
	case DHCPMsgTypeDiscover:
		return "DISCOVER"
	case DHCPMsgTypeOffer:
		return "OFFER"
	case DHCPMsgTypeRequest:
		return "REQUEST"
	case DHCPMsgTypeDecline:
		return "DECLINE"
	case DHCPMsgTypeAck:
		return "ACK"
	case DHCPMsgTypeNak:
		return "NAK"
	case DHCPMsgTypeRelease:
		return "RELEASE"
	case DHCPMsgTypeInform:
		return "INFORM"
	default:
		return "UNKNOWN"
	}
}

// GetDHCPDeviceHint returns a hint about the device based on JA4D fingerprint characteristics
func GetDHCPDeviceHint(data *DHCPv4Data) string {
	vendorLower := strings.ToLower(data.VendorClass)

	// Check vendor class for common patterns
	switch {
	case strings.Contains(vendorLower, "msft"):
		return "Microsoft Windows"
	case strings.Contains(vendorLower, "android"):
		return "Android Device"
	case strings.Contains(vendorLower, "dhcpcd"):
		return "Linux (dhcpcd)"
	case strings.Contains(vendorLower, "udhcp"):
		return "Linux (BusyBox udhcp)"
	case strings.Contains(vendorLower, "isc-dhclient"):
		return "Linux (ISC dhclient)"
	case strings.Contains(vendorLower, "darwin"):
		return "macOS/iOS"
	case strings.Contains(vendorLower, "cisco"):
		return "Cisco Device"
	case strings.Contains(vendorLower, "juniper"):
		return "Juniper Device"
	case strings.Contains(vendorLower, "printer"):
		return "Network Printer"
	case strings.Contains(vendorLower, "hp "):
		return "HP Device"
	case strings.Contains(vendorLower, "xerox"):
		return "Xerox Device"
	case strings.Contains(vendorLower, "canon"):
		return "Canon Device"
	case strings.Contains(vendorLower, "epson"):
		return "Epson Device"
	case strings.Contains(vendorLower, "samsung"):
		return "Samsung Device"
	case strings.Contains(vendorLower, "apple"):
		return "Apple Device"
	}

	// Check hostname patterns
	hostnameLower := strings.ToLower(data.Hostname)
	switch {
	case strings.HasPrefix(hostnameLower, "iphone"):
		return "iPhone"
	case strings.HasPrefix(hostnameLower, "ipad"):
		return "iPad"
	case strings.HasPrefix(hostnameLower, "android"):
		return "Android Device"
	case strings.HasPrefix(hostnameLower, "galaxy"):
		return "Samsung Galaxy"
	case strings.HasPrefix(hostnameLower, "desktop"):
		return "Windows Desktop"
	case strings.HasPrefix(hostnameLower, "laptop"):
		return "Laptop Computer"
	}

	// Infer from Parameter Request List length
	prlLen := len(data.ParamRequestList)
	switch {
	case prlLen >= 15:
		return "Modern OS (extensive options)"
	case prlLen >= 8:
		return "Standard Client"
	case prlLen >= 4:
		return "Basic Client"
	case prlLen > 0:
		return "Minimal Client (embedded/IoT)"
	}

	return "Unknown Device"
}

// ExtractDHCPv4Data extracts JA4D data from raw DHCP option bytes
// The options should be the raw option bytes from the DHCP packet
func ExtractDHCPv4Data(messageType uint8, hardwareType uint8, optionBytes []byte) *DHCPv4Data {
	data := &DHCPv4Data{
		MessageType:  messageType,
		HardwareType: hardwareType,
	}

	offset := 0
	for offset < len(optionBytes) {
		optType := optionBytes[offset]

		// End option
		if optType == DHCPOptionEnd {
			data.Options = append(data.Options, optType)
			break
		}

		// Pad option (single byte)
		if optType == DHCPOptionPad {
			data.Options = append(data.Options, optType)
			offset++
			continue
		}

		// All other options have length field
		if offset+1 >= len(optionBytes) {
			break
		}
		optLen := int(optionBytes[offset+1])
		if optLen < 0 || offset+2+optLen > len(optionBytes) {
			break
		}

		data.Options = append(data.Options, optType)
		optValue := optionBytes[offset+2 : offset+2+optLen]

		// Extract specific options
		switch optType {
		case DHCPOptionParamRequestList:
			data.ParamRequestList = make([]uint8, len(optValue))
			copy(data.ParamRequestList, optValue)
		case DHCPOptionVendorClassID:
			data.VendorClass = string(optValue)
		case DHCPOptionHostname:
			data.Hostname = string(optValue)
		}

		offset += 2 + optLen
	}

	return data
}

// BuildDHCPv4DataFromOptions builds DHCPv4Data from parsed DHCP options
// This is useful when the options have already been parsed (e.g., by gopacket)
func BuildDHCPv4DataFromOptions(
	messageType uint8,
	hardwareType uint8,
	options []uint8,
	paramRequestList []uint8,
	vendorClass string,
	hostname string,
) *DHCPv4Data {
	return &DHCPv4Data{
		MessageType:      messageType,
		HardwareType:     hardwareType,
		Options:          options,
		ParamRequestList: paramRequestList,
		VendorClass:      vendorClass,
		Hostname:         hostname,
	}
}

