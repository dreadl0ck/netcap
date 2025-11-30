/*
 * NETCAP - Traffic Analysis Framework
 * Copyright (c) Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
 * License: GNU General Public License v3.0
 */

package ja4

import (
	"strings"
	"testing"
)

func TestComputeJA4D(t *testing.T) {
	tests := []struct {
		name        string
		data        *DHCPv4Data
		validateLen bool // Just validate format since hashes will change
	}{
		{
			name: "Windows DHCP DISCOVER",
			data: &DHCPv4Data{
				MessageType:  DHCPMsgTypeDiscover,
				HardwareType: 1, // Ethernet
				Options: []uint8{
					DHCPOptionMessageType,
					DHCPOptionHostname,
					DHCPOptionParamRequestList,
					DHCPOptionVendorClassID,
					DHCPOptionClientID,
					DHCPOptionEnd,
				},
				ParamRequestList: []uint8{1, 3, 6, 15, 31, 33, 43, 44, 46, 47, 119, 121, 249, 252},
				VendorClass:      "MSFT 5.0",
				Hostname:         "DESKTOP-ABC123",
			},
			validateLen: true,
		},
		{
			name: "Android DHCP REQUEST",
			data: &DHCPv4Data{
				MessageType:  DHCPMsgTypeRequest,
				HardwareType: 1,
				Options: []uint8{
					DHCPOptionMessageType,
					DHCPOptionHostname,
					DHCPOptionParamRequestList,
					DHCPOptionVendorClassID,
					DHCPOptionRequestedIP,
					DHCPOptionEnd,
				},
				ParamRequestList: []uint8{1, 3, 6, 15, 26, 28, 51, 58, 59},
				VendorClass:      "android-dhcp-12",
				Hostname:         "android-abcdef123456",
			},
			validateLen: true,
		},
		{
			name: "Linux dhclient DISCOVER",
			data: &DHCPv4Data{
				MessageType:  DHCPMsgTypeDiscover,
				HardwareType: 1,
				Options: []uint8{
					DHCPOptionMessageType,
					DHCPOptionParamRequestList,
					DHCPOptionHostname,
					DHCPOptionEnd,
				},
				ParamRequestList: []uint8{1, 28, 2, 3, 15, 6, 119, 12, 44, 47, 26, 121, 42},
				VendorClass:      "",
				Hostname:         "ubuntu-server",
			},
			validateLen: true,
		},
		{
			name: "iOS DHCP DISCOVER",
			data: &DHCPv4Data{
				MessageType:  DHCPMsgTypeDiscover,
				HardwareType: 1,
				Options: []uint8{
					DHCPOptionMessageType,
					DHCPOptionParamRequestList,
					DHCPOptionHostname,
					DHCPOptionEnd,
				},
				ParamRequestList: []uint8{1, 3, 6, 15, 119, 78, 79, 95, 252},
				VendorClass:      "",
				Hostname:         "iPhone",
			},
			validateLen: true,
		},
		{
			name: "Minimal embedded device",
			data: &DHCPv4Data{
				MessageType:  DHCPMsgTypeDiscover,
				HardwareType: 1,
				Options: []uint8{
					DHCPOptionMessageType,
					DHCPOptionParamRequestList,
				},
				ParamRequestList: []uint8{1, 3, 6},
				VendorClass:      "",
				Hostname:         "",
			},
			validateLen: true,
		},
		{
			name: "DHCP INFORM",
			data: &DHCPv4Data{
				MessageType:  DHCPMsgTypeInform,
				HardwareType: 1,
				Options: []uint8{
					DHCPOptionMessageType,
					DHCPOptionParamRequestList,
					DHCPOptionHostname,
					DHCPOptionEnd,
				},
				ParamRequestList: []uint8{1, 3, 6, 15, 44, 46, 47},
				VendorClass:      "",
				Hostname:         "workstation",
			},
			validateLen: true,
		},
		{
			name: "No Parameter Request List",
			data: &DHCPv4Data{
				MessageType:  DHCPMsgTypeDiscover,
				HardwareType: 1,
				Options: []uint8{
					DHCPOptionMessageType,
					DHCPOptionHostname,
					DHCPOptionEnd,
				},
				ParamRequestList: []uint8{},
				VendorClass:      "",
				Hostname:         "test-device",
			},
			validateLen: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ComputeJA4D(tt.data)

			// Validate format
			if !ValidateJA4D(result) {
				t.Errorf("ComputeJA4D() = %v, format validation failed", result)
			}

			// Check parts
			parts := strings.Split(result, "_")
			if len(parts) != 3 {
				t.Errorf("ComputeJA4D() = %v, expected 3 parts", result)
			}

			// Validate ja4d_a structure
			if len(parts[0]) != 10 {
				t.Errorf("ja4d_a length = %d, want 10", len(parts[0]))
			}

			// Check message type character
			expectedMsgType := dhcpMsgTypeChar(tt.data.MessageType)
			if string(parts[0][0]) != expectedMsgType {
				t.Errorf("message type = %s, want %s", string(parts[0][0]), expectedMsgType)
			}

			t.Logf("JA4D: %s", result)
		})
	}
}

func TestComputeJA4DRaw(t *testing.T) {
	data := &DHCPv4Data{
		MessageType:      DHCPMsgTypeDiscover,
		HardwareType:     1,
		Options:          []uint8{53, 12, 55, 60, 61, 255},
		ParamRequestList: []uint8{1, 3, 6, 15, 28, 42},
		VendorClass:      "MSFT 5.0",
		Hostname:         "DESKTOP-TEST",
	}

	result := ComputeJA4DRaw(data)
	t.Logf("JA4D Raw: %s", result)

	// Check it contains the raw PRL values
	if !strings.Contains(result, "1,3,6,15,28,42") {
		t.Errorf("JA4D Raw should contain PRL values, got: %s", result)
	}
}

func TestValidateJA4D(t *testing.T) {
	tests := []struct {
		fingerprint string
		valid       bool
	}{
		{"d010505msh_abc123def456_123456789abc", true},
		{"r010808anh_abc123def456_123456789abc", true},
		{"d010303000_000000000000_000000000000", true},
		{"invalid", false},
		{"d010505msh_abc123def456", false}, // Missing part
		{"d010505msh_abc123def456_123456789abc_extra", false}, // Extra part
		{"", false},
		{"d10505msh_abc123def456_123456789abc", false}, // ja4d_a too short (9 chars)
	}

	for _, tt := range tests {
		t.Run(tt.fingerprint, func(t *testing.T) {
			result := ValidateJA4D(tt.fingerprint)
			if result != tt.valid {
				t.Errorf("ValidateJA4D(%q) = %v, want %v", tt.fingerprint, result, tt.valid)
			}
		})
	}
}

func TestDHCPMsgTypeChar(t *testing.T) {
	tests := []struct {
		msgType  uint8
		expected string
	}{
		{DHCPMsgTypeDiscover, "d"},
		{DHCPMsgTypeOffer, "o"},
		{DHCPMsgTypeRequest, "r"},
		{DHCPMsgTypeDecline, "n"},
		{DHCPMsgTypeAck, "a"},
		{DHCPMsgTypeNak, "k"},
		{DHCPMsgTypeRelease, "l"},
		{DHCPMsgTypeInform, "i"},
		{99, "x"}, // Unknown type
	}

	for _, tt := range tests {
		t.Run(DHCPMsgTypeName(tt.msgType), func(t *testing.T) {
			result := dhcpMsgTypeChar(tt.msgType)
			if result != tt.expected {
				t.Errorf("dhcpMsgTypeChar(%d) = %s, want %s", tt.msgType, result, tt.expected)
			}
		})
	}
}

func TestExtractVendorCode(t *testing.T) {
	tests := []struct {
		vendorClass string
		expected    string
	}{
		{"MSFT 5.0", "ms"},
		{"android-dhcp-12", "an"},
		{"dhcpcd-6.11.5", "dh"},
		{"", "00"},
		{"AB", "ab"},
		{"A", "a0"},
		{"123", "12"},
		{"   test", "te"},     // Leading spaces
		{"!!!hello", "he"},    // Non-alphanumeric prefix
		{"αβγδ", "00"},        // Non-ASCII
		{"HP LaserJet", "hp"}, // Mixed case
	}

	for _, tt := range tests {
		t.Run(tt.vendorClass, func(t *testing.T) {
			result := extractVendorCode(tt.vendorClass)
			if result != tt.expected {
				t.Errorf("extractVendorCode(%q) = %s, want %s", tt.vendorClass, result, tt.expected)
			}
		})
	}
}

func TestCountSignificantOptions(t *testing.T) {
	tests := []struct {
		name     string
		options  []uint8
		expected int
	}{
		{"Empty", []uint8{}, 0},
		{"Only pad and end", []uint8{0, 255}, 0},
		{"With real options", []uint8{0, 53, 12, 55, 60, 255}, 4},
		{"All significant", []uint8{53, 12, 55, 60}, 4},
		{"Multiple pads", []uint8{0, 0, 53, 0, 12, 0, 255}, 2},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := countSignificantOptions(tt.options)
			if result != tt.expected {
				t.Errorf("countSignificantOptions() = %d, want %d", result, tt.expected)
			}
		})
	}
}

func TestFilterDHCPOptions(t *testing.T) {
	tests := []struct {
		name     string
		options  []uint8
		expected []uint8
	}{
		{
			name:     "Filter PRL and MessageType",
			options:  []uint8{0, 53, 12, 55, 60, 61, 255},
			expected: []uint8{12, 60, 61},
		},
		{
			name:     "Only filtered options",
			options:  []uint8{0, 53, 55, 255},
			expected: []uint8{},
		},
		{
			name:     "No filtered options",
			options:  []uint8{12, 60, 61},
			expected: []uint8{12, 60, 61},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := filterDHCPOptions(tt.options)
			if len(result) != len(tt.expected) {
				t.Errorf("filterDHCPOptions() len = %d, want %d", len(result), len(tt.expected))
				return
			}
			for i, v := range result {
				if v != tt.expected[i] {
					t.Errorf("filterDHCPOptions()[%d] = %d, want %d", i, v, tt.expected[i])
				}
			}
		})
	}
}

func TestGetDHCPDeviceHint(t *testing.T) {
	tests := []struct {
		name     string
		data     *DHCPv4Data
		contains string
	}{
		{
			name: "Windows via vendor class",
			data: &DHCPv4Data{
				VendorClass: "MSFT 5.0",
			},
			contains: "Windows",
		},
		{
			name: "Android via vendor class",
			data: &DHCPv4Data{
				VendorClass: "android-dhcp-12",
			},
			contains: "Android",
		},
		{
			name: "Linux dhcpcd",
			data: &DHCPv4Data{
				VendorClass: "dhcpcd-6.11.5",
			},
			contains: "dhcpcd",
		},
		{
			name: "iPhone via hostname",
			data: &DHCPv4Data{
				Hostname: "iPhone-12-Pro",
			},
			contains: "iPhone",
		},
		{
			name: "iPad via hostname",
			data: &DHCPv4Data{
				Hostname: "iPadPro",
			},
			contains: "iPad",
		},
		{
			name: "Minimal IoT device",
			data: &DHCPv4Data{
				ParamRequestList: []uint8{1, 3},
			},
			contains: "Minimal",
		},
		{
			name: "Unknown device",
			data: &DHCPv4Data{},
			contains: "Unknown",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := GetDHCPDeviceHint(tt.data)
			if !strings.Contains(result, tt.contains) {
				t.Errorf("GetDHCPDeviceHint() = %s, want to contain %s", result, tt.contains)
			}
		})
	}
}

func TestExtractDHCPv4Data(t *testing.T) {
	// Build a sample DHCP options payload
	// MessageType = DISCOVER (1)
	// Hostname = "test"
	// ParamRequestList = [1, 3, 6, 15]
	// VendorClass = "MSFT"
	// End
	optionBytes := []byte{
		// Message Type
		53, 1, 1,
		// Hostname "test"
		12, 4, 't', 'e', 's', 't',
		// Parameter Request List
		55, 4, 1, 3, 6, 15,
		// Vendor Class "MSFT"
		60, 4, 'M', 'S', 'F', 'T',
		// End
		255,
	}

	data := ExtractDHCPv4Data(DHCPMsgTypeDiscover, 1, optionBytes)

	if data.Hostname != "test" {
		t.Errorf("Hostname = %s, want test", data.Hostname)
	}

	if data.VendorClass != "MSFT" {
		t.Errorf("VendorClass = %s, want MSFT", data.VendorClass)
	}

	expectedPRL := []uint8{1, 3, 6, 15}
	if len(data.ParamRequestList) != len(expectedPRL) {
		t.Errorf("ParamRequestList len = %d, want %d", len(data.ParamRequestList), len(expectedPRL))
	} else {
		for i, v := range data.ParamRequestList {
			if v != expectedPRL[i] {
				t.Errorf("ParamRequestList[%d] = %d, want %d", i, v, expectedPRL[i])
			}
		}
	}

	// Should contain all options
	expectedOpts := []uint8{53, 12, 55, 60, 255}
	if len(data.Options) != len(expectedOpts) {
		t.Errorf("Options len = %d, want %d", len(data.Options), len(expectedOpts))
	}
}

func TestBuildDHCPv4DataFromOptions(t *testing.T) {
	data := BuildDHCPv4DataFromOptions(
		DHCPMsgTypeRequest,
		1,
		[]uint8{53, 12, 55, 60},
		[]uint8{1, 3, 6, 15, 28},
		"android-dhcp",
		"Pixel-5",
	)

	if data.MessageType != DHCPMsgTypeRequest {
		t.Errorf("MessageType = %d, want %d", data.MessageType, DHCPMsgTypeRequest)
	}

	if data.HardwareType != 1 {
		t.Errorf("HardwareType = %d, want 1", data.HardwareType)
	}

	if data.VendorClass != "android-dhcp" {
		t.Errorf("VendorClass = %s, want android-dhcp", data.VendorClass)
	}

	if data.Hostname != "Pixel-5" {
		t.Errorf("Hostname = %s, want Pixel-5", data.Hostname)
	}

	result := ComputeJA4D(data)
	if !ValidateJA4D(result) {
		t.Errorf("ComputeJA4D() = %s, format validation failed", result)
	}
	t.Logf("JA4D: %s", result)
}

func TestJA4DConsistency(t *testing.T) {
	// Test that the same data always produces the same fingerprint
	data := &DHCPv4Data{
		MessageType:      DHCPMsgTypeDiscover,
		HardwareType:     1,
		Options:          []uint8{53, 12, 55, 60, 61, 255},
		ParamRequestList: []uint8{1, 3, 6, 15, 28, 42, 44, 45, 46, 47},
		VendorClass:      "MSFT 5.0",
		Hostname:         "TEST-PC",
	}

	first := ComputeJA4D(data)
	for i := 0; i < 100; i++ {
		result := ComputeJA4D(data)
		if result != first {
			t.Errorf("Inconsistent fingerprint: got %s, want %s", result, first)
		}
	}
}

func TestJA4DUniqueness(t *testing.T) {
	// Different PRL should produce different fingerprints
	data1 := &DHCPv4Data{
		MessageType:      DHCPMsgTypeDiscover,
		HardwareType:     1,
		Options:          []uint8{53, 55, 255},
		ParamRequestList: []uint8{1, 3, 6, 15},
		VendorClass:      "",
		Hostname:         "",
	}

	data2 := &DHCPv4Data{
		MessageType:      DHCPMsgTypeDiscover,
		HardwareType:     1,
		Options:          []uint8{53, 55, 255},
		ParamRequestList: []uint8{1, 3, 6, 15, 28},
		VendorClass:      "",
		Hostname:         "",
	}

	fp1 := ComputeJA4D(data1)
	fp2 := ComputeJA4D(data2)

	if fp1 == fp2 {
		t.Errorf("Different PRL should produce different fingerprints: %s == %s", fp1, fp2)
	}

	// Both should still be valid
	if !ValidateJA4D(fp1) {
		t.Errorf("fp1 validation failed: %s", fp1)
	}
	if !ValidateJA4D(fp2) {
		t.Errorf("fp2 validation failed: %s", fp2)
	}

	t.Logf("FP1: %s", fp1)
	t.Logf("FP2: %s", fp2)
}

func TestParseJA4D(t *testing.T) {
	// Create a fingerprint and then parse it
	data := &DHCPv4Data{
		MessageType:      DHCPMsgTypeDiscover,
		HardwareType:     1,
		Options:          []uint8{53, 12, 55, 60, 255},
		ParamRequestList: []uint8{1, 3, 6, 15, 28},
		VendorClass:      "MSFT 5.0",
		Hostname:         "TEST-PC",
	}

	fp := ComputeJA4D(data)
	t.Logf("Fingerprint: %s", fp)

	msgType, hwType, prlCount, optCount, vendor, hostname, prlHash, optHash, err := ParseJA4D(fp)
	if err != nil {
		t.Fatalf("ParseJA4D failed: %v", err)
	}

	if msgType != "d" {
		t.Errorf("msgType = %s, want d", msgType)
	}

	if hwType != 1 {
		t.Errorf("hwType = %d, want 1", hwType)
	}

	if prlCount != 5 { // Length of ParamRequestList
		t.Errorf("prlCount = %d, want 5", prlCount)
	}

	// optCount should be significant options (excluding pad/end)
	if optCount != 4 { // 53, 12, 55, 60 (excluding 255/end)
		t.Errorf("optCount = %d, want 4", optCount)
	}

	if vendor != "ms" {
		t.Errorf("vendor = %s, want ms", vendor)
	}

	if hostname != "h" {
		t.Errorf("hostname = %s, want h", hostname)
	}

	if len(prlHash) != 12 {
		t.Errorf("prlHash length = %d, want 12", len(prlHash))
	}

	if len(optHash) != 12 {
		t.Errorf("optHash length = %d, want 12", len(optHash))
	}
}

