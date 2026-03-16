/*
 * NETCAP - Traffic Analysis Framework
 * Copyright (c) Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
 * License: GNU General Public License v3.0
 *
 * JA4T/JA4TS TCP fingerprinting is licensed under the FoxIO License 1.1
 * Reference: https://github.com/FoxIO-LLC/ja4
 */

package ja4

import (
	"fmt"
	"slices"
	"strings"
)

// TCPFingerprintData contains the data needed to compute a JA4T/JA4TS fingerprint
type TCPFingerprintData struct {
	WindowSize  uint16  // TCP Window Size
	Options     []uint8 // TCP Option types in order
	MSS         uint16  // Maximum Segment Size (Option 2)
	WindowScale uint8   // Window Scale factor (Option 3)
	IsSYN       bool    // Is this a SYN packet (client)
	IsSYNACK    bool    // Is this a SYN-ACK packet (server)
}

// ComputeJA4T computes the JA4T fingerprint for a TCP SYN packet (client)
// Format: {window_size}_{options}_{mss}_{window_scale}
// Example: 64240_2-1-3-1-1-4_1460_8
func ComputeJA4T(data *TCPFingerprintData) string {
	if !data.IsSYN || data.IsSYNACK {
		// JA4T is only for SYN packets (not SYN-ACK)
		return ""
	}

	return computeTCPFingerprint(data)
}

// ComputeJA4TS computes the JA4TS fingerprint for a TCP SYN-ACK packet (server)
// Format: {window_size}_{options}_{mss}_{window_scale}
// Same format as JA4T but from server response
func ComputeJA4TS(data *TCPFingerprintData) string {
	if !data.IsSYNACK {
		// JA4TS is only for SYN-ACK packets
		return ""
	}

	return computeTCPFingerprint(data)
}

// computeTCPFingerprint computes the common TCP fingerprint format
func computeTCPFingerprint(data *TCPFingerprintData) string {
	// Build options string (hyphen-separated)
	var optStrs []string
	for _, opt := range data.Options {
		optStrs = append(optStrs, fmt.Sprintf("%d", opt))
	}
	optionsStr := strings.Join(optStrs, "-")
	if optionsStr == "" {
		optionsStr = "0" // No options
	}

	return fmt.Sprintf("%d_%s_%d_%d",
		data.WindowSize,
		optionsStr,
		data.MSS,
		data.WindowScale,
	)
}

// ValidateJA4T checks if a JA4T/JA4TS fingerprint has the correct format
func ValidateJA4T(fingerprint string) bool {
	parts := strings.Split(fingerprint, "_")
	return len(parts) == 4
}

// ParseJA4T parses a JA4T fingerprint into its components
func ParseJA4T(fingerprint string) (windowSize, mss, windowScale int, options []int, ok bool) {
	parts := strings.Split(fingerprint, "_")
	if len(parts) != 4 {
		return 0, 0, 0, nil, false
	}

	_, err := fmt.Sscanf(parts[0], "%d", &windowSize)
	if err != nil {
		return 0, 0, 0, nil, false
	}

	// Parse options
	if parts[1] != "0" && parts[1] != "" {
		optParts := strings.SplitSeq(parts[1], "-")
		for opt := range optParts {
			var o int
			_, err := fmt.Sscanf(opt, "%d", &o)
			if err != nil {
				return 0, 0, 0, nil, false
			}
			options = append(options, o)
		}
	}

	_, err = fmt.Sscanf(parts[2], "%d", &mss)
	if err != nil {
		return 0, 0, 0, nil, false
	}

	_, err = fmt.Sscanf(parts[3], "%d", &windowScale)
	if err != nil {
		return 0, 0, 0, nil, false
	}

	return windowSize, mss, windowScale, options, true
}

// ExtractTCPOptionsFromPacket extracts TCP option types from raw option bytes
func ExtractTCPOptionsFromPacket(optionData []byte) []uint8 {
	var options []uint8
	offset := 0

	for offset < len(optionData) {
		optType := optionData[offset]

		// End of options list
		if optType == 0 {
			options = append(options, 0)
			break
		}

		// No-operation (single byte)
		if optType == 1 {
			options = append(options, 1)
			offset++
			continue
		}

		// Other options have length field
		if offset+1 >= len(optionData) {
			break
		}
		optLen := int(optionData[offset+1])
		if optLen < 2 || offset+optLen > len(optionData) {
			break
		}

		options = append(options, optType)
		offset += optLen
	}

	return options
}

// GetOSHint returns a hint about the OS based on JA4T fingerprint characteristics
func GetOSHint(data *TCPFingerprintData) string {
	// Check for Windows (no timestamp option)
	hasTimestamp := slices.Contains(data.Options, 8)

	if !hasTimestamp {
		return "Windows (no timestamp option)"
	}

	// Check for iOS (ends with option 0)
	if len(data.Options) > 0 && data.Options[len(data.Options)-1] == 0 {
		return "iOS (ends with EOL)"
	}

	// Check for common Unix patterns
	if data.WindowSize == 65535 {
		return "macOS/BSD"
	}

	return "Unix/Linux"
}
