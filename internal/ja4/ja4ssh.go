/*
 * NETCAP - Traffic Analysis Framework
 * Copyright (c) Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
 * License: GNU General Public License v3.0
 *
 * JA4SSH SSH fingerprinting is licensed under the FoxIO License 1.1
 * Reference: https://github.com/FoxIO-LLC/ja4
 */

package ja4

import (
	"fmt"
	"strings"
)

// DefaultSSHSampleSize is the number of packets to sample for JA4SSH
const DefaultSSHSampleSize = 200

// SSHStreamData contains the data needed to compute JA4SSH fingerprints
type SSHStreamData struct {
	// Client packet payload lengths and their counts
	ClientPayloadCounts map[int]int
	// Server packet payload lengths and their counts
	ServerPayloadCounts map[int]int
	// Number of SSH packets from client
	ClientSSHPackets int
	// Number of SSH packets from server
	ServerSSHPackets int
	// Number of bare ACK packets from client
	ClientACKs int
	// Number of bare ACK packets from server
	ServerACKs int
}

// NewSSHStreamData creates a new SSHStreamData instance
func NewSSHStreamData() *SSHStreamData {
	return &SSHStreamData{
		ClientPayloadCounts: make(map[int]int),
		ServerPayloadCounts: make(map[int]int),
	}
}

// AddClientPacket records a client SSH packet
func (s *SSHStreamData) AddClientPacket(payloadLen int) {
	s.ClientPayloadCounts[payloadLen]++
	s.ClientSSHPackets++
}

// AddServerPacket records a server SSH packet
func (s *SSHStreamData) AddServerPacket(payloadLen int) {
	s.ServerPayloadCounts[payloadLen]++
	s.ServerSSHPackets++
}

// AddClientACK records a client bare ACK
func (s *SSHStreamData) AddClientACK() {
	s.ClientACKs++
}

// AddServerACK records a server bare ACK
func (s *SSHStreamData) AddServerACK() {
	s.ServerACKs++
}

// TotalPackets returns the total number of SSH packets seen
func (s *SSHStreamData) TotalPackets() int {
	return s.ClientSSHPackets + s.ServerSSHPackets
}

// ComputeJA4SSH computes the JA4SSH fingerprint for an SSH session
// Format: c{mode_client}s{mode_server}_c{client_packets}s{server_packets}_c{client_acks}s{server_acks}
// Example: c76s76_c71s59_c0s70
func ComputeJA4SSH(data *SSHStreamData) string {
	// Calculate mode (most frequent payload length) for client and server
	clientMode := calculateMode(data.ClientPayloadCounts)
	serverMode := calculateMode(data.ServerPayloadCounts)

	return fmt.Sprintf("c%ds%d_c%ds%d_c%ds%d",
		clientMode, serverMode,
		data.ClientSSHPackets, data.ServerSSHPackets,
		data.ClientACKs, data.ServerACKs,
	)
}

// calculateMode finds the payload length that appears most frequently
// If there's a tie, the smaller length wins
func calculateMode(counts map[int]int) int {
	if len(counts) == 0 {
		return 0
	}

	maxCount := 0
	mode := 0

	for length, count := range counts {
		if count > maxCount || (count == maxCount && length < mode) {
			maxCount = count
			mode = length
		}
	}

	return mode
}

// ValidateJA4SSH checks if a JA4SSH fingerprint has the correct format
func ValidateJA4SSH(fingerprint string) bool {
	parts := strings.Split(fingerprint, "_")
	if len(parts) != 3 {
		return false
	}
	// Each part should start with 'c' and contain 's'
	for _, part := range parts {
		if !strings.HasPrefix(part, "c") || !strings.Contains(part, "s") {
			return false
		}
	}
	return true
}

// ParseJA4SSH parses a JA4SSH fingerprint into its components
func ParseJA4SSH(fingerprint string) (clientMode, serverMode, clientPkts, serverPkts, clientACKs, serverACKs int, ok bool) {
	parts := strings.Split(fingerprint, "_")
	if len(parts) != 3 {
		return 0, 0, 0, 0, 0, 0, false
	}

	// Parse first part: c{mode_client}s{mode_server}
	n, err := fmt.Sscanf(parts[0], "c%ds%d", &clientMode, &serverMode)
	if err != nil || n != 2 {
		return 0, 0, 0, 0, 0, 0, false
	}

	// Parse second part: c{client_packets}s{server_packets}
	n, err = fmt.Sscanf(parts[1], "c%ds%d", &clientPkts, &serverPkts)
	if err != nil || n != 2 {
		return 0, 0, 0, 0, 0, 0, false
	}

	// Parse third part: c{client_acks}s{server_acks}
	n, err = fmt.Sscanf(parts[2], "c%ds%d", &clientACKs, &serverACKs)
	if err != nil || n != 2 {
		return 0, 0, 0, 0, 0, 0, false
	}

	return clientMode, serverMode, clientPkts, serverPkts, clientACKs, serverACKs, true
}

// DetectSessionType analyzes JA4SSH fingerprint to detect session type
func DetectSessionType(fingerprint string) string {
	clientMode, serverMode, clientPkts, serverPkts, _, _, ok := ParseJA4SSH(fingerprint)
	if !ok {
		return "unknown"
	}

	// Idle session: low packet counts with similar small modes
	if clientPkts < 10 && serverPkts < 10 {
		return "idle"
	}

	// Interactive shell: similar client/server modes around 36-100 bytes
	if clientMode >= 36 && clientMode <= 100 && serverMode >= 36 && serverMode <= 100 {
		if abs(clientPkts-serverPkts) < clientPkts/2 {
			return "interactive"
		}
	}

	// File transfer (SCP/SFTP): one side has much larger mode (check first before reverse shell)
	if clientMode > 1000 || serverMode > 1000 {
		if clientMode > serverMode*10 {
			return "file_upload"
		}
		if serverMode > clientMode*10 {
			return "file_download"
		}
		return "file_transfer"
	}

	// Reverse shell: high server mode, low client mode, more server packets
	// Only check this after ruling out file transfer
	if serverMode > clientMode*2 && serverPkts > clientPkts*2 {
		return "reverse_shell"
	}

	return "normal"
}

func abs(x int) int {
	if x < 0 {
		return -x
	}
	return x
}

// IsPotentialReverseShell checks if the JA4SSH pattern suggests a reverse shell
func IsPotentialReverseShell(fingerprint string) bool {
	sessionType := DetectSessionType(fingerprint)
	return sessionType == "reverse_shell"
}
