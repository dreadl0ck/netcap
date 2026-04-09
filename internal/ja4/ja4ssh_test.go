/*
 * NETCAP - Traffic Analysis Framework
 * Copyright (c) Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
 * License: GNU General Public License v3.0
 */

package ja4

import (
	"testing"
)

func TestComputeJA4SSH(t *testing.T) {
	tests := []struct {
		name     string
		data     *SSHStreamData
		expected string
	}{
		{
			name: "Interactive session",
			data: &SSHStreamData{
				ClientPayloadCounts: map[int]int{76: 71, 52: 20, 36: 10},
				ServerPayloadCounts: map[int]int{76: 59, 52: 30, 100: 10},
				ClientSSHPackets:    71,
				ServerSSHPackets:    59,
				ClientACKs:          0,
				ServerACKs:          70,
			},
			expected: "c76s76_c71s59_c0s70",
		},
		{
			name: "File transfer session",
			data: &SSHStreamData{
				ClientPayloadCounts: map[int]int{36: 5, 1400: 100},
				ServerPayloadCounts: map[int]int{36: 10, 52: 5},
				ClientSSHPackets:    105,
				ServerSSHPackets:    15,
				ClientACKs:          10,
				ServerACKs:          100,
			},
			expected: "c1400s36_c105s15_c10s100",
		},
		{
			name: "Empty session",
			data: &SSHStreamData{
				ClientPayloadCounts: map[int]int{},
				ServerPayloadCounts: map[int]int{},
				ClientSSHPackets:    0,
				ServerSSHPackets:    0,
				ClientACKs:          0,
				ServerACKs:          0,
			},
			expected: "c0s0_c0s0_c0s0",
		},
		{
			name: "Reverse shell pattern",
			data: &SSHStreamData{
				ClientPayloadCounts: map[int]int{36: 10},
				ServerPayloadCounts: map[int]int{500: 100},
				ClientSSHPackets:    10,
				ServerSSHPackets:    100,
				ClientACKs:          5,
				ServerACKs:          50,
			},
			expected: "c36s500_c10s100_c5s50",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ComputeJA4SSH(tt.data)
			if result != tt.expected {
				t.Errorf("ComputeJA4SSH() = %q, want %q", result, tt.expected)
			}
		})
	}
}

func TestSSHStreamDataAddMethods(t *testing.T) {
	data := NewSSHStreamData()

	// Add some packets
	data.AddClientPacket(76)
	data.AddClientPacket(76)
	data.AddClientPacket(52)
	data.AddServerPacket(76)
	data.AddServerPacket(100)
	data.AddClientACK()
	data.AddServerACK()
	data.AddServerACK()

	if data.ClientSSHPackets != 3 {
		t.Errorf("ClientSSHPackets = %d, want 3", data.ClientSSHPackets)
	}
	if data.ServerSSHPackets != 2 {
		t.Errorf("ServerSSHPackets = %d, want 2", data.ServerSSHPackets)
	}
	if data.ClientACKs != 1 {
		t.Errorf("ClientACKs = %d, want 1", data.ClientACKs)
	}
	if data.ServerACKs != 2 {
		t.Errorf("ServerACKs = %d, want 2", data.ServerACKs)
	}
	if data.TotalPackets() != 5 {
		t.Errorf("TotalPackets() = %d, want 5", data.TotalPackets())
	}
}

func TestCalculateMode(t *testing.T) {
	tests := []struct {
		name   string
		counts map[int]int
		mode   int
	}{
		{
			name:   "Single value",
			counts: map[int]int{76: 100},
			mode:   76,
		},
		{
			name:   "Multiple values, clear winner",
			counts: map[int]int{36: 10, 76: 100, 52: 50},
			mode:   76,
		},
		{
			name:   "Tie - smaller value wins",
			counts: map[int]int{100: 50, 50: 50},
			mode:   50,
		},
		{
			name:   "Empty",
			counts: map[int]int{},
			mode:   0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := calculateMode(tt.counts)
			if result != tt.mode {
				t.Errorf("calculateMode() = %d, want %d", result, tt.mode)
			}
		})
	}
}

func TestValidateJA4SSH(t *testing.T) {
	tests := []struct {
		fingerprint string
		valid       bool
	}{
		{"c76s76_c71s59_c0s70", true},
		{"c0s0_c0s0_c0s0", true},
		{"c1400s36_c105s15_c10s100", true},
		{"invalid", false},
		{"c76s76_c71s59", false},      // Missing part
		{"76s76_c71s59_c0s70", false}, // Missing 'c' prefix
		{"", false},
	}

	for _, tt := range tests {
		t.Run(tt.fingerprint, func(t *testing.T) {
			result := ValidateJA4SSH(tt.fingerprint)
			if result != tt.valid {
				t.Errorf("ValidateJA4SSH(%q) = %v, want %v", tt.fingerprint, result, tt.valid)
			}
		})
	}
}

func TestParseJA4SSH(t *testing.T) {
	clientMode, serverMode, clientPkts, serverPkts, clientACKs, serverACKs, ok := ParseJA4SSH("c76s76_c71s59_c0s70")
	if !ok {
		t.Fatal("ParseJA4SSH failed")
	}
	if clientMode != 76 {
		t.Errorf("clientMode = %d, want 76", clientMode)
	}
	if serverMode != 76 {
		t.Errorf("serverMode = %d, want 76", serverMode)
	}
	if clientPkts != 71 {
		t.Errorf("clientPkts = %d, want 71", clientPkts)
	}
	if serverPkts != 59 {
		t.Errorf("serverPkts = %d, want 59", serverPkts)
	}
	if clientACKs != 0 {
		t.Errorf("clientACKs = %d, want 0", clientACKs)
	}
	if serverACKs != 70 {
		t.Errorf("serverACKs = %d, want 70", serverACKs)
	}
}

func TestDetectSessionType(t *testing.T) {
	tests := []struct {
		fingerprint string
		sessionType string
	}{
		{"c76s76_c71s59_c0s70", "interactive"},
		{"c36s500_c10s100_c5s50", "reverse_shell"},
		{"c1400s36_c105s15_c10s100", "file_upload"},
		{"c36s1400_c15s105_c100s10", "file_download"},
		{"c36s36_c5s5_c2s2", "idle"},
		{"invalid", "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.fingerprint, func(t *testing.T) {
			result := DetectSessionType(tt.fingerprint)
			if result != tt.sessionType {
				t.Errorf("DetectSessionType(%q) = %q, want %q", tt.fingerprint, result, tt.sessionType)
			}
		})
	}
}

func TestIsPotentialReverseShell(t *testing.T) {
	tests := []struct {
		fingerprint  string
		reverseShell bool
	}{
		{"c36s500_c10s100_c5s50", true},
		{"c76s76_c71s59_c0s70", false},
		{"c1400s36_c105s15_c10s100", false},
	}

	for _, tt := range tests {
		t.Run(tt.fingerprint, func(t *testing.T) {
			result := IsPotentialReverseShell(tt.fingerprint)
			if result != tt.reverseShell {
				t.Errorf("IsPotentialReverseShell(%q) = %v, want %v", tt.fingerprint, result, tt.reverseShell)
			}
		})
	}
}
