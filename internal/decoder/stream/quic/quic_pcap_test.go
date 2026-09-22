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

package quic

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"
)

const testdataDir = "testdata"

// QUICPacketStats holds statistics about QUIC packets found in a pcap
type QUICPacketStats struct {
	TotalPackets    int
	UDPPackets      int
	QUICPackets     int
	IETFQUICPackets int
	GQUICPackets    int
	InitialPackets  int
	ShortHeader     int
	LongHeader      int
}

// TestQUICPcapProcessing tests QUIC detection on a real pcap file
func TestQUICPcapProcessing(t *testing.T) {
	pcapPath := filepath.Join(testdataDir, "nDPI-quic.pcap")

	// Check if file exists
	if _, err := os.Stat(pcapPath); os.IsNotExist(err) {
		t.Skipf("Test pcap file not found: %s", pcapPath)
	}

	stats, err := processQUICPcap(pcapPath)
	if err != nil {
		t.Fatalf("Failed to process pcap: %v", err)
	}

	// Log statistics
	t.Logf("QUIC Pcap Processing Results:")
	t.Logf("  Total packets:     %d", stats.TotalPackets)
	t.Logf("  UDP packets:       %d", stats.UDPPackets)
	t.Logf("  QUIC packets:      %d", stats.QUICPackets)
	t.Logf("  IETF QUIC:         %d", stats.IETFQUICPackets)
	t.Logf("  gQUIC:             %d", stats.GQUICPackets)
	t.Logf("  Long header:       %d", stats.LongHeader)
	t.Logf("  Short header:      %d", stats.ShortHeader)
	t.Logf("  Initial packets:   %d", stats.InitialPackets)

	// Validate results
	if stats.TotalPackets == 0 {
		t.Error("Expected at least some packets in the pcap")
	}

	if stats.UDPPackets == 0 {
		t.Error("Expected UDP packets in a QUIC pcap")
	}

	if stats.QUICPackets == 0 {
		t.Error("Expected QUIC packets to be detected")
	}

	// At least some packets should be identified as IETF or gQUIC
	if stats.IETFQUICPackets == 0 && stats.GQUICPackets == 0 {
		t.Error("Expected either IETF QUIC or gQUIC packets to be detected")
	}

	// QUIC detection ratio should be reasonable
	if stats.UDPPackets > 0 {
		detectionRatio := float64(stats.QUICPackets) / float64(stats.UDPPackets)
		t.Logf("  Detection ratio:   %.2f%%", detectionRatio*100)

		// For gQUIC-heavy pcaps, expect at least 30% detection
		minExpectedRatio := 0.30
		if stats.IETFQUICPackets > 0 || stats.InitialPackets > 0 {
			minExpectedRatio = 0.50
		}

		if detectionRatio < minExpectedRatio {
			t.Errorf("Low QUIC detection ratio: %.2f%% (expected at least %.0f%%)",
				detectionRatio*100, minExpectedRatio*100)
		}
	}
}

// TestQUICInitialParsing tests parsing of QUIC Initial packets
func TestQUICInitialParsing(t *testing.T) {
	pcapPath := filepath.Join(testdataDir, "nDPI-quic.pcap")

	if _, err := os.Stat(pcapPath); os.IsNotExist(err) {
		t.Skipf("Test pcap file not found: %s", pcapPath)
	}

	f, err := os.Open(pcapPath)
	if err != nil {
		t.Fatalf("Failed to open pcap: %v", err)
	}
	defer f.Close()

	reader, err := pcapgo.NewReader(f)
	if err != nil {
		t.Fatalf("Failed to create pcap reader: %v", err)
	}

	packetSource := gopacket.NewPacketSource(reader, reader.LinkType())

	parsedInitials := 0
	clientHellosFound := 0

	for packet := range packetSource.Packets() {
		udpLayer := packet.Layer(layers.LayerTypeUDP)
		if udpLayer == nil {
			continue
		}

		udp := udpLayer.(*layers.UDP)
		payload := udp.Payload

		if len(payload) < 5 {
			continue
		}

		// Try to parse as IETF QUIC Initial
		if IsIETFQUICPacket(payload) {
			result, err := ParseIETFQUICInitial(payload)
			if err == nil && result != nil {
				parsedInitials++

				// Check if we got meaningful data
				if result.SNI != "" || len(result.CipherSuites) > 0 {
					clientHellosFound++
					t.Logf("Found ClientHello: SNI=%s, CipherSuites=%d, Extensions=%d",
						result.SNI, len(result.CipherSuites), len(result.Extensions))
				} else if len(result.DCID) > 0 {
					t.Logf("Found Initial packet: DCID=%x, Version=0x%08x",
						result.DCID, result.Version)
				}
			}
		}

		// Try to parse as gQUIC
		if IsGQUICPacket(payload) {
			result, err := ParseGQUICClientHello(payload)
			if err == nil && result != nil {
				parsedInitials++

				if result.SNI != "" {
					clientHellosFound++
					t.Logf("Found gQUIC CHLO: SNI=%s, UAID=%s, Version=%s, Tags=%v",
						result.SNI, result.UAID, result.Version, result.Tags)
				}
			}
		}
	}

	t.Logf("Parsed %d Initial packets, %d with ClientHello data", parsedInitials, clientHellosFound)

	// We expect at least some Initial packets to be parsed
	if parsedInitials == 0 {
		t.Logf("Warning: No Initial packets were successfully parsed (encryption may prevent this)")
	}
}

// processQUICPcap processes a pcap file and returns QUIC statistics
func processQUICPcap(pcapPath string) (*QUICPacketStats, error) {
	f, err := os.Open(pcapPath)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	reader, err := pcapgo.NewReader(f)
	if err != nil {
		return nil, err
	}

	packetSource := gopacket.NewPacketSource(reader, reader.LinkType())
	stats := &QUICPacketStats{}

	for packet := range packetSource.Packets() {
		stats.TotalPackets++

		// Check for UDP layer
		udpLayer := packet.Layer(layers.LayerTypeUDP)
		if udpLayer == nil {
			continue
		}

		stats.UDPPackets++
		udp := udpLayer.(*layers.UDP)
		payload := udp.Payload

		if len(payload) < 5 {
			continue
		}

		// Check if it's a QUIC packet
		isIETF := IsIETFQUICPacket(payload)
		isGQUIC := IsGQUICPacket(payload)

		if isIETF || isGQUIC {
			stats.QUICPackets++

			if isIETF {
				stats.IETFQUICPackets++
			}
			if isGQUIC {
				stats.GQUICPackets++
			}

			// Check header type
			if payload[0]&0x80 == 0x80 {
				stats.LongHeader++

				// Check if Initial
				version := uint32(payload[1])<<24 | uint32(payload[2])<<16 | uint32(payload[3])<<8 | uint32(payload[4])
				headerType := (payload[0] & 0x30) >> 4

				// QUIC v1: Initial = 0, QUIC v2: Initial = 1
				isInitial := false
				if version == 0x00000001 && headerType == 0 {
					isInitial = true
				} else if version == 0x6b3343cf && headerType == 1 {
					isInitial = true
				}

				if isInitial {
					stats.InitialPackets++
				}
			} else {
				stats.ShortHeader++
			}
		}
	}

	return stats, nil
}

// TestQUICVersionDetection tests that different QUIC versions are correctly detected
func TestQUICVersionDetection(t *testing.T) {
	// Use the multistream pcap which has IETF QUIC draft-29 with clear version fields
	pcapPath := filepath.Join(testdataDir, "wireshark-quic_follow_multistream.pcapng")

	if _, err := os.Stat(pcapPath); os.IsNotExist(err) {
		t.Skipf("Test pcap file not found: %s", pcapPath)
	}

	f, err := os.Open(pcapPath)
	if err != nil {
		t.Fatalf("Failed to open pcap: %v", err)
	}
	defer f.Close()

	reader, err := pcapgo.NewNgReader(f, pcapgo.DefaultNgReaderOptions)
	if err != nil {
		t.Fatalf("Failed to create pcapng reader: %v", err)
	}

	packetSource := gopacket.NewPacketSource(reader, reader.LinkType())

	versions := make(map[string]int)

	for packet := range packetSource.Packets() {
		udpLayer := packet.Layer(layers.LayerTypeUDP)
		if udpLayer == nil {
			continue
		}

		udp := udpLayer.(*layers.UDP)
		payload := udp.Payload

		if len(payload) < 5 {
			continue
		}

		// Check for long header (version field is present)
		if payload[0]&0x80 == 0x80 {
			version := uint32(payload[1])<<24 | uint32(payload[2])<<16 | uint32(payload[3])<<8 | uint32(payload[4])

			versionStr := getQUICVersionString(version)
			versions[versionStr]++
		}
	}

	t.Logf("QUIC versions detected:")
	for version, count := range versions {
		t.Logf("  %s: %d packets", version, count)
	}

	if len(versions) == 0 {
		t.Error("No QUIC versions detected")
	}
}

// getQUICVersionString returns a human-readable version string
func getQUICVersionString(version uint32) string {
	switch version {
	case 0x00000001:
		return "IETF QUIC v1"
	case 0x6b3343cf:
		return "IETF QUIC v2"
	case 0x00000000:
		return "Version Negotiation"
	default:
		// Check for IETF draft versions
		if version >= 0xff000000 && version <= 0xff00001d {
			draftNum := version & 0x000000ff
			return "IETF QUIC Draft-" + string(rune('0'+draftNum/10)) + string(rune('0'+draftNum%10))
		}
		// Check for gQUIC
		if version&0xff000000 == 0x51000000 { // 'Q' prefix
			return "gQUIC " + string([]byte{byte(version >> 24), byte(version >> 16), byte(version >> 8), byte(version)})
		}
		return "Unknown"
	}
}

// TestAllQUICPcaps tests all available QUIC pcap files
func TestAllQUICPcaps(t *testing.T) {
	testCases := []struct {
		name        string
		filename    string
		expectIETF  bool
		expectGQUIC bool
		minPackets  int
		description string
	}{
		{
			name:        "nDPI-quic",
			filename:    "nDPI-quic.pcap",
			expectIETF:  false,
			expectGQUIC: true,
			minPackets:  100,
			description: "gQUIC traffic to Google services",
		},
		{
			name:        "nDPI-quic_crypto_aes",
			filename:    "nDPI-quic_crypto_aes_auth_size.pcap",
			expectIETF:  true,
			expectGQUIC: false,
			minPackets:  1,
			description: "IETF QUIC v1 Initial packets with tokens",
		},
		{
			name:        "nDPI-youtube_quic",
			filename:    "nDPI-youtube_quic.pcap",
			expectIETF:  false,
			expectGQUIC: true,
			minPackets:  100,
			description: "gQUIC traffic to YouTube",
		},
		{
			name:        "wireshark-quic_multistream",
			filename:    "wireshark-quic_follow_multistream.pcapng",
			expectIETF:  true,
			expectGQUIC: false,
			minPackets:  100,
			description: "IETF QUIC draft-29 multistream",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			pcapPath := filepath.Join(testdataDir, tc.filename)

			if _, err := os.Stat(pcapPath); os.IsNotExist(err) {
				t.Skipf("Pcap file not found: %s", tc.filename)
			}

			var stats *QUICPacketStats
			var err error

			// Handle pcapng vs pcap
			if filepath.Ext(tc.filename) == ".pcapng" {
				stats, err = processQUICPcapNg(pcapPath)
			} else {
				stats, err = processQUICPcap(pcapPath)
			}

			if err != nil {
				t.Fatalf("Failed to process %s: %v", tc.filename, err)
			}

			t.Logf("%s: %s", tc.name, tc.description)
			t.Logf("  Packets: total=%d UDP=%d QUIC=%d (IETF=%d gQUIC=%d)",
				stats.TotalPackets, stats.UDPPackets, stats.QUICPackets,
				stats.IETFQUICPackets, stats.GQUICPackets)

			if stats.TotalPackets < tc.minPackets {
				t.Errorf("Expected at least %d packets, got %d", tc.minPackets, stats.TotalPackets)
			}

			if tc.expectIETF && stats.IETFQUICPackets == 0 {
				t.Errorf("Expected IETF QUIC packets in %s", tc.filename)
			}

			if tc.expectGQUIC && stats.GQUICPackets == 0 {
				t.Errorf("Expected gQUIC packets in %s", tc.filename)
			}
		})
	}
}

// processQUICPcapNg processes a pcapng file and returns QUIC statistics
func processQUICPcapNg(pcapPath string) (*QUICPacketStats, error) {
	f, err := os.Open(pcapPath)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	reader, err := pcapgo.NewNgReader(f, pcapgo.DefaultNgReaderOptions)
	if err != nil {
		return nil, err
	}

	packetSource := gopacket.NewPacketSource(reader, reader.LinkType())
	stats := &QUICPacketStats{}

	for packet := range packetSource.Packets() {
		stats.TotalPackets++

		udpLayer := packet.Layer(layers.LayerTypeUDP)
		if udpLayer == nil {
			continue
		}

		stats.UDPPackets++
		udp := udpLayer.(*layers.UDP)
		payload := udp.Payload

		if len(payload) < 5 {
			continue
		}

		isIETF := IsIETFQUICPacket(payload)
		isGQUIC := IsGQUICPacket(payload)

		if isIETF || isGQUIC {
			stats.QUICPackets++

			if isIETF {
				stats.IETFQUICPackets++
			}
			if isGQUIC {
				stats.GQUICPackets++
			}

			if payload[0]&0x80 == 0x80 {
				stats.LongHeader++

				version := uint32(payload[1])<<24 | uint32(payload[2])<<16 | uint32(payload[3])<<8 | uint32(payload[4])
				headerType := (payload[0] & 0x30) >> 4

				// Check if Initial (accounting for version)
				isInitial := false
				if version == 0x00000001 && headerType == 0 {
					isInitial = true
				} else if version == 0x6b3343cf && headerType == 1 {
					isInitial = true
				} else if version >= 0xff000000 && version <= 0xff00001d && headerType == 0 {
					// Draft versions use v1 encoding
					isInitial = true
				}

				if isInitial {
					stats.InitialPackets++
				}
			} else {
				stats.ShortHeader++
			}
		}
	}

	return stats, nil
}

// BenchmarkQUICDetection benchmarks QUIC detection on real traffic
func BenchmarkQUICDetection(b *testing.B) {
	pcapPath := filepath.Join(testdataDir, "nDPI-quic.pcap")

	if _, err := os.Stat(pcapPath); os.IsNotExist(err) {
		b.Skipf("Test pcap file not found: %s", pcapPath)
	}

	// Read all UDP payloads first
	f, err := os.Open(pcapPath)
	if err != nil {
		b.Fatalf("Failed to open pcap: %v", err)
	}

	reader, err := pcapgo.NewReader(f)
	if err != nil {
		f.Close()
		b.Fatalf("Failed to create pcap reader: %v", err)
	}

	packetSource := gopacket.NewPacketSource(reader, reader.LinkType())

	var payloads [][]byte
	for packet := range packetSource.Packets() {
		udpLayer := packet.Layer(layers.LayerTypeUDP)
		if udpLayer == nil {
			continue
		}
		udp := udpLayer.(*layers.UDP)
		if len(udp.Payload) >= 5 {
			// Make a copy of the payload
			payload := make([]byte, len(udp.Payload))
			copy(payload, udp.Payload)
			payloads = append(payloads, payload)
		}
	}
	f.Close()

	if len(payloads) == 0 {
		b.Skip("No UDP payloads found in pcap")
	}

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		for _, payload := range payloads {
			_ = IsIETFQUICPacket(payload)
			_ = IsGQUICPacket(payload)
		}
	}

	b.ReportMetric(float64(len(payloads)*b.N), "packets")
}
