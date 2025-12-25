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

package cip

import (
	"encoding/binary"
	"os"
	"testing"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"
)

// Sample ENIP/CIP packet data from pcaps/cip.pcap
// This is the TCP payload of the first packet (58 bytes)
var sampleENIPCIPRequest = []byte{
	// ENIP Header (24 bytes)
	0x6f, 0x00, // Command: SendRRData (0x006F)
	0x22, 0x00, // Length: 34 bytes
	0x44, 0x55, 0x8b, 0x88, // Session Handle
	0x00, 0x00, 0x00, 0x00, // Status: Success
	0x51, 0xc9, 0x0e, 0x00, 0x20, 0xcc, 0xd7, 0x00, // Sender Context (8 bytes)
	0x00, 0x00, 0x00, 0x00, // Options

	// SendRRData Command Specific Data (34 bytes)
	0x00, 0x00, 0x00, 0x00, // Interface Handle
	0x0a, 0x00, // Timeout: 10
	0x02, 0x00, // Item Count: 2

	// Item 1: Null Address (4 bytes)
	0x00, 0x00, // Type: Null Address Item (0x0000)
	0x00, 0x00, // Length: 0

	// Item 2: Unconnected Data (4 + 18 bytes)
	0xb2, 0x00, // Type: Unconnected Data Item (0x00B2)
	0x12, 0x00, // Length: 18 bytes

	// CIP Request Data (18 bytes)
	0x4b,       // Service: Execute PCCC (0x4B)
	0x02,       // Path Size: 2 words
	0x20, 0x67, // Path Segment: Class 0x67 (PCCC)
	0x24, 0x01, // Path Segment: Instance 0x01
	0x07, 0x4d, 0x00, 0xd3, 0x23, 0xaa, // PCCC data
	0x07, 0x06, 0x00, 0xd7, 0xb1, 0x03, // More PCCC data
}

// Sample ENIP/CIP response packet
var sampleENIPCIPResponse = []byte{
	// ENIP Header (24 bytes)
	0x6f, 0x00, // Command: SendRRData (0x006F)
	0x38, 0x00, // Length: 56 bytes
	0x44, 0x55, 0x8b, 0x88, // Session Handle
	0x00, 0x00, 0x00, 0x00, // Status: Success
	0x51, 0xc9, 0x0e, 0x00, 0x20, 0xcc, 0xd7, 0x00, // Sender Context
	0x00, 0x00, 0x00, 0x00, // Options

	// SendRRData Command Specific Data
	0x00, 0x00, 0x00, 0x00, // Interface Handle
	0x00, 0x04, // Timeout
	0x02, 0x00, // Item Count: 2

	// Item 1: Null Address (4 bytes)
	0x00, 0x00, // Type: Null Address Item
	0x00, 0x00, // Length: 0

	// Item 2: Unconnected Data (4 + 40 bytes)
	0xb2, 0x00, // Type: Unconnected Data Item
	0x28, 0x00, // Length: 40 bytes

	// CIP Response Data (40 bytes)
	0xcb, 0x00, // Service: 0xCB (Execute PCCC Response = 0x4B | 0x80)
	0x00, 0x00, // Reserved + Status (Success)
	// ... more response data
	0x07, 0x4d, 0x00, 0xd3, 0x23, 0xaa,
	0x07, 0x46, 0x00, 0xd7, 0xb1, 0x00,
	0xee, 0x4a, 0x9c, 0x23,
	0x31, 0x37, 0x36, 0x33, 0x2d, 0x4c, 0x45, 0x43,
	0x20, 0x20, 0x20, 0x00, 0x00, 0x26, 0x00, 0x78,
	0x1a, 0x30, 0xfc, 0x01,
}

func TestCanDecodeENIP(t *testing.T) {
	tests := []struct {
		name     string
		data     []byte
		expected bool
	}{
		{
			name:     "Valid ENIP SendRRData request",
			data:     sampleENIPCIPRequest,
			expected: true,
		},
		{
			name:     "Valid ENIP SendRRData response",
			data:     sampleENIPCIPResponse,
			expected: true,
		},
		{
			name:     "Too short for ENIP",
			data:     []byte{0x6f, 0x00, 0x22, 0x00},
			expected: false,
		},
		{
			name:     "Invalid ENIP command",
			data:     make([]byte, 30),
			expected: false,
		},
		{
			name:     "Empty data",
			data:     []byte{},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := canDecodeENIP(tt.data)
			if result != tt.expected {
				t.Errorf("canDecodeENIP() = %v, expected %v", result, tt.expected)
			}
		})
	}
}

func TestCanDecodeCIP(t *testing.T) {
	tests := []struct {
		name     string
		data     []byte
		expected bool
	}{
		{
			name:     "ENIP encapsulated CIP request",
			data:     sampleENIPCIPRequest,
			expected: true,
		},
		{
			name:     "ENIP encapsulated CIP response",
			data:     sampleENIPCIPResponse,
			expected: true,
		},
		{
			// Raw CIP without ENIP encapsulation is no longer detected to avoid false positives
			// CIP detection now requires ENIP encapsulation for reliability
			name:     "Raw CIP request (Get Attribute All) - not detected without ENIP",
			data:     []byte{0x01, 0x02, 0x20, 0x01, 0x24, 0x01},
			expected: false,
		},
		{
			// Raw CIP without ENIP encapsulation is no longer detected to avoid false positives
			name:     "Raw CIP response - not detected without ENIP",
			data:     []byte{0x81, 0x00, 0x00, 0x00},
			expected: false,
		},
		{
			name:     "Too short",
			data:     []byte{0x01, 0x02},
			expected: false,
		},
		{
			name:     "Empty",
			data:     []byte{},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := canDecodeCIP(tt.data)
			if result != tt.expected {
				t.Errorf("canDecodeCIP() = %v, expected %v", result, tt.expected)
			}
		})
	}
}

func TestCIPReaderParseCIPRequest(t *testing.T) {
	// CIP Request: Service 0x4B, Path Size 2, Class 0x67, Instance 0x01
	cipRequest := []byte{
		0x4b,       // Service: Execute PCCC
		0x02,       // Path Size: 2 words
		0x20, 0x67, // Class: 0x67 (PCCC)
		0x24, 0x01, // Instance: 0x01
		0x07, 0x4d, 0x00, 0xd3, 0x23, 0xaa, // Data
	}

	reader := &cipReader{}
	msg, consumed := reader.parseCIPRequest(cipRequest)

	if msg == nil {
		t.Fatal("parseCIPRequest returned nil message")
	}

	if msg.Response {
		t.Error("Expected Response=false for CIP request")
	}

	if msg.ServiceID != 0x4B {
		t.Errorf("ServiceID = %d, expected %d", msg.ServiceID, 0x4B)
	}

	if msg.ClassID != 0x67 {
		t.Errorf("ClassID = %d, expected %d", msg.ClassID, 0x67)
	}

	if msg.InstanceID != 0x01 {
		t.Errorf("InstanceID = %d, expected %d", msg.InstanceID, 0x01)
	}

	// When parsing CIP messages from ENIP, consumed returns full message length
	// (entire data slice), not just the header size
	if consumed != len(cipRequest) {
		t.Errorf("consumed = %d, expected %d (full message length)", consumed, len(cipRequest))
	}
}

func TestCIPReaderParseCIPResponse(t *testing.T) {
	// CIP Response: Service 0xCB (0x4B | 0x80), Status 0, No additional status
	cipResponse := []byte{
		0xcb,       // Service: Execute PCCC Response
		0x00,       // Reserved
		0x00,       // Status: Success
		0x00,       // Additional Status Size: 0
		0x07, 0x4d, // Response data
	}

	reader := &cipReader{}
	msg, consumed := reader.parseCIPResponse(cipResponse)

	if msg == nil {
		t.Fatal("parseCIPResponse returned nil message")
	}

	if !msg.Response {
		t.Error("Expected Response=true for CIP response")
	}

	if msg.ServiceID != 0x4B {
		t.Errorf("ServiceID = %d, expected %d (original service without response bit)", msg.ServiceID, 0x4B)
	}

	if msg.Status != 0 {
		t.Errorf("Status = %d, expected 0", msg.Status)
	}

	// When parsing CIP messages from ENIP, consumed returns full message length
	// (entire data slice), not just the header size
	if consumed != len(cipResponse) {
		t.Errorf("consumed = %d, expected %d (full message length)", consumed, len(cipResponse))
	}
}

func TestCIPReaderParseEPATH(t *testing.T) {
	tests := []struct {
		name          string
		pathData      []byte
		expectedClass uint32
		expectedInst  uint32
	}{
		{
			name:          "8-bit Class and Instance",
			pathData:      []byte{0x20, 0x67, 0x24, 0x01},
			expectedClass: 0x67,
			expectedInst:  0x01,
		},
		{
			name:          "8-bit Class only",
			pathData:      []byte{0x20, 0x02},
			expectedClass: 0x02,
			expectedInst:  0,
		},
		{
			name:          "16-bit Class (with padding)",
			pathData:      []byte{0x21, 0x00, 0x67, 0x00, 0x24, 0x01},
			expectedClass: 0x67,
			expectedInst:  0x01,
		},
	}

	reader := &cipReader{}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			classID, instanceID := reader.parseEPATH(tt.pathData)

			if classID != tt.expectedClass {
				t.Errorf("classID = %d, expected %d", classID, tt.expectedClass)
			}

			if instanceID != tt.expectedInst {
				t.Errorf("instanceID = %d, expected %d", instanceID, tt.expectedInst)
			}
		})
	}
}

func TestCIPReaderIsENIPHeader(t *testing.T) {
	reader := &cipReader{}

	tests := []struct {
		name     string
		data     []byte
		expected bool
	}{
		{
			name:     "Valid SendRRData",
			data:     sampleENIPCIPRequest,
			expected: true,
		},
		{
			name:     "Too short",
			data:     []byte{0x6f, 0x00, 0x22, 0x00, 0x44, 0x55},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := reader.isENIPHeader(tt.data)
			if result != tt.expected {
				t.Errorf("isENIPHeader() = %v, expected %v", result, tt.expected)
			}
		})
	}
}

// TestDecoderMatchingWithRealPcapData verifies CanDecodeStream works with real pcap data
func TestDecoderMatchingWithRealPcapData(t *testing.T) {
	pcapPath := "../../../pcaps/cip.pcap"

	f, err := os.Open(pcapPath)
	if err != nil {
		t.Skipf("Test pcap file not found: %s", pcapPath)
	}
	defer f.Close()

	reader, err := pcapgo.NewReader(f)
	if err != nil {
		t.Fatalf("Failed to create pcap reader: %v", err)
	}

	packetSource := gopacket.NewPacketSource(reader, reader.LinkType())

	// Find first client and server data packets
	var (
		clientData []byte
		serverData []byte
		clientIP   string
		serverIP   string
	)

	for packet := range packetSource.Packets() {
		tcpLayer := packet.Layer(layers.LayerTypeTCP)
		if tcpLayer == nil {
			continue
		}

		tcp := tcpLayer.(*layers.TCP)
		payload := tcp.Payload
		if len(payload) == 0 {
			continue
		}

		netLayer := packet.NetworkLayer()
		if netLayer == nil {
			continue
		}

		srcIP := netLayer.NetworkFlow().Src().String()
		dstIP := netLayer.NetworkFlow().Dst().String()

		// First packet determines client/server
		if clientIP == "" {
			clientIP = srcIP
			serverIP = dstIP
		}

		if srcIP == clientIP && len(clientData) == 0 {
			clientData = payload
			t.Logf("First client data: %d bytes, first 24 bytes hex: %x", len(payload), payload[:min(24, len(payload))])
		} else if srcIP == serverIP && len(serverData) == 0 {
			serverData = payload
			t.Logf("First server data: %d bytes, first 24 bytes hex: %x", len(payload), payload[:min(24, len(payload))])
		}

		if len(clientData) > 0 && len(serverData) > 0 {
			break
		}
	}

	// Test CanDecodeStream
	if len(clientData) == 0 && len(serverData) == 0 {
		t.Fatal("No client or server data found in pcap")
	}

	t.Logf("Testing CanDecodeStream with client=%d bytes, server=%d bytes", len(clientData), len(serverData))

	// Test individual detection functions
	t.Logf("canDecodeENIP(clientData) = %v", canDecodeENIP(clientData))
	t.Logf("canDecodeENIP(serverData) = %v", canDecodeENIP(serverData))
	t.Logf("canDecodeCIP(clientData) = %v", canDecodeCIP(clientData))
	t.Logf("canDecodeCIP(serverData) = %v", canDecodeCIP(serverData))

	// Test the decoder's CanDecodeStream
	result := Decoder.CanDecodeStream(clientData, serverData)
	t.Logf("Decoder.CanDecodeStream() = %v", result)

	if !result {
		t.Error("Expected CanDecodeStream to return true for CIP pcap data")
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// TestParseMultipleENIPMessages tests parsing multiple ENIP messages in sequence
func TestParseMultipleENIPMessages(t *testing.T) {
	// Combine request and response
	combinedData := append(sampleENIPCIPRequest, sampleENIPCIPResponse...)

	reader := &cipReader{}
	offset := 0
	messageCount := 0

	for offset < len(combinedData)-4 {
		if reader.isENIPHeader(combinedData[offset:]) {
			// Parse ENIP
			if len(combinedData[offset:]) >= enipHeaderSize {
				command := binary.LittleEndian.Uint16(combinedData[offset : offset+2])
				length := binary.LittleEndian.Uint16(combinedData[offset+2 : offset+4])
				totalSize := enipHeaderSize + int(length)

				if len(combinedData[offset:]) >= totalSize {
					if command == ENIPCommandSendRRData || command == ENIPCommandSendUnitData {
						// Extract CPF data
						cpfData := combinedData[offset+enipHeaderSize : offset+totalSize]

						// Parse CPF
						if len(cpfData) >= 8 {
							itemCount := binary.LittleEndian.Uint16(cpfData[6:8])
							cpfOffset := 8

							for i := uint16(0); i < itemCount && cpfOffset+4 <= len(cpfData); i++ {
								itemType := binary.LittleEndian.Uint16(cpfData[cpfOffset : cpfOffset+2])
								itemLen := binary.LittleEndian.Uint16(cpfData[cpfOffset+2 : cpfOffset+4])
								cpfOffset += 4

								if cpfOffset+int(itemLen) > len(cpfData) {
									break
								}

								if itemType == CPFItemIDUnconnectedData || itemType == CPFItemIDConnectedData {
									cipData := cpfData[cpfOffset : cpfOffset+int(itemLen)]
									msg, _ := reader.parseCIPMessage(cipData)
									if msg != nil {
										messageCount++
										t.Logf("Message %d: Response=%v, Service=0x%02X",
											messageCount, msg.Response, msg.ServiceID)
									}
								}
								cpfOffset += int(itemLen)
							}
						}
					}
					offset += totalSize
					continue
				}
			}
		}
		offset++
	}

	if messageCount < 2 {
		t.Errorf("Expected at least 2 messages, got %d", messageCount)
	}
}

func TestDecoderCanDecodeStream(t *testing.T) {
	tests := []struct {
		name     string
		client   []byte
		server   []byte
		expected bool
	}{
		{
			name:     "Client has ENIP request",
			client:   sampleENIPCIPRequest,
			server:   []byte{},
			expected: true,
		},
		{
			name:     "Server has ENIP response",
			client:   []byte{},
			server:   sampleENIPCIPResponse,
			expected: true,
		},
		{
			name:     "Both have ENIP",
			client:   sampleENIPCIPRequest,
			server:   sampleENIPCIPResponse,
			expected: true,
		},
		{
			name:     "Neither has ENIP/CIP",
			client:   []byte("HTTP/1.1 200 OK\r\n"),
			server:   []byte("GET / HTTP/1.1\r\n"),
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := Decoder.CanDecodeStream(tt.client, tt.server)
			if result != tt.expected {
				t.Errorf("CanDecodeStream() = %v, expected %v", result, tt.expected)
			}
		})
	}
}

// TestParseCIPPcap tests parsing of CIP traffic from a real pcap file
func TestParseCIPPcap(t *testing.T) {
	pcapPath := "../../../pcaps/cip.pcap"

	f, err := os.Open(pcapPath)
	if err != nil {
		t.Skipf("Test pcap file not found: %s", pcapPath)
	}
	defer f.Close()

	reader, err := pcapgo.NewReader(f)
	if err != nil {
		t.Fatalf("Failed to create pcap reader: %v", err)
	}

	packetSource := gopacket.NewPacketSource(reader, reader.LinkType())

	var (
		totalPackets   int
		tcpPackets     int
		cipPortPackets int
		enipPackets    int
		cipRequests    int
		cipResponses   int
	)

	cipReader := &cipReader{}

	for packet := range packetSource.Packets() {
		totalPackets++

		tcpLayer := packet.Layer(layers.LayerTypeTCP)
		if tcpLayer == nil {
			continue
		}
		tcpPackets++

		tcp := tcpLayer.(*layers.TCP)
		if tcp.SrcPort != 44818 && tcp.DstPort != 44818 {
			continue
		}
		cipPortPackets++

		payload := tcp.Payload
		if len(payload) == 0 {
			continue
		}

		// Try to detect ENIP
		if canDecodeENIP(payload) {
			enipPackets++

			// Parse ENIP header
			if len(payload) >= enipHeaderSize {
				command := binary.LittleEndian.Uint16(payload[0:2])
				length := binary.LittleEndian.Uint16(payload[2:4])

				if command == ENIPCommandSendRRData || command == ENIPCommandSendUnitData {
					totalSize := enipHeaderSize + int(length)
					if len(payload) >= totalSize {
						cpfData := payload[enipHeaderSize:totalSize]

						// Parse CPF manually
						if len(cpfData) >= 8 {
							// Skip interface handle (4) and timeout (2)
							itemCount := binary.LittleEndian.Uint16(cpfData[6:8])
							offset := 8

							for i := uint16(0); i < itemCount && offset+4 <= len(cpfData); i++ {
								itemType := binary.LittleEndian.Uint16(cpfData[offset : offset+2])
								itemLen := binary.LittleEndian.Uint16(cpfData[offset+2 : offset+4])
								offset += 4

								if offset+int(itemLen) > len(cpfData) {
									break
								}

								if itemType == CPFItemIDUnconnectedData || itemType == CPFItemIDConnectedData {
									cipData := cpfData[offset : offset+int(itemLen)]

									// Parse CIP
									msg, consumed := cipReader.parseCIPMessage(cipData)
									if msg != nil {
										if msg.Response {
											cipResponses++
										} else {
											cipRequests++
										}
										t.Logf("CIP Message: Response=%v, Service=0x%02X, Class=0x%02X, Instance=0x%02X, Status=%d, Consumed=%d",
											msg.Response, msg.ServiceID, msg.ClassID, msg.InstanceID, msg.Status, consumed)
									}
								}

								offset += int(itemLen)
							}
						}
					}
				}
			}
		}
	}

	t.Logf("CIP Pcap Analysis:")
	t.Logf("  Total packets: %d", totalPackets)
	t.Logf("  TCP packets: %d", tcpPackets)
	t.Logf("  CIP port (44818) packets: %d", cipPortPackets)
	t.Logf("  ENIP packets detected: %d", enipPackets)
	t.Logf("  CIP requests: %d", cipRequests)
	t.Logf("  CIP responses: %d", cipResponses)

	if enipPackets == 0 {
		t.Error("Expected to find ENIP packets")
	}

	if cipRequests == 0 && cipResponses == 0 {
		t.Error("Expected to find CIP messages")
	}
}

func TestParseENIPAndExtractCIP(t *testing.T) {
	reader := &cipReader{}

	// Test isENIPHeader
	if !reader.isENIPHeader(sampleENIPCIPRequest) {
		t.Error("isENIPHeader should return true for valid ENIP request")
	}

	// Test parseENIPMessage - it should extract CIP from CPF
	// We need a mock writer to capture the output
	t.Run("Parse ENIP SendRRData", func(t *testing.T) {
		// Verify ENIP header parsing
		if len(sampleENIPCIPRequest) < enipHeaderSize {
			t.Fatalf("Sample data too short: %d < %d", len(sampleENIPCIPRequest), enipHeaderSize)
		}

		command := uint16(sampleENIPCIPRequest[0]) | uint16(sampleENIPCIPRequest[1])<<8
		if command != ENIPCommandSendRRData {
			t.Errorf("ENIP command = 0x%04X, expected 0x%04X (SendRRData)", command, ENIPCommandSendRRData)
		}

		length := uint16(sampleENIPCIPRequest[2]) | uint16(sampleENIPCIPRequest[3])<<8
		if length != 34 {
			t.Errorf("ENIP length = %d, expected 34", length)
		}

		totalSize := enipHeaderSize + int(length)
		if totalSize != 58 {
			t.Errorf("Total ENIP message size = %d, expected 58", totalSize)
		}

		// Verify CPF parsing
		cpfData := sampleENIPCIPRequest[enipHeaderSize:totalSize]
		t.Logf("CPF data length: %d bytes", len(cpfData))
		t.Logf("CPF data (hex): %x", cpfData)

		// CPF format for SendRRData:
		// Bytes 0-3: Interface Handle
		// Bytes 4-5: Timeout
		// Bytes 6-7: Item Count
		if len(cpfData) < 8 {
			t.Fatalf("CPF data too short: %d < 8", len(cpfData))
		}

		itemCount := uint16(cpfData[6]) | uint16(cpfData[7])<<8
		if itemCount != 2 {
			t.Errorf("CPF item count = %d, expected 2", itemCount)
		}

		// Parse items
		offset := 8
		for i := 0; i < int(itemCount); i++ {
			if offset+4 > len(cpfData) {
				t.Fatalf("Not enough data for item %d header", i)
			}

			itemType := uint16(cpfData[offset]) | uint16(cpfData[offset+1])<<8
			itemLen := uint16(cpfData[offset+2]) | uint16(cpfData[offset+3])<<8
			t.Logf("Item %d: Type=0x%04X, Length=%d", i, itemType, itemLen)

			offset += 4

			if i == 1 {
				// Second item should be Unconnected Data with CIP
				if itemType != CPFItemIDUnconnectedData {
					t.Errorf("Item 1 type = 0x%04X, expected 0x%04X (Unconnected Data)", itemType, CPFItemIDUnconnectedData)
				}

				if offset+int(itemLen) > len(cpfData) {
					t.Fatalf("Not enough data for CIP payload")
				}

				cipData := cpfData[offset : offset+int(itemLen)]
				t.Logf("CIP data (hex): %x", cipData)

				// Parse CIP request
				msg, consumed := reader.parseCIPRequest(cipData)
				if msg == nil {
					t.Error("parseCIPRequest returned nil for valid CIP data")
				} else {
					t.Logf("CIP: Service=0x%02X, ClassID=0x%02X, InstanceID=0x%02X, Consumed=%d",
						msg.ServiceID, msg.ClassID, msg.InstanceID, consumed)

					if msg.ServiceID != 0x4B {
						t.Errorf("CIP ServiceID = 0x%02X, expected 0x4B", msg.ServiceID)
					}
					if msg.ClassID != 0x67 {
						t.Errorf("CIP ClassID = 0x%02X, expected 0x67", msg.ClassID)
					}
					if msg.InstanceID != 0x01 {
						t.Errorf("CIP InstanceID = 0x%02X, expected 0x01", msg.InstanceID)
					}
				}
			}

			offset += int(itemLen)
		}
	})
}
