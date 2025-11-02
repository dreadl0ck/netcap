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

package packet

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcap"

	"github.com/dreadl0ck/netcap/decoder/config"
	"github.com/dreadl0ck/netcap/types"
)

// TestCIPDecoder_pcap tests the CIP decoder with actual pcap file
// This test investigates why CIP audit records lack CIP-specific fields
func TestCIPDecoder_pcap(t *testing.T) {
	// Initialize decoder config like the collector does
	testConfig := config.DefaultConfig
	testConfig.IncludePayloads = true
	SetConfig(testConfig)

	// Ensure ENIP/CIP layers are registered to TCP ports
	// Standard ENIP ports
	layers.RegisterTCPPortLayerType(layers.TCPPort(44818), layers.LayerTypeENIP)
	layers.RegisterTCPPortLayerType(layers.TCPPort(2222), layers.LayerTypeENIP)
	layers.RegisterUDPPortLayerType(layers.UDPPort(2222), layers.LayerTypeENIP)
	// Also register non-standard port 2430 seen in the pcap
	layers.RegisterTCPPortLayerType(layers.TCPPort(2430), layers.LayerTypeENIP)

	// Open the pcap file
	handle, err := pcap.OpenOffline("../../pcaps/cip.pcap")
	if err != nil {
		t.Fatalf("Failed to open pcap file: %v", err)
	}
	defer handle.Close()

	// Create packet source with DecodeStreamsAsDatagrams option
	// This is CRITICAL for decoding application-level protocols (ENIP/CIP) over TCP
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	packetSource.DecodeOptions = gopacket.DecodeStreamsAsDatagrams

	var (
		cipRecordsFound         int
		enipPacketsFound        int
		recordsWithCIPFields    int
		recordsWithoutCIPFields int
	)

	// Process packets
	for packet := range packetSource.Packets() {
		// Check for ENIP layer first
		enipLayer := packet.Layer(layers.LayerTypeENIP)
		if enipLayer != nil {
			enipPacketsFound++
			t.Logf("Packet #%d has ENIP layer", enipPacketsFound)

			// Inspect ENIP layer
			if enip, ok := enipLayer.(*layers.ENIP); ok {
				t.Logf("  ENIP Command: %d, Length: %d, Status: %d", enip.Command, enip.Length, enip.Status)
			}
		}

		// Check if packet has CIP layer
		cipLayer := packet.Layer(layers.LayerTypeCIP)
		if cipLayer == nil {
			continue
		}

		cipRecordsFound++

		// Inspect the raw CIP layer from gopacket
		if rawCIP, ok := cipLayer.(*layers.CIP); ok {
			t.Logf("\nCIP Record #%d (from gopacket layer):", cipRecordsFound)
			t.Logf("  Response: %v", rawCIP.Response)
			t.Logf("  Service: %d (0x%02x)", rawCIP.Service, rawCIP.Service)
			t.Logf("  ClassID: %v", rawCIP.ClassID)
			t.Logf("  InstanceID: %v", rawCIP.InstanceID)
			t.Logf("  Status: %d", rawCIP.Status)
			t.Logf("  AdditionalStatus: %v", rawCIP.AdditionalStatus)
			t.Logf("  LayerPayload length: %d", len(rawCIP.LayerPayload()))
			t.Logf("  LayerContents length: %d", len(rawCIP.LayerContents()))
		}

		// Create the audit record using the decoder handler
		timestamp := packet.Metadata().Timestamp.UnixNano()
		record := cipDecoder.Handler(cipLayer, timestamp)
		if record == nil {
			t.Error("CIP handler returned nil record")
			continue
		}

		// Cast to CIP type
		cip, ok := record.(*types.CIP)
		if !ok {
			t.Errorf("Record is not a CIP type: %T", record)
			continue
		}

		// Create PacketContext from packet layers
		ctx := createPacketContext(packet)

		// Apply the packet context
		cip.SetPacketContext(ctx)

		// Check if CIP-specific fields are populated
		hasCIPFields := cip.ServiceID != 0 || cip.ClassID != 0 || cip.InstanceID != 0 ||
			cip.Status != 0 || cip.Response || len(cip.AdditionalStatus) > 0 || len(cip.Data) > 0

		if hasCIPFields {
			recordsWithCIPFields++
			// Marshal to JSON for first few records with actual CIP data
			if recordsWithCIPFields <= 3 {
				jsonData, err := json.MarshalIndent(cip, "", "  ")
				if err != nil {
					t.Errorf("Failed to marshal CIP record to JSON: %v", err)
				} else {
					fmt.Printf("\n=== CIP Record #%d WITH CIP Fields ===\n%s\n", cipRecordsFound, string(jsonData))
				}
			}
		} else {
			recordsWithoutCIPFields++
			// Show first few empty records
			if recordsWithoutCIPFields <= 3 {
				jsonData, err := json.MarshalIndent(cip, "", "  ")
				if err != nil {
					t.Errorf("Failed to marshal CIP record to JSON: %v", err)
				} else {
					fmt.Printf("\n=== CIP Record #%d WITHOUT CIP Fields (BUG!) ===\n%s\n", cipRecordsFound, string(jsonData))
				}
			}
		}

		// Only process first 50 packets for detailed analysis
		if cipRecordsFound >= 50 {
			break
		}
	}

	t.Logf("\n=== SUMMARY ===")
	t.Logf("ENIP packets found: %d", enipPacketsFound)
	t.Logf("CIP records found: %d", cipRecordsFound)
	t.Logf("Records WITH CIP-specific fields: %d", recordsWithCIPFields)
	t.Logf("Records WITHOUT CIP-specific fields: %d (BUG!)", recordsWithoutCIPFields)

	if cipRecordsFound == 0 {
		t.Fatal("No CIP packets found in pcap file - layer registration may have failed")
	}

	if recordsWithoutCIPFields > 0 {
		t.Errorf("INVESTIGATION RESULT: %d out of %d CIP records lack CIP-specific fields!",
			recordsWithoutCIPFields, cipRecordsFound)
		t.Error("This confirms the bug: CIP audit records only contain network context (IP/Port) but no CIP protocol data")
	} else {
		t.Log("SUCCESS: All CIP records contain proper CIP-specific fields")
	}
}

// createPacketContext extracts network and transport layer information from a packet
func createPacketContext(p gopacket.Packet) *types.PacketContext {
	ctx := &types.PacketContext{}

	// Extract network layer information (IP addresses)
	if nl := p.NetworkLayer(); nl != nil {
		if nf := nl.NetworkFlow(); nf != (gopacket.Flow{}) {
			ctx.SrcIP = nf.Src().String()
			ctx.DstIP = nf.Dst().String()
		}
	}

	// Extract transport layer information (ports)
	if tl := p.TransportLayer(); tl != nil {
		if tf := tl.TransportFlow(); tf != (gopacket.Flow{}) {
			// Convert port bytes to int32
			srcPort := tf.Src().Raw()
			dstPort := tf.Dst().Raw()

			if len(srcPort) >= 2 {
				ctx.SrcPort = int32(uint16(srcPort[0])<<8 | uint16(srcPort[1]))
			}
			if len(dstPort) >= 2 {
				ctx.DstPort = int32(uint16(dstPort[0])<<8 | uint16(dstPort[1]))
			}
		}
	}

	return ctx
}

// TestCIPDecoder_withContext tests CIP decoder with proper PacketContext
func TestCIPDecoder_withContext(t *testing.T) {
	// Initialize decoder config
	testConfig := config.DefaultConfig
	testConfig.IncludePayloads = true
	SetConfig(testConfig)

	// Ensure ENIP/CIP layers are registered to TCP ports
	// Standard ENIP ports
	layers.RegisterTCPPortLayerType(layers.TCPPort(44818), layers.LayerTypeENIP)
	layers.RegisterTCPPortLayerType(layers.TCPPort(2222), layers.LayerTypeENIP)
	layers.RegisterUDPPortLayerType(layers.UDPPort(2222), layers.LayerTypeENIP)
	// Also register non-standard port 2430 seen in the pcap
	layers.RegisterTCPPortLayerType(layers.TCPPort(2430), layers.LayerTypeENIP)

	// Open the pcap file
	handle, err := pcap.OpenOffline("../../pcaps/cip.pcap")
	if err != nil {
		t.Fatalf("Failed to open pcap file: %v", err)
	}
	defer handle.Close()

	// Use DecodeStreamsAsDatagrams for application-level protocol decoding
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	packetSource.DecodeOptions = gopacket.DecodeStreamsAsDatagrams

	recordsWithContext := 0
	recordsWithoutContext := 0

	// Process packets
	for packet := range packetSource.Packets() {
		// Check if packet has CIP layer
		cipLayer := packet.Layer(layers.LayerTypeCIP)
		if cipLayer == nil {
			continue
		}

		// Create PacketContext
		ctx := createPacketContext(packet)

		if ctx.SrcIP != "" && ctx.DstIP != "" {
			recordsWithContext++
			t.Logf("Packet with context: SrcIP=%s, DstIP=%s, SrcPort=%d, DstPort=%d",
				ctx.SrcIP, ctx.DstIP, ctx.SrcPort, ctx.DstPort)
		} else {
			recordsWithoutContext++
			t.Logf("Packet without proper context")
		}
	}

	t.Logf("Records with context: %d", recordsWithContext)
	t.Logf("Records without context: %d", recordsWithoutContext)

	if recordsWithContext == 0 {
		t.Error("No CIP packets found with proper network context")
	}
}

// TestCIPDecoder_layerInspection inspects the layers in CIP packets
func TestCIPDecoder_layerInspection(t *testing.T) {
	// Initialize decoder config
	testConfig := config.DefaultConfig
	testConfig.IncludePayloads = true
	SetConfig(testConfig)

	// Ensure ENIP/CIP layers are registered to TCP ports
	// Standard ENIP ports
	layers.RegisterTCPPortLayerType(layers.TCPPort(44818), layers.LayerTypeENIP)
	layers.RegisterTCPPortLayerType(layers.TCPPort(2222), layers.LayerTypeENIP)
	layers.RegisterUDPPortLayerType(layers.UDPPort(2222), layers.LayerTypeENIP)
	// Also register non-standard port 2430 seen in the pcap
	layers.RegisterTCPPortLayerType(layers.TCPPort(2430), layers.LayerTypeENIP)

	// Open the pcap file
	handle, err := pcap.OpenOffline("../../pcaps/cip.pcap")
	if err != nil {
		t.Fatalf("Failed to open pcap file: %v", err)
	}
	defer handle.Close()

	// Use DecodeStreamsAsDatagrams - critical for TCP-based application protocols
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	packetSource.DecodeOptions = gopacket.DecodeStreamsAsDatagrams

	packetCount := 0
	cipPacketCount := 0

	// Process packets
	for packet := range packetSource.Packets() {
		packetCount++

		// List all layers in the packet
		packetLayers := packet.Layers()
		hasENIP := false
		hasCIP := false

		fmt.Printf("\n=== Packet #%d ===\n", packetCount)
		fmt.Printf("Layers (%d):\n", len(packetLayers))
		for i, layer := range packetLayers {
			layerType := layer.LayerType()
			fmt.Printf("  %d. %s\n", i+1, layerType.String())

			if layerType == layers.LayerTypeENIP {
				hasENIP = true
			}
			if layerType == layers.LayerTypeCIP {
				hasCIP = true
			}
		}

		// Check network and transport layers
		if nl := packet.NetworkLayer(); nl != nil {
			fmt.Printf("Network Layer: %s\n", nl.LayerType())
			if nf := nl.NetworkFlow(); nf != (gopacket.Flow{}) {
				fmt.Printf("  Src: %s, Dst: %s\n", nf.Src(), nf.Dst())
			}
		} else {
			fmt.Printf("Network Layer: NONE\n")
		}

		if tl := packet.TransportLayer(); tl != nil {
			fmt.Printf("Transport Layer: %s\n", tl.LayerType())
			if tf := tl.TransportFlow(); tf != (gopacket.Flow{}) {
				fmt.Printf("  Src: %s, Dst: %s\n", tf.Src(), tf.Dst())
			}
		} else {
			fmt.Printf("Transport Layer: NONE\n")
		}

		fmt.Printf("Has ENIP: %v, Has CIP: %v\n", hasENIP, hasCIP)

		if hasCIP {
			cipPacketCount++

			// Get the CIP layer
			cipLayer := packet.Layer(layers.LayerTypeCIP)
			if cipLayer != nil {
				fmt.Printf("CIP Layer Contents: %v\n", cipLayer.LayerContents())
				fmt.Printf("CIP Layer Payload: %v\n", cipLayer.LayerPayload())
			}
		}

		// Only inspect first 10 packets in detail
		if packetCount >= 10 {
			break
		}
	}

	t.Logf("\nTotal packets inspected: %d", packetCount)
	t.Logf("CIP packets found: %d", cipPacketCount)
}
