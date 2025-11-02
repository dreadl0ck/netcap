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
	"encoding/hex"
	"testing"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcap"
	"github.com/gopacket/gopacket/reassembly"

	"github.com/dreadl0ck/netcap/decoder/config"
	"github.com/dreadl0ck/netcap/types"
)

// TestCIPInvestigation performs deep investigation of CIP decoding issue
// ISSUE: CIP audit records contain only Timestamp and network context (IP/Port)
//
//	but are missing CIP-specific fields (ServiceID, ClassID, InstanceID, etc.)
func TestCIPInvestigation(t *testing.T) {
	// Initialize decoder config like the collector does
	testConfig := config.DefaultConfig
	testConfig.IncludePayloads = true
	testConfig.Debug = true
	SetConfig(testConfig)

	// Register ENIP/CIP layers to TCP ports
	layers.RegisterTCPPortLayerType(layers.TCPPort(44818), layers.LayerTypeENIP)
	layers.RegisterTCPPortLayerType(layers.TCPPort(2222), layers.LayerTypeENIP)
	layers.RegisterTCPPortLayerType(layers.TCPPort(2430), layers.LayerTypeENIP)
	layers.RegisterUDPPortLayerType(layers.UDPPort(2222), layers.LayerTypeENIP)

	// Open the pcap file
	handle, err := pcap.OpenOffline("../../pcaps/cip.pcap")
	if err != nil {
		t.Fatalf("Failed to open pcap file: %v", err)
	}
	defer handle.Close()

	// Create packet source with DecodeStreamsAsDatagrams
	// This is the CRITICAL setting for decoding application-level protocols over TCP
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	packetSource.DecodeOptions = gopacket.DecodeStreamsAsDatagrams

	enipCount := 0
	cipCount := 0
	tcpPayloadCount := 0

	t.Log("=== INVESTIGATING CIP DECODING ISSUE ===\n")

	// Process first 100 packets
	i := 0
	for packet := range packetSource.Packets() {
		i++
		if i > 100 {
			break
		}

		// Check for TCP payload that might contain ENIP/CIP
		if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
			tcp, _ := tcpLayer.(*layers.TCP)
			payload := tcp.Payload

			if len(payload) > 0 {
				tcpPayloadCount++

				// Check if this looks like ENIP (starts with 0x6F00 command or similar)
				if len(payload) >= 24 { // ENIP header is 24 bytes
					t.Logf("\n--- Packet #%d: TCP with payload (len=%d) ---", i, len(payload))
					t.Logf("TCP Ports: %d -> %d", tcp.SrcPort, tcp.DstPort)
					t.Logf("First 64 bytes of payload:\n%s", hex.Dump(payload[:min(64, len(payload))]))

					// Try to manually parse ENIP header
					if len(payload) >= 24 {
						command := uint16(payload[0]) | uint16(payload[1])<<8
						length := uint16(payload[2]) | uint16(payload[3])<<8
						sessionHandle := uint32(payload[4]) | uint32(payload[5])<<8 | uint32(payload[6])<<16 | uint32(payload[7])<<24
						status := uint32(payload[8]) | uint32(payload[9])<<8 | uint32(payload[10])<<16 | uint32(payload[11])<<24

						t.Logf("Manual ENIP parse: Command=0x%04x, Length=%d, SessionHandle=0x%08x, Status=0x%08x",
							command, length, sessionHandle, status)
					}
				}
			}
		}

		// Check what layers gopacket decoded
		enipLayer := packet.Layer(layers.LayerTypeENIP)
		cipLayer := packet.Layer(layers.LayerTypeCIP)

		if enipLayer != nil {
			enipCount++
			t.Logf("\n✓ Packet #%d: gopacket decoded ENIP layer", i)

			if enip, ok := enipLayer.(*layers.ENIP); ok {
				t.Logf("  ENIP Command: 0x%04x (%d)", enip.Command, enip.Command)
				t.Logf("  ENIP Length: %d", enip.Length)
				t.Logf("  ENIP Status: 0x%08x", enip.Status)
				t.Logf("  ENIP SessionHandle: 0x%08x", enip.SessionHandle)
				t.Logf("  ENIP Payload length: %d", len(enip.LayerPayload()))

				// Show payload
				if len(enip.LayerPayload()) > 0 {
					t.Logf("  ENIP Payload (first 32 bytes):\n%s",
						hex.Dump(enip.LayerPayload()[:min(32, len(enip.LayerPayload()))]))
				}
			}
		}

		if cipLayer != nil {
			cipCount++
			t.Logf("\n✓✓ Packet #%d: gopacket decoded CIP layer", i)

			if cip, ok := cipLayer.(*layers.CIP); ok {
				t.Logf("  CIP Response: %v", cip.Response)
				t.Logf("  CIP Service: 0x%02x (%d)", cip.Service, cip.Service)
				t.Logf("  CIP ClassID: %v", cip.ClassID)
				t.Logf("  CIP InstanceID: %v", cip.InstanceID)
				t.Logf("  CIP Status: 0x%02x (%d)", cip.Status, cip.Status)
				t.Logf("  CIP AdditionalStatus: %v", cip.AdditionalStatus)
				t.Logf("  CIP Payload length: %d", len(cip.LayerPayload()))

				// Now test the decoder
				timestamp := packet.Metadata().Timestamp.UnixNano()
				record := cipDecoder.Handler(cipLayer, timestamp)
				if record != nil {
					if cipRec, ok := record.(*types.CIP); ok {
						// Get TCP layer for port information
						tcpLayer := packet.Layer(layers.LayerTypeTCP)
						tcp, _ := tcpLayer.(*layers.TCP)

						ctx := &types.PacketContext{
							SrcIP:   packet.NetworkLayer().NetworkFlow().Src().String(),
							DstIP:   packet.NetworkLayer().NetworkFlow().Dst().String(),
							SrcPort: int32(tcp.SrcPort),
							DstPort: int32(tcp.DstPort),
						}
						cipRec.SetPacketContext(ctx)

						t.Logf("  Netcap CIP Record:")
						t.Logf("    ServiceID: %d", cipRec.ServiceID)
						t.Logf("    ClassID: %d", cipRec.ClassID)
						t.Logf("    InstanceID: %d", cipRec.InstanceID)
						t.Logf("    Status: %d", cipRec.Status)
						t.Logf("    Response: %v", cipRec.Response)
						t.Logf("    Data length: %d", len(cipRec.Data))

						// Check if record has CIP fields
						hasCIPFields := cipRec.ServiceID != 0 || cipRec.ClassID != 0 ||
							cipRec.InstanceID != 0 || cipRec.Status != 0 || cipRec.Response ||
							len(cipRec.AdditionalStatus) > 0 || len(cipRec.Data) > 0

						if !hasCIPFields {
							t.Errorf("    ❌ BUG CONFIRMED: CIP record has NO CIP-specific fields!")
							t.Error("    This means gopacket's CIP layer decoder is returning empty/zero values")
						} else {
							t.Log("    ✓ CIP record has proper CIP fields")
						}
					}
				}
			}
		}

		// Stop after finding first 5 CIP packets or after 100 packets
		if cipCount >= 5 {
			break
		}
	}

	t.Logf("\n=== INVESTIGATION SUMMARY ===")
	t.Logf("TCP packets with payload: %d", tcpPayloadCount)
	t.Logf("Packets with ENIP layer decoded by gopacket: %d", enipCount)
	t.Logf("Packets with CIP layer decoded by gopacket: %d", cipCount)

	if tcpPayloadCount > 0 && enipCount == 0 {
		t.Error("\n❌ ROOT CAUSE: gopacket is NOT decoding ENIP from TCP payload")
		t.Error("   This could be because:")
		t.Error("   1. TCP port registration didn't work")
		t.Error("   2. gopacket requires TCP reassembly for ENIP/CIP")
		t.Error("   3. The packets need connection state tracking")
	}

	if enipCount > 0 && cipCount == 0 {
		t.Error("\n❌ ROOT CAUSE: gopacket decodes ENIP but not CIP")
		t.Error("   The ENIP layer is not properly exposing the CIP data")
	}

	if cipCount > 0 {
		t.Log("\n✓ gopacket successfully decodes CIP layers")
		t.Log("  If CIP fields are still empty, the issue is in gopacket's CIP decoder implementation")
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// TestCIPWithReassembly tests if TCP reassembly helps decode ENIP/CIP
func TestCIPWithReassembly(t *testing.T) {
	t.Log("=== Testing CIP decoding with TCP reassembly ===")
	t.Log("NOTE: ENIP/CIP over TCP may require stream reassembly")
	t.Log("The main netcap tool uses TCP reassembly which is why it works in production")

	// Initialize decoder config
	testConfig := config.DefaultConfig
	testConfig.IncludePayloads = true
	SetConfig(testConfig)

	// Register layers
	layers.RegisterTCPPortLayerType(layers.TCPPort(44818), layers.LayerTypeENIP)
	layers.RegisterTCPPortLayerType(layers.TCPPort(2430), layers.LayerTypeENIP)

	// Open pcap
	handle, err := pcap.OpenOffline("../../pcaps/cip.pcap")
	if err != nil {
		t.Fatalf("Failed to open pcap file: %v", err)
	}
	defer handle.Close()

	// Create a simple TCP reassembly to decode application layers
	streamFactory := &cipStreamFactory{t: t}
	streamPool := reassembly.NewStreamPool(streamFactory)
	assembler := reassembly.NewAssembler(streamPool)

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	packets := 0
	cipFound := 0

	for packet := range packetSource.Packets() {
		packets++
		tcp := packet.Layer(layers.LayerTypeTCP)
		if tcp != nil {
			tcpLayer := tcp.(*layers.TCP)
			if tcpLayer.SrcPort == 44818 || tcpLayer.DstPort == 44818 ||
				tcpLayer.SrcPort == 2430 || tcpLayer.DstPort == 2430 {

				// Feed to assembler
				if packet.NetworkLayer() != nil {
					assembler.Assemble(
						packet.NetworkLayer().NetworkFlow(),
						tcpLayer,
					)
				}
			}
		}

		// Check if packet has CIP after reassembly
		if cipLayer := packet.Layer(layers.LayerTypeCIP); cipLayer != nil {
			cipFound++
		}

		if packets >= 1000 {
			break
		}
	}

	assembler.FlushAll()

	t.Logf("Processed %d packets", packets)
	t.Logf("CIP layers found: %d", cipFound)
	t.Logf("Streams with CIP data: %d", streamFactory.cipStreams)
}

type cipStreamFactory struct {
	t          *testing.T
	cipStreams int
}

func (f *cipStreamFactory) New(net, transport gopacket.Flow, tcp *layers.TCP, ac reassembly.AssemblerContext) reassembly.Stream {
	return &cipStream{
		net:       net,
		transport: transport,
		factory:   f,
	}
}

type cipStream struct {
	net       gopacket.Flow
	transport gopacket.Flow
	factory   *cipStreamFactory
	data      []byte
}

func (s *cipStream) Accept(tcp *layers.TCP, ci gopacket.CaptureInfo, dir reassembly.TCPFlowDirection, nextSeq reassembly.Sequence, start *bool, ac reassembly.AssemblerContext) bool {
	return true
}

func (s *cipStream) ReassembledSG(sg reassembly.ScatterGather, ac reassembly.AssemblerContext) {
	length, _ := sg.Lengths()
	data := sg.Fetch(length)

	// Try to decode as ENIP
	packet := gopacket.NewPacket(data, layers.LayerTypeENIP, gopacket.Default)
	if cipLayer := packet.Layer(layers.LayerTypeCIP); cipLayer != nil {
		s.factory.cipStreams++
		s.factory.t.Logf("Found CIP in reassembled stream!")
	}
}

func (s *cipStream) ReassemblyComplete(ac reassembly.AssemblerContext) bool {
	return true
}
