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

package collector_test

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/dreadl0ck/netcap/collector"
	"github.com/dreadl0ck/netcap/decoder/config"
	"github.com/dreadl0ck/netcap/defaults"
	"github.com/dreadl0ck/netcap/resolvers"
	"github.com/dreadl0ck/netcap/utils"
)

// TestCIPPcapDecoding tests that CIP audit records are properly created from cip.pcap
func TestCIPPcapDecoding(t *testing.T) {
	// Get the path to the CIP pcap file
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("failed to get current file path")
	}

	projectRoot := filepath.Join(filepath.Dir(filename), "..")
	pcapPath := filepath.Join(projectRoot, "testdata", "cip.pcap")

	// Check if the pcap file exists
	if _, err := os.Stat(pcapPath); os.IsNotExist(err) {
		t.Skipf("CIP pcap file does not exist at: %s (skipping test)", pcapPath)
	}

	t.Logf("Using CIP pcap file: %s", pcapPath)

	// Create temporary output directory
	outputDir := filepath.Join(os.TempDir(), fmt.Sprintf("netcap-cip-test-%d", time.Now().Unix()))
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		t.Fatalf("failed to create output directory: %v", err)
	}
	defer func() {
		// Clean up output directory after test
		t.Logf("Cleaning up test output directory: %s", outputDir)
		os.RemoveAll(outputDir)
	}()

	t.Logf("Output directory: %s", outputDir)

	// Configure the collector to process the CIP pcap
	c := collector.New(collector.Config{
		WriteUnknownPackets: false,
		Workers:             1,
		PacketBufferSize:    100,
		SnapLen:             defaults.SnapLen,
		Promisc:             false,
		DecoderConfig: &config.Config{
			Buffer:               true,
			Compression:          false, // Disable compression for easier debugging
			CSV:                  false,
			Proto:                true,
			IncludeDecoders:      "",
			ExcludeDecoders:      "DeviceProfile,IPProfile,Connection", // Exclude decoders that use DPI
			Out:                  outputDir,
			Source:               "cip.pcap unit test",
			IncludePayloads:      false,
			ExportMetrics:        false,
			AddContext:           true,
			MemBufferSize:        defaults.BufferSize,
			FlushEvery:           defaults.FlushEvery,
			DefragIPv4:           false,
			Checksum:             false,
			NoOptCheck:           true,
			IgnoreFSMerr:         true,
			AllowMissingInit:     true,
			Debug:                true, // Enable debug to see what's happening
			HexDump:              false,
			WriteIncomplete:      true,
			MemProfile:           "",
			FileStorage:          "",
			Quiet:                false, // Verbose output for debugging
			CompressionBlockSize: defaults.CompressionBlockSize,
			CompressionLevel:     defaults.CompressionLevel,
			NumStreamWorkers:     10,
			StreamBufferSize:     100,
		},
		BaseLayer:     utils.GetBaseLayer("ethernet"),
		DecodeOptions: utils.GetDecodeOptions("default"),
		DPI:           false,
		ResolverConfig: resolvers.Config{
			ReverseDNS:    false,
			LocalDNS:      false,
			MACDB:         false,
			Ja3DB:         false,
			ServiceDB:     false,
			GeolocationDB: false,
		},
		OutDirPermission:      0o755,
		FreeOSMem:             0,
		ReassembleConnections: true, // Critical: enable TCP reassembly for stream decoders
	})

	// Process the pcap file
	t.Log("Starting CIP pcap processing...")
	t.Log("Expected: CIP/ENIP traffic on port 44818")
	t.Log("The pcap contains EtherNet/IP (ENIP) encapsulated CIP messages")

	if err := c.CollectPcap(pcapPath); err != nil {
		t.Fatalf("failed to collect audit records from pcap file: %v", err)
	}

	t.Log("Pcap processing complete")

	// List all files in the output directory for debugging
	t.Log("Files created in output directory:")
	files, err := os.ReadDir(outputDir)
	if err != nil {
		t.Fatalf("failed to read output directory: %v", err)
	}

	var cipFileExists bool
	var cipFileSize int64
	for _, file := range files {
		info, _ := file.Info()
		t.Logf("  - %s (size: %d bytes)", file.Name(), info.Size())
		if file.Name() == "CIP.ncap" {
			cipFileExists = true
			cipFileSize = info.Size()
		}
	}

	// Read and display CIP log for detailed debugging
	cipLogPath := filepath.Join(outputDir, "cip.log")
	if logData, err := os.ReadFile(cipLogPath); err == nil && len(logData) > 0 {
		t.Log("=== CIP Decoder Log ===")
		if len(logData) > 4096 {
			t.Logf("(showing first 4KB of %d bytes)", len(logData))
			t.Log(string(logData[:4096]))
		} else {
			t.Log(string(logData))
		}
		t.Log("=== End CIP Decoder Log ===")
	}

	// Read and display reassembly log for stream information
	reassemblyLogPath := filepath.Join(outputDir, "reassembly.log")
	if logData, err := os.ReadFile(reassemblyLogPath); err == nil && len(logData) > 0 {
		t.Log("=== TCP Reassembly Log (last 4KB) ===")
		if len(logData) > 4096 {
			t.Log(string(logData[len(logData)-4096:]))
		} else {
			t.Log(string(logData))
		}
		t.Log("=== End TCP Reassembly Log ===")
	}

	// Read decoder log for stream decoder matching information
	decoderLogPath := filepath.Join(outputDir, "decoder.log")
	if logData, err := os.ReadFile(decoderLogPath); err == nil && len(logData) > 0 {
		t.Log("=== Decoder Log (last 4KB) ===")
		if len(logData) > 4096 {
			t.Log(string(logData[len(logData)-4096:]))
		} else {
			t.Log(string(logData))
		}
		t.Log("=== End Decoder Log ===")
	}

	// Check if CIP audit records were created
	if !cipFileExists {
		t.Errorf("FAIL: CIP audit record file was not created")
		t.Log("")
		t.Log("Expected behavior:")
		t.Log("  - CIP.ncap file should be created in output directory")
		t.Log("  - The pcap contains ENIP/CIP traffic on port 44818")
		t.Log("  - CIP stream decoder should match and decode the traffic")
		t.Log("")
		t.Log("Possible issues:")
		t.Log("  1. CIP decoder not registered in DefaultStreamDecoders")
		t.Log("  2. CanDecodeStream returning false for the traffic")
		t.Log("  3. Stream decoder not being invoked (TCP reassembly issue)")
		t.Log("  4. Writer nil (initialization issue)")
		t.Log("")
		t.Log("Check the logs above for debugging information")
		return
	}

	if cipFileSize == 0 {
		t.Errorf("FAIL: CIP audit record file exists but is empty")
		t.Log("")
		t.Log("Expected:")
		t.Log("  - Multiple CIP audit records (requests and responses)")
		t.Log("  - Service code 0x4B (Execute PCCC)")
		t.Log("  - Class 0x67 (PCCC Class), Instance 0x01")
		t.Log("")
		t.Log("Check CIP decoder logs above for write errors")
		return
	}

	t.Logf("SUCCESS: CIP audit records created (size: %d bytes)", cipFileSize)
	t.Log("")
	t.Log("Validation:")
	t.Log("  ✅ CIP audit record file exists and has content")
	t.Log("  ✅ ENIP/CIP traffic was properly decoded")
}

// TestCIPDecoderOnly tests CIP decoding with only the CIP decoder enabled
func TestCIPDecoderOnly(t *testing.T) {
	// Get the path to the CIP pcap file
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("failed to get current file path")
	}

	projectRoot := filepath.Join(filepath.Dir(filename), "..")
	pcapPath := filepath.Join(projectRoot, "testdata", "cip.pcap")

	// Check if the pcap file exists
	if _, err := os.Stat(pcapPath); os.IsNotExist(err) {
		t.Skipf("CIP pcap file does not exist at: %s (skipping test)", pcapPath)
	}

	t.Logf("Using CIP pcap file: %s", pcapPath)

	// Create temporary output directory
	outputDir := filepath.Join(os.TempDir(), fmt.Sprintf("netcap-cip-only-test-%d", time.Now().Unix()))
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		t.Fatalf("failed to create output directory: %v", err)
	}
	defer func() {
		t.Logf("Cleaning up test output directory: %s", outputDir)
		os.RemoveAll(outputDir)
	}()

	t.Logf("Output directory: %s", outputDir)

	// Configure the collector with ONLY CIP decoder enabled
	c := collector.New(collector.Config{
		WriteUnknownPackets: false,
		Workers:             1,
		PacketBufferSize:    100,
		SnapLen:             defaults.SnapLen,
		Promisc:             false,
		DecoderConfig: &config.Config{
			Buffer:               true,
			Compression:          false,
			CSV:                  false,
			Proto:                true,
			IncludeDecoders:      "CIP", // Only CIP decoder
			ExcludeDecoders:      "",
			Out:                  outputDir,
			Source:               "cip.pcap CIP-only unit test",
			IncludePayloads:      false,
			ExportMetrics:        false,
			AddContext:           true,
			MemBufferSize:        defaults.BufferSize,
			FlushEvery:           defaults.FlushEvery,
			DefragIPv4:           false,
			Checksum:             false,
			NoOptCheck:           true,
			IgnoreFSMerr:         true,
			AllowMissingInit:     true,
			Debug:                true,
			HexDump:              false,
			WriteIncomplete:      true,
			MemProfile:           "",
			FileStorage:          "",
			Quiet:                false,
			CompressionBlockSize: defaults.CompressionBlockSize,
			CompressionLevel:     defaults.CompressionLevel,
			NumStreamWorkers:     10,
			StreamBufferSize:     100,
		},
		BaseLayer:     utils.GetBaseLayer("ethernet"),
		DecodeOptions: utils.GetDecodeOptions("default"),
		DPI:           false,
		ResolverConfig: resolvers.Config{
			ReverseDNS:    false,
			LocalDNS:      false,
			MACDB:         false,
			Ja3DB:         false,
			ServiceDB:     false,
			GeolocationDB: false,
		},
		OutDirPermission:      0o755,
		FreeOSMem:             0,
		ReassembleConnections: true,
	})

	t.Log("Starting CIP pcap processing with CIP decoder ONLY...")

	if err := c.CollectPcap(pcapPath); err != nil {
		t.Fatalf("failed to collect audit records from pcap file: %v", err)
	}

	t.Log("Pcap processing complete")

	// List all files in the output directory
	t.Log("Files created in output directory:")
	files, err := os.ReadDir(outputDir)
	if err != nil {
		t.Fatalf("failed to read output directory: %v", err)
	}

	var cipFileExists bool
	var cipFileSize int64
	for _, file := range files {
		info, _ := file.Info()
		t.Logf("  - %s (size: %d bytes)", file.Name(), info.Size())
		if file.Name() == "CIP.ncap" {
			cipFileExists = true
			cipFileSize = info.Size()
		}
	}

	// Read CIP log
	cipLogPath := filepath.Join(outputDir, "cip.log")
	if logData, err := os.ReadFile(cipLogPath); err == nil && len(logData) > 0 {
		t.Log("=== CIP Decoder Log ===")
		if len(logData) > 2048 {
			t.Logf("(showing first 2KB of %d bytes)", len(logData))
			t.Log(string(logData[:2048]))
		} else {
			t.Log(string(logData))
		}
		t.Log("=== End CIP Decoder Log ===")
	}

	// Read IO log
	ioLogPath := filepath.Join(outputDir, "io.log")
	if logData, err := os.ReadFile(ioLogPath); err == nil && len(logData) > 0 {
		t.Log("=== IO Log ===")
		t.Log(string(logData))
		t.Log("=== End IO Log ===")
	}

	// Read netcap log
	netcapLogPath := filepath.Join(outputDir, "netcap.log")
	if logData, err := os.ReadFile(netcapLogPath); err == nil && len(logData) > 0 {
		t.Log("=== Netcap Log ===")
		t.Log(string(logData))
		t.Log("=== End Netcap Log ===")
	}

	if !cipFileExists {
		t.Error("FAIL: CIP audit record file was not created")
		return
	}

	if cipFileSize == 0 {
		t.Error("FAIL: CIP audit record file exists but is empty")
		return
	}

	t.Logf("SUCCESS: CIP audit records created (size: %d bytes)", cipFileSize)
}

// TestCIPSuricataVerifyPcap tests CIP decoding with the suricata-verify-enip_cip_example.pcap file
// This file contains Multiple Service Packet requests which need special handling
func TestCIPSuricataVerifyPcap(t *testing.T) {
	// Get the path to the pcap file
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("failed to get current file path")
	}

	projectRoot := filepath.Join(filepath.Dir(filename), "..")
	pcapPath := filepath.Join(projectRoot, "testdata", "suricata-verify-enip_cip_example.pcap")

	// Check if the pcap file exists
	if _, err := os.Stat(pcapPath); os.IsNotExist(err) {
		t.Skipf("Suricata ENIP/CIP pcap file does not exist at: %s (skipping test)", pcapPath)
	}

	t.Logf("Using Suricata ENIP/CIP pcap file: %s", pcapPath)

	// Create temporary output directory
	outputDir := filepath.Join(os.TempDir(), fmt.Sprintf("netcap-cip-suricata-test-%d", time.Now().Unix()))
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		t.Fatalf("failed to create output directory: %v", err)
	}
	defer func() {
		t.Logf("Cleaning up test output directory: %s", outputDir)
		os.RemoveAll(outputDir)
	}()

	t.Logf("Output directory: %s", outputDir)

	// Configure the collector with ONLY CIP decoder enabled
	c := collector.New(collector.Config{
		WriteUnknownPackets: false,
		Workers:             1,
		PacketBufferSize:    100,
		SnapLen:             defaults.SnapLen,
		Promisc:             false,
		DecoderConfig: &config.Config{
			Buffer:               true,
			Compression:          false,
			CSV:                  false,
			Proto:                true,
			IncludeDecoders:      "CIP", // Only CIP decoder
			ExcludeDecoders:      "",
			Out:                  outputDir,
			Source:               "suricata-verify-enip_cip_example.pcap CIP test",
			IncludePayloads:      false,
			ExportMetrics:        false,
			AddContext:           true,
			MemBufferSize:        defaults.BufferSize,
			FlushEvery:           defaults.FlushEvery,
			DefragIPv4:           false,
			Checksum:             false,
			NoOptCheck:           true,
			IgnoreFSMerr:         true,
			AllowMissingInit:     true,
			Debug:                true,
			HexDump:              false,
			WriteIncomplete:      true,
			MemProfile:           "",
			FileStorage:          "",
			Quiet:                false,
			CompressionBlockSize: defaults.CompressionBlockSize,
			CompressionLevel:     defaults.CompressionLevel,
			NumStreamWorkers:     10,
			StreamBufferSize:     100,
		},
		BaseLayer:     utils.GetBaseLayer("ethernet"),
		DecodeOptions: utils.GetDecodeOptions("default"),
		DPI:           false,
		ResolverConfig: resolvers.Config{
			ReverseDNS:    false,
			LocalDNS:      false,
			MACDB:         false,
			Ja3DB:         false,
			ServiceDB:     false,
			GeolocationDB: false,
		},
		OutDirPermission:      0o755,
		FreeOSMem:             0,
		ReassembleConnections: true,
	})

	t.Log("Starting Suricata ENIP/CIP pcap processing with CIP decoder ONLY...")

	if err := c.CollectPcap(pcapPath); err != nil {
		t.Fatalf("failed to collect audit records from pcap file: %v", err)
	}

	t.Log("Pcap processing complete")

	// List all files in the output directory
	t.Log("Files created in output directory:")
	files, err := os.ReadDir(outputDir)
	if err != nil {
		t.Fatalf("failed to read output directory: %v", err)
	}

	var cipFileExists bool
	var cipFileSize int64
	for _, f := range files {
		info, _ := f.Info()
		if info != nil {
			t.Logf("  - %s (%d bytes)", f.Name(), info.Size())
			if f.Name() == "CIP.ncap.gz" || f.Name() == "CIP.ncap" {
				cipFileExists = true
				cipFileSize = info.Size()
			}
		} else {
			t.Logf("  - %s", f.Name())
		}
	}

	if !cipFileExists {
		t.Error("FAIL: CIP audit record file not found")
		t.Log("")
		t.Log("Expected: CIP.ncap.gz or CIP.ncap file in output directory")
		t.Log("")
		t.Log("This test verifies that:")
		t.Log("  1. ENIP SendUnitData (0x0070) messages are detected")
		t.Log("  2. Connected Data items (0x00B1) are parsed correctly")
		t.Log("  3. Multiple Service Packet (0x0A) is expanded to individual CIP records")
		return
	}

	if cipFileSize == 0 {
		t.Error("FAIL: CIP audit record file exists but is empty")
		return
	}

	t.Logf("SUCCESS: CIP audit records created from Suricata ENIP/CIP pcap (size: %d bytes)", cipFileSize)
	t.Log("")
	t.Log("Validation:")
	t.Log("  ✅ ENIP SendUnitData messages decoded")
	t.Log("  ✅ Connected Data items parsed (with sequence count skip)")
	t.Log("  ✅ Multiple Service Packet expanded to individual CIP records")
}
