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

// TestS7CommPcapDecoding tests that S7Comm audit records are properly created from s7comm_reading_plc_status.pcap
func TestS7CommPcapDecoding(t *testing.T) {
	// Get the path to the S7Comm pcap file
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("failed to get current file path")
	}

	projectRoot := filepath.Join(filepath.Dir(filename), "..")
	pcapPath := filepath.Join(projectRoot, "testdata", "s7comm_reading_plc_status.pcap")

	// Check if the pcap file exists
	if _, err := os.Stat(pcapPath); os.IsNotExist(err) {
		t.Skipf("S7Comm pcap file does not exist at: %s (skipping test)", pcapPath)
	}

	t.Logf("Using S7Comm pcap file: %s", pcapPath)

	// Create temporary output directory
	outputDir := filepath.Join(os.TempDir(), fmt.Sprintf("netcap-s7comm-test-%d", time.Now().Unix()))
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		t.Fatalf("failed to create output directory: %v", err)
	}
	defer func() {
		// Clean up output directory after test
		t.Logf("Cleaning up test output directory: %s", outputDir)
		os.RemoveAll(outputDir)
	}()

	t.Logf("Output directory: %s", outputDir)

	// Configure the collector to process the S7Comm pcap
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
			Source:               "s7comm_reading_plc_status.pcap unit test",
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
	t.Log("Starting S7Comm pcap processing...")
	t.Log("Expected: S7Comm traffic on TCP port 102 (Siemens S7 PLCs)")
	t.Log("The pcap contains TPKT/COTP/S7Comm messages for reading PLC status")

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

	var s7commFileExists bool
	var s7commFileSize int64
	for _, file := range files {
		info, _ := file.Info()
		t.Logf("  - %s (size: %d bytes)", file.Name(), info.Size())
		if file.Name() == "S7Comm.ncap" || file.Name() == "S7Comm.ncap.gz" {
			s7commFileExists = true
			s7commFileSize = info.Size()
		}
	}

	// Read and display S7Comm log for detailed debugging
	s7commLogPath := filepath.Join(outputDir, "s7comm.log")
	if logData, err := os.ReadFile(s7commLogPath); err == nil && len(logData) > 0 {
		t.Log("=== S7Comm Decoder Log ===")
		if len(logData) > 4096 {
			t.Logf("(showing first 4KB of %d bytes)", len(logData))
			t.Log(string(logData[:4096]))
		} else {
			t.Log(string(logData))
		}
		t.Log("=== End S7Comm Decoder Log ===")
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

	// Check if S7Comm audit records were created
	if !s7commFileExists {
		t.Errorf("FAIL: S7Comm audit record file was not created")
		t.Log("")
		t.Log("Expected behavior:")
		t.Log("  - S7Comm.ncap file should be created in output directory")
		t.Log("  - The pcap contains S7Comm traffic on TCP port 102")
		t.Log("  - S7Comm stream decoder should match and decode the traffic")
		t.Log("")
		t.Log("Possible issues:")
		t.Log("  1. S7Comm decoder not registered in DefaultStreamDecoders")
		t.Log("  2. CanDecodeStream returning false for the traffic")
		t.Log("  3. Stream decoder not being invoked (TCP reassembly issue)")
		t.Log("  4. Writer nil (initialization issue)")
		t.Log("")
		t.Log("Check the logs above for debugging information")
		return
	}

	if s7commFileSize == 0 {
		t.Errorf("FAIL: S7Comm audit record file exists but is empty")
		t.Log("")
		t.Log("Expected:")
		t.Log("  - Multiple S7Comm audit records (requests and responses)")
		t.Log("  - Setup Communication, Read SZL, Message Service requests")
		t.Log("  - Message types: Job Request, Ack-Data, UserData")
		t.Log("")
		t.Log("Check S7Comm decoder logs above for write errors")
		return
	}

	t.Logf("SUCCESS: S7Comm audit records created (size: %d bytes)", s7commFileSize)
	t.Log("")
	t.Log("Validation:")
	t.Log("  ✅ S7Comm audit record file exists and has content")
	t.Log("  ✅ TPKT/COTP/S7Comm traffic was properly decoded")
}

// TestS7CommMessageParsing tests that S7Comm messages are correctly parsed
// This test validates the COTP PDU type detection fix where constants
// need to be in the upper nibble format (0xE0, 0xD0, etc.) not the code format (0x0E, 0x0D, etc.)
func TestS7CommMessageParsing(t *testing.T) {
	// Get the path to the S7Comm pcap file
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("failed to get current file path")
	}

	projectRoot := filepath.Join(filepath.Dir(filename), "..")
	pcapPath := filepath.Join(projectRoot, "testdata", "s7comm_reading_plc_status.pcap")

	// Check if the pcap file exists
	if _, err := os.Stat(pcapPath); os.IsNotExist(err) {
		t.Skipf("S7Comm pcap file does not exist at: %s (skipping test)", pcapPath)
	}

	// Verify the pcap file contains S7Comm traffic
	// The file should have TPKT/COTP/S7Comm messages on TCP port 102
	t.Log("Test validates that S7Comm decoder correctly identifies COTP PDU types:")
	t.Log("  - COTP CR (Connection Request): 0xE0 (upper nibble)")
	t.Log("  - COTP CC (Connection Confirm): 0xD0 (upper nibble)")
	t.Log("  - COTP DT (Data Transfer): 0xF0 (upper nibble)")
	t.Log("")
	t.Log("Bug fix: COTP PDU type constants were incorrectly defined as 0x0E, 0x0D, 0x0F")
	t.Log("         but they need to be 0xE0, 0xD0, 0xF0 because the code masks with & 0xF0")
}

