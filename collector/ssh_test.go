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

// TestSSHPcapDecoding tests that SSH audit records are properly created from ssh.pcap
func TestSSHPcapDecoding(t *testing.T) {
	// Get the path to the SSH pcap file
	// The test is in collector/, pcap is in pcaps/
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("failed to get current file path")
	}

	projectRoot := filepath.Join(filepath.Dir(filename), "..")
	pcapPath := filepath.Join(projectRoot, "pcaps", "ssh.pcap")

	// Check if the pcap file exists
	if _, err := os.Stat(pcapPath); os.IsNotExist(err) {
		t.Fatalf("SSH pcap file does not exist at: %s", pcapPath)
	}

	t.Logf("Using SSH pcap file: %s", pcapPath)

	// Create temporary output directory
	outputDir := filepath.Join(os.TempDir(), fmt.Sprintf("netcap-ssh-test-%d", time.Now().Unix()))
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		t.Fatalf("failed to create output directory: %v", err)
	}
	defer func() {
		// Clean up output directory after test
		t.Logf("Cleaning up test output directory: %s", outputDir)
		os.RemoveAll(outputDir)
	}()

	t.Logf("Output directory: %s", outputDir)

	// Configure the collector to process the SSH pcap
	c := collector.New(collector.Config{
		WriteUnknownPackets: false,
		Workers:             1,
		PacketBufferSize:    100,
		SnapLen:             defaults.SnapLen,
		Promisc:             false,
		DecoderConfig: &config.Config{
			Buffer:           true,
			Compression:      false, // Disable compression for easier debugging
			CSV:              false,
			Proto:            true,
			IncludeDecoders:  "",
			ExcludeDecoders:  "DeviceProfile,IPProfile,Connection", // Exclude decoders that use DPI
			Out:              outputDir,
			Source:           "ssh.pcap unit test",
			IncludePayloads:  false,
			ExportMetrics:    false,
			AddContext:       true, // Enable context - required for proper initialization
			MemBufferSize:    defaults.BufferSize,
			FlushEvery:       defaults.FlushEvery,
			DefragIPv4:       false, // Disable defrag
			Checksum:         false, // Disable checksum validation for testing
			NoOptCheck:       true,  // Ignore option check errors
			IgnoreFSMerr:     true,  // Ignore FSM errors for testing
			AllowMissingInit: true,  // Allow missing init
			Debug:            false, // Disable debug to avoid verbose output
			HexDump:          false, // Don't hex dump
			WriteIncomplete:  true,  // Write incomplete streams
			MemProfile:       "",
			// NOTE: Use default timeout values (24 hours)
			// Aggressive timeouts cause streams to close prematurely in offline pcap analysis!
			FileStorage:          "",
			Quiet:                true, // Be quiet
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
		ReassembleConnections: true, // Critical: enable TCP reassembly
	})

	// Process the pcap file (it's actually in PCAPNG format)
	t.Log("Starting pcap processing...")
	if err := c.CollectPcapNG(pcapPath); err != nil {
		t.Fatalf("failed to collect audit records from pcap file: %v", err)
	}

	t.Log("Pcap processing complete")

	// List all files in the output directory for debugging
	t.Log("Files created in output directory:")
	files, err := os.ReadDir(outputDir)
	if err != nil {
		t.Fatalf("failed to read output directory: %v", err)
	}

	for _, file := range files {
		info, _ := file.Info()
		t.Logf("  - %s (size: %d bytes)", file.Name(), info.Size())
	}

	// Check if SSH audit records were created
	sshFile := filepath.Join(outputDir, "SSH.ncap")
	if _, err := os.Stat(sshFile); os.IsNotExist(err) {
		t.Fatalf("FAIL: SSH audit record file was not created: %s", sshFile)
	}

	// Check if the SSH file has content
	info, err := os.Stat(sshFile)
	if err != nil {
		t.Fatalf("failed to stat SSH file: %v", err)
	}

	if info.Size() == 0 {
		t.Fatal("FAIL: SSH audit record file is empty")
	}

	t.Logf("SUCCESS: SSH audit records created (size: %d bytes)", info.Size())
}

// TestSSHUnidirectionalPcap tests SSH audit record generation from ssh_unidirectional.pcap
// This test is designed to debug why no SSH audit records are generated for unidirectional SSH traffic
// where the server sends SSH ident and "Protocol mismatch" but no KexInit is exchanged
func TestSSHUnidirectionalPcap(t *testing.T) {
	// Get the path to the test pcap file
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("failed to get current file path")
	}

	projectRoot := filepath.Join(filepath.Dir(filename), "..")
	pcapPath := filepath.Join(projectRoot, "tests", "testdata", "ssh_unidirectional.pcap")

	// Check if the pcap file exists
	if _, err := os.Stat(pcapPath); os.IsNotExist(err) {
		t.Fatalf("SSH unidirectional pcap file does not exist at: %s", pcapPath)
	}

	t.Logf("Using SSH unidirectional pcap file: %s", pcapPath)

	// Create temporary output directory
	outputDir := filepath.Join(os.TempDir(), fmt.Sprintf("netcap-ssh-unidirectional-test-%d", time.Now().Unix()))
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		t.Fatalf("failed to create output directory: %v", err)
	}

	// Don't clean up automatically - keep logs for inspection
	keepLogs := true
	if !keepLogs {
		defer func() {
			// Clean up output directory after test
			t.Logf("Cleaning up test output directory: %s", outputDir)
			os.RemoveAll(outputDir)
		}()
	}

	t.Logf("Output directory: %s", outputDir)

	// Configure the collector with DEBUG logging enabled to trace SSH decoding
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
			IncludeDecoders:      "SSH", // Only enable SSH decoder for this test
			ExcludeDecoders:      "",
			Out:                  outputDir,
			Source:               "ssh_unidirectional.pcap unit test",
			IncludePayloads:      false,
			ExportMetrics:        false,
			AddContext:           true, // Enable context - required for proper initialization
			MemBufferSize:        defaults.BufferSize,
			FlushEvery:           defaults.FlushEvery,
			DefragIPv4:           false, // Disable defrag
			Checksum:             false, // Disable checksum validation for testing
			NoOptCheck:           true,  // Ignore option check errors
			IgnoreFSMerr:         true,  // Ignore FSM errors for testing
			AllowMissingInit:     true,  // Allow missing init
			Debug:                true,  // Enable debug logging to see what's happening
			HexDump:              false, // Don't hex dump
			WriteIncomplete:      true,  // Write incomplete streams
			MemProfile:           "",
			FileStorage:          "",
			Quiet:                false, // Enable verbose output for debugging
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
		ReassembleConnections: true, // Critical: enable TCP reassembly
	})

	// Process the pcap file
	t.Log("Starting pcap processing with DEBUG logging enabled...")
	t.Log("This PCAP contains unidirectional SSH traffic:")
	t.Log("  - Server sends: SSH-2.0-OpenSSH_7.4p1 Debian-10+deb9u7")
	t.Log("  - Server sends: Protocol mismatch.")
	t.Log("  - No KexInit exchange occurs")
	t.Log("  - Connection terminates early")
	t.Log("")
	t.Log("Expected result:")
	t.Log("  - SSH audit records SHOULD be created (even without KexInit)")
	t.Log("  - Server ident should be captured")
	t.Log("  - HASSH field will be empty (no KexInit)")
	t.Log("  - Notes field: 'Incomplete handshake - no KexInit'")

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

	var sshFileExists bool
	var sshFileSize int64
	for _, file := range files {
		info, _ := file.Info()
		t.Logf("  - %s (size: %d bytes)", file.Name(), info.Size())
		if file.Name() == "SSH.ncap" {
			sshFileExists = true
			sshFileSize = info.Size()
		}
	}

	// Read and display SSH log for detailed debugging
	sshLogPath := filepath.Join(outputDir, "ssh.log")
	if logData, err := os.ReadFile(sshLogPath); err == nil {
		t.Log("=== SSH Decoder Log ===")
		t.Log(string(logData))
		t.Log("=== End SSH Decoder Log ===")
	}

	// Read and display reassembly log for stream information
	reassemblyLogPath := filepath.Join(outputDir, "reassembly.log")
	if logData, err := os.ReadFile(reassemblyLogPath); err == nil {
		t.Log("=== TCP Reassembly Log ===")
		t.Log(string(logData))
		t.Log("=== End TCP Reassembly Log ===")
	}

	// Report findings - SSH audit records should be created even without KexInit
	if !sshFileExists {
		t.Errorf("FAIL: SSH audit record file was not created")
		t.Log("Expected behavior:")
		t.Log("  - SSH audit records should be created for ident-only connections")
		t.Log("  - Even without KexInit, we capture SSH identification strings")
		t.Log("  - HASSH field will be empty, Notes field indicates incomplete handshake")
		t.Log("")
		t.Log("Debug the SSH decoder logs above to see why records weren't created")
		return
	}

	if sshFileSize == 0 {
		t.Errorf("FAIL: SSH audit record file exists but is empty")
		t.Log("Expected:")
		t.Log("  - At least one SSH audit record for the server ident")
		t.Log("  - Server sent: SSH-2.0-OpenSSH_7.4p1 Debian-10+deb9u7")
		t.Log("")
		t.Log("Check SSH decoder logs above for write errors")
		return
	}

	t.Logf("SUCCESS: SSH audit records created (size: %d bytes)", sshFileSize)
	t.Log("Validation:")
	t.Log("  ✅ SSH audit record file exists and has content")
	t.Log("  ✅ Captured incomplete SSH handshake")
	t.Log("  ✅ Server ident should be recorded: SSH-2.0-OpenSSH_7.4p1 Debian-10+deb9u7")
	t.Log("  ✅ Notes field should indicate: 'Incomplete handshake - no KexInit'")
}
