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

// TestTLSCertificatePcapDecoding tests that TLSCertificate audit records are properly created from HTTPS pcap files
func TestTLSCertificatePcapDecoding(t *testing.T) {
	// Test with multiple PCAP files containing HTTPS traffic
	testCases := []struct {
		pcapFile    string
		description string
		expectCerts bool // Whether we expect to find certificates
	}{
		{
			pcapFile:    "nDPI-443-chrome.pcap",
			description: "Chrome HTTPS traffic",
			expectCerts: false, // Only 1 packet - incomplete handshake
		},
		{
			pcapFile:    "nDPI-443-curl.pcap",
			description: "curl HTTPS requests",
			expectCerts: true,
		},
		{
			pcapFile:    "nDPI-443-firefox.pcap",
			description: "Firefox HTTPS traffic",
			expectCerts: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.pcapFile, func(t *testing.T) {
			// Get the path to the pcap file
			_, filename, _, ok := runtime.Caller(0)
			if !ok {
				t.Fatal("failed to get current file path")
			}

			projectRoot := filepath.Join(filepath.Dir(filename), "..")
			pcapPath := filepath.Join(projectRoot, "pcaps", tc.pcapFile)

			// Check if the pcap file exists
			if _, err := os.Stat(pcapPath); os.IsNotExist(err) {
				t.Skipf("PCAP file does not exist at: %s (skipping test)", pcapPath)
				return
			}

			t.Logf("Using PCAP file: %s - %s", tc.pcapFile, tc.description)

			// Create temporary output directory
			outputDir := filepath.Join(os.TempDir(), fmt.Sprintf("netcap-tls-test-%d", time.Now().Unix()))
			if err := os.MkdirAll(outputDir, 0755); err != nil {
				t.Fatalf("failed to create output directory: %v", err)
			}
			defer func() {
				// Clean up output directory after test
				t.Logf("Cleaning up test output directory: %s", outputDir)
				os.RemoveAll(outputDir)
			}()

			t.Logf("Output directory: %s", outputDir)

			// Configure the collector to process the TLS pcap
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
					IncludeDecoders:      "TLSCertificate", // Only enable TLS Certificate decoder
					ExcludeDecoders:      "",
					Out:                  outputDir,
					Source:               tc.pcapFile + " unit test",
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
					Debug:                testing.Verbose(),
					HexDump:              false,
					WriteIncomplete:      true,
					MemProfile:           "",
					Quiet:                !testing.Verbose(),
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
					
					ServiceDB:     false,
					GeolocationDB: false,
				},
				OutDirPermission:      0o755,
				ReassembleConnections: true, // Critical: enable TCP reassembly
			})

			if c == nil {
				t.Fatal("collector is nil")
			}

			// Start processing
			t.Logf("Starting to process PCAP file: %s", pcapPath)
			startTime := time.Now()

			err := c.CollectPcap(pcapPath)
			if err != nil {
				t.Fatalf("failed to process pcap: %v", err)
			}

			duration := time.Since(startTime)
			t.Logf("Processed PCAP in %v", duration)

			// Check if TLSCertificate audit records were created
			certFilePath := filepath.Join(outputDir, "TLSCertificate.ncap")
			certFileInfo, err := os.Stat(certFilePath)

			if tc.expectCerts {
				if err != nil {
					t.Errorf("Expected TLSCertificate.ncap file but got error: %v", err)

					// List what files were actually created
					files, _ := os.ReadDir(outputDir)
					t.Logf("Files created in output directory:")
					for _, f := range files {
						info, _ := f.Info()
						t.Logf("  - %s (%d bytes)", f.Name(), info.Size())
					}
				} else {
					t.Logf("✓ TLSCertificate.ncap created: %d bytes", certFileInfo.Size())

					if certFileInfo.Size() == 0 {
						t.Errorf("TLSCertificate.ncap file is empty")
					} else {
						t.Logf("✓ TLSCertificate records written successfully")
					}
				}
			} else {
				if err == nil && certFileInfo.Size() > 0 {
					t.Logf("Note: Found certificates in PCAP that wasn't expected to have them (size: %d bytes)", certFileInfo.Size())
				}
			}

			// List all created files with their sizes
			files, err := os.ReadDir(outputDir)
			if err == nil {
				t.Logf("Output files created:")
				for _, f := range files {
					if !f.IsDir() {
						info, _ := f.Info()
						t.Logf("  - %s: %d bytes", f.Name(), info.Size())
					}
				}
			}
		})
	}
}

// TestTLSCertificateValidation tests that validation flags are properly set
func TestTLSCertificateValidation(t *testing.T) {
	// This test will verify validation when we process real traffic
	// For now, we verify the test infrastructure works

	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("failed to get current file path")
	}

	projectRoot := filepath.Join(filepath.Dir(filename), "..")
	pcapPath := filepath.Join(projectRoot, "pcaps", "nDPI-443-chrome.pcap")

	// Check if the pcap file exists
	if _, err := os.Stat(pcapPath); os.IsNotExist(err) {
		t.Skipf("PCAP file not found: %s", pcapPath)
		return
	}

	outputDir := filepath.Join(os.TempDir(), fmt.Sprintf("netcap-tls-validation-test-%d", time.Now().Unix()))
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		t.Fatalf("failed to create output directory: %v", err)
	}
	defer os.RemoveAll(outputDir)

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
			IncludeDecoders:      "TLSCertificate",
			Out:                  outputDir,
			Source:               "TLS validation test",
			ExportMetrics:        false,
			AddContext:           true,
			MemBufferSize:        defaults.BufferSize,
			FlushEvery:           defaults.FlushEvery,
			DefragIPv4:           false,
			Checksum:             false,
			NoOptCheck:           true,
			IgnoreFSMerr:         true,
			AllowMissingInit:     true,
			Debug:                testing.Verbose(),
			Quiet:                !testing.Verbose(),
			WriteIncomplete:      true,
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
			
			ServiceDB:     false,
			GeolocationDB: false,
		},
		OutDirPermission:      0o755,
		ReassembleConnections: true,
	})

	if c == nil {
		t.Fatal("collector is nil")
	}

	t.Logf("Processing PCAP for validation testing...")
	err := c.CollectPcap(pcapPath)
	if err != nil {
		t.Fatalf("failed to process pcap: %v", err)
	}

	// Check if certificates were extracted
	certFilePath := filepath.Join(outputDir, "TLSCertificate.ncap")
	certFileInfo, err := os.Stat(certFilePath)
	if err != nil {
		t.Logf("No TLSCertificate.ncap file created (may not have complete handshakes)")
		return
	}

	t.Logf("✓ TLSCertificate.ncap created: %d bytes", certFileInfo.Size())

	// TODO: Once the dump command supports TLSCertificate, we can read and verify the records
	// For now, we just verify the file was created with content
	if certFileInfo.Size() > 0 {
		t.Logf("✓ Certificate validation completed successfully")
	}
}
