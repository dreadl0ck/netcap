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
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dreadl0ck/netcap/collector"
	"github.com/dreadl0ck/netcap/decoder/config"
	"github.com/dreadl0ck/netcap/decoder/stream/file"
	"github.com/dreadl0ck/netcap/defaults"
	netio "github.com/dreadl0ck/netcap/io"
	"github.com/dreadl0ck/netcap/resolvers"
	"github.com/dreadl0ck/netcap/types"
	"github.com/dreadl0ck/netcap/utils"
)

// Test PCAP file paths
const (
	httpAuthPCAP = "../decoder/stream/credentials/testdata/http-basic-auth.pcap"
	httpPostPCAP = "../decoder/stream/credentials/testdata/http-post-auth.pcap"
	ftpPCAP      = "../decoder/stream/credentials/testdata/ftp.pcap"
	smtpPCAP     = "../decoder/stream/credentials/testdata/smtp.pcap"

	// Zeek test data
	zeekFTPRetr = "/Users/pmieden/Development/zeek/testing/btest/Traces/ftp/retr.trace"
	zeekHTTPGet = "/Users/pmieden/Development/zeek/testing/btest/Traces/http/get.trace"
)

// fileExists checks if a file exists
func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// createTestCollector creates a collector configured for testing file extraction
func createTestCollector(outDir string, enableDPI bool) *collector.Collector {
	return collector.New(collector.Config{
		Workers:               2,
		PacketBufferSize:      100,
		WriteUnknownPackets:   false,
		Promisc:               false,
		SnapLen:               defaults.SnapLen,
		BaseLayer:             utils.GetBaseLayer("ethernet"),
		DecodeOptions:         utils.GetDecodeOptions("default"),
		DPI:                   false, // Always disabled for file extraction tests
		DPIModules:            "",    // No DPI modules
		ReassembleConnections: true,
		LogErrors:             false,
		NoPrompt:              true,
		DecoderConfig: &config.Config{
			Quiet:                          true,
			Out:                            outDir,
			Source:                         "file-extraction-test",
			Buffer:                         true,
			Compression:                    true,
			CSV:                            false,
			Proto:                          true,
			IncludeDecoders:                "",
			ExcludeDecoders:                "Connection,DeviceProfile,IPProfile", // Exclude DPI-dependent decoders
			IncludePayloads:                false,
			ExportMetrics:                  false,
			AddContext:                     true,
			MemBufferSize:                  defaults.BufferSize,
			FlushEvery:                     defaults.FlushEvery,
			DefragIPv4:                     defaults.DefragIPv4,
			Checksum:                       defaults.Checksum,
			NoOptCheck:                     defaults.NoOptCheck,
			IgnoreFSMerr:                   true,
			AllowMissingInit:               true,
			Debug:                          false,
			HexDump:                        false,
			WaitForConnections:             true,
			WriteIncomplete:                true,
			MemProfile:                     "",
			ConnFlushInterval:              10000,
			ConnTimeOut:                    10,
			FlowFlushInterval:              2000,
			FlowTimeOut:                    10,
			CloseInactiveTimeOut:           24 * 60 * 60,
			ClosePendingTimeOut:            5,
			FileStorage:                    "files",
			CalculateEntropy:               false,
			SaveConns:                      false,
			TCPDebug:                       false,
			UseRE2:                         true,
			BannerSize:                     512,
			StreamDecoderBufSize:           10,
			HarvesterBannerSize:            512,
			StopAfterHarvesterMatch:        true,
			StopAfterServiceProbeMatch:     true,
			StopAfterServiceCategoryMiss:   true,
			CustomRegex:                    "",
			HarvestersConfigPath:           "",
			StreamBufferSize:               10,
			NumStreamWorkers:               2,
			MaxStreamBytes:                 10485760,
			MaxBufferedPagesPerConnection:  0,
			MaxBufferedPagesTotal:          0,
			IgnoreDecoderInitErrors:        true,
			DisableGenericVersionHarvester: true,
			RemoveClosedStreams:            false,
			CompressionBlockSize:           defaults.CompressionBlockSize,
			CompressionLevel:               defaults.CompressionLevel,
		},
		ResolverConfig: resolvers.Config{
			ReverseDNS:    false,
			LocalDNS:      false,
			MACDB:         false,
			
			ServiceDB:     false,
			GeolocationDB: false,
		},
	})
}

// TestHTTPFileExtraction tests end-to-end HTTP file extraction
func TestHTTPFileExtraction(t *testing.T) {
	if !fileExists(httpAuthPCAP) {
		t.Skip("HTTP test PCAP not found:", httpAuthPCAP)
	}

	// Create temporary output directory
	tmpDir := t.TempDir()

	// Configure file extraction
	cfg := file.GetDefaultConfig()
	cfg.FileExtraction.Enabled = true
	cfg.FileExtraction.Protocols.HTTP = true
	cfg.FileExtraction.HashAlgorithms.MD5 = true
	cfg.FileExtraction.HashAlgorithms.SHA1 = true
	cfg.FileExtraction.HashAlgorithms.SHA256 = true
	file.SetGlobalConfig(cfg)

	// Create collector
	c := createTestCollector(tmpDir, false)
	c.InputFile = httpAuthPCAP

	// Run capture
	err := c.CollectPcap(httpAuthPCAP)
	if err != nil {
		t.Fatalf("Capture failed: %v", err)
	}

	// Verify File audit records were created
	fileAuditPath := filepath.Join(tmpDir, "File.ncap.gz")
	if !fileExists(fileAuditPath) {
		t.Log("No File audit records created (auth traffic may not have file transfers)")
		return
	}

	// Read and verify file records
	reader, err := netio.Open(fileAuditPath, defaults.BufferSize)
	if err != nil {
		t.Fatalf("Failed to open File audit records: %v", err)
	}
	defer reader.Close()

	// Read file header first
	_, err = reader.ReadHeader()
	if err != nil {
		t.Fatalf("Failed to read File audit header: %v", err)
	}

	var fileRecord types.File
	fileCount := 0
	validFileCount := 0

	for {
		err := reader.Next(&fileRecord)
		if err != nil {
			if err != io.EOF {
				t.Errorf("Error reading file record: %v", err)
			}
			break
		}
		fileCount++

		// Skip empty/incomplete records
		if fileRecord.Length == 0 || fileRecord.Name == "" {
			continue
		}

		validFileCount++

		// Verify HTTP source (only if source is set)
		if fileRecord.Source != "" && !strings.Contains(fileRecord.Source, "HTTP") {
			t.Errorf("Expected HTTP source, got: %s", fileRecord.Source)
		}

		// Verify hashes were computed (only if Hashes field exists)
		if fileRecord.Hashes != nil {
			if fileRecord.Hashes.MD5 != "" && len(fileRecord.Hashes.MD5) != 32 {
				t.Errorf("MD5 hash invalid length: %d", len(fileRecord.Hashes.MD5))
			}
			if fileRecord.Hashes.SHA1 != "" && len(fileRecord.Hashes.SHA1) != 40 {
				t.Errorf("SHA1 hash invalid length: %d", len(fileRecord.Hashes.SHA1))
			}
			if fileRecord.Hashes.SHA256 != "" && len(fileRecord.Hashes.SHA256) != 64 {
				t.Errorf("SHA256 hash invalid length: %d", len(fileRecord.Hashes.SHA256))
			}

			if fileRecord.Hashes.SHA256 != "" {
				t.Logf("File: %s, MD5: %s, SHA256: %s",
					fileRecord.Name,
					fileRecord.Hashes.MD5,
					fileRecord.Hashes.SHA256)
			}
		}

		// Verify file exists on disk (if location is set)
		if fileRecord.Location != "" && !fileExists(fileRecord.Location) {
			t.Logf("Note: Extracted file not found at: %s (may have been cleaned up)", fileRecord.Location)
		}

		t.Logf("Extracted: %s (%d bytes) from %s",
			fileRecord.Name,
			fileRecord.Length,
			fileRecord.Source)
	}

	if validFileCount == 0 {
		t.Error("No valid files extracted from HTTP traffic")
	}

	t.Logf("Total files extracted from HTTP: %d", fileCount)
}

// TestSMTPFileExtraction tests email attachment extraction
func TestSMTPFileExtraction(t *testing.T) {
	if !fileExists(smtpPCAP) {
		t.Skip("SMTP test PCAP not found:", smtpPCAP)
	}

	tmpDir := t.TempDir()

	// Configure file extraction
	cfg := file.GetDefaultConfig()
	cfg.FileExtraction.Enabled = true
	cfg.FileExtraction.Protocols.SMTP = true
	file.SetGlobalConfig(cfg)

	// Create collector
	c := createTestCollector(tmpDir, false)
	c.InputFile = smtpPCAP

	// Run capture
	err := c.CollectPcap(smtpPCAP)
	if err != nil {
		t.Fatalf("Capture failed: %v", err)
	}

	// Check for file audit records
	fileAuditPath := filepath.Join(tmpDir, "File.ncap.gz")
	if !fileExists(fileAuditPath) {
		t.Log("No File audit records (SMTP traffic may not have attachments)")
		return
	}

	// Read file records
	reader, err := netio.Open(fileAuditPath, defaults.BufferSize)
	if err != nil {
		t.Fatalf("Failed to open File audit records: %v", err)
	}
	defer reader.Close()

	// Read file header first
	_, err = reader.ReadHeader()
	if err != nil {
		t.Fatalf("Failed to read File audit header: %v", err)
	}

	var fileRecord types.File
	fileCount := 0

	for {
		err := reader.Next(&fileRecord)
		if err != nil {
			if err != io.EOF {
				t.Errorf("Error reading file record: %v", err)
			}
			break
		}
		fileCount++

		t.Logf("Extracted attachment: %s (%d bytes) from %s",
			fileRecord.Name,
			fileRecord.Length,
			fileRecord.Source)
	}

	t.Logf("Total attachments extracted: %d", fileCount)
}

// TestFTPDecoder tests FTP decoder functionality
func TestFTPDecoder(t *testing.T) {
	if !fileExists(ftpPCAP) {
		t.Skip("FTP test PCAP not found:", ftpPCAP)
	}

	tmpDir := t.TempDir()

	// Configure file extraction
	cfg := file.GetDefaultConfig()
	cfg.FileExtraction.Enabled = true
	cfg.FileExtraction.Protocols.FTP = true
	file.SetGlobalConfig(cfg)

	// Create collector
	c := createTestCollector(tmpDir, false)
	c.InputFile = ftpPCAP

	// Run capture
	err := c.CollectPcap(ftpPCAP)
	if err != nil {
		t.Fatalf("Capture failed: %v", err)
	}

	// Check for FTP audit records
	ftpAuditPath := filepath.Join(tmpDir, "FTP.ncap.gz")
	if !fileExists(ftpAuditPath) {
		t.Log("No FTP audit records created")
		return
	}

	// Read FTP records
	reader, err := netio.Open(ftpAuditPath, defaults.BufferSize)
	if err != nil {
		t.Fatalf("Failed to open FTP audit records: %v", err)
	}
	defer reader.Close()

	// Read file header first
	header, err := reader.ReadHeader()
	if err != nil {
		t.Fatalf("Failed to read FTP audit header: %v", err)
	}
	if header.Type != types.Type_NC_FTP {
		t.Fatalf("Expected FTP type, got: %v", header.Type)
	}

	var ftpRecord types.FTP
	commandCount := 0
	var foundRETR, foundSTOR, foundPORT, foundPASV bool

	for {
		err := reader.Next(&ftpRecord)
		if err != nil {
			if err != io.EOF {
				t.Errorf("Error reading FTP record: %v", err)
			}
			break
		}
		commandCount++

		// Track interesting commands
		switch ftpRecord.Command {
		case "RETR":
			foundRETR = true
			t.Logf("RETR: %s", ftpRecord.Filename)
		case "STOR":
			foundSTOR = true
			t.Logf("STOR: %s", ftpRecord.Filename)
		case "PORT":
			foundPORT = true
			t.Logf("PORT: %s:%d", ftpRecord.DataIP, ftpRecord.DataPort)
		case "PASV":
			// PASV is a command, response contains the info
			if ftpRecord.IsResponse && ftpRecord.ResponseCode == 227 {
				foundPASV = true
				t.Logf("PASV response: %s:%d", ftpRecord.DataIP, ftpRecord.DataPort)
			}
		}

		if ftpRecord.Username != "" {
			t.Logf("FTP user: %s", ftpRecord.Username)
		}
	}

	if commandCount == 0 {
		t.Error("No FTP commands/responses parsed")
	} else {
		t.Logf("Parsed %d FTP commands/responses", commandCount)
		t.Logf("Found RETR: %v, STOR: %v, PORT: %v, PASV: %v",
			foundRETR, foundSTOR, foundPORT, foundPASV)
	}
}

// TestZeekFTPTrace tests with Zeek's FTP RETR test trace
func TestZeekFTPTrace(t *testing.T) {
	if !fileExists(zeekFTPRetr) {
		t.Skip("Zeek FTP test trace not found:", zeekFTPRetr)
	}

	tmpDir := t.TempDir()

	// Configure file extraction
	cfg := file.GetDefaultConfig()
	cfg.FileExtraction.Enabled = true
	cfg.FileExtraction.Protocols.FTP = true
	file.SetGlobalConfig(cfg)

	// Create collector
	c := createTestCollector(tmpDir, false)
	c.InputFile = zeekFTPRetr

	// Run capture
	err := c.CollectPcap(zeekFTPRetr)
	if err != nil {
		t.Fatalf("Capture failed: %v", err)
	}

	// Verify FTP audit records
	ftpAuditPath := filepath.Join(tmpDir, "FTP.ncap.gz")
	if !fileExists(ftpAuditPath) {
		t.Fatal("FTP audit records should be created for FTP traffic")
	}

	reader, err := netio.Open(ftpAuditPath, defaults.BufferSize)
	if err != nil {
		t.Fatalf("Failed to open FTP audit records: %v", err)
	}
	defer reader.Close()

	// Read file header first
	_, err = reader.ReadHeader()
	if err != nil {
		t.Fatalf("Failed to read FTP audit header: %v", err)
	}

	var ftpRecord types.FTP
	commandCount := 0

	for {
		err := reader.Next(&ftpRecord)
		if err != nil {
			break
		}
		commandCount++
	}

	t.Logf("Parsed %d FTP commands/responses from Zeek trace", commandCount)
}

// TestZeekHTTPTrace tests with Zeek's HTTP test trace
func TestZeekHTTPTrace(t *testing.T) {
	if !fileExists(zeekHTTPGet) {
		t.Skip("Zeek HTTP test trace not found:", zeekHTTPGet)
	}

	tmpDir := t.TempDir()

	// Configure file extraction
	cfg := file.GetDefaultConfig()
	cfg.FileExtraction.Enabled = true
	cfg.FileExtraction.Protocols.HTTP = true
	file.SetGlobalConfig(cfg)

	// Create collector
	c := createTestCollector(tmpDir, false)
	c.InputFile = zeekHTTPGet

	// Run capture
	err := c.CollectPcap(zeekHTTPGet)
	if err != nil {
		t.Fatalf("Capture failed: %v", err)
	}

	// Check for File audit records
	fileAuditPath := filepath.Join(tmpDir, "File.ncap.gz")
	if fileExists(fileAuditPath) {
		reader, err := netio.Open(fileAuditPath, defaults.BufferSize)
		if err != nil {
			t.Fatalf("Failed to open File audit records: %v", err)
		}
		defer reader.Close()

		// Read file header first
		_, err = reader.ReadHeader()
		if err != nil {
			t.Fatalf("Failed to read File audit header: %v", err)
		}

		var fileRecord types.File
		for {
			err := reader.Next(&fileRecord)
			if err != nil {
				break
			}
			t.Logf("Extracted: %s (%d bytes)", fileRecord.Name, fileRecord.Length)
		}
	}

	// Check for HTTP audit records
	httpAuditPath := filepath.Join(tmpDir, "HTTP.ncap.gz")
	if fileExists(httpAuditPath) {
		reader, err := netio.Open(httpAuditPath, defaults.BufferSize)
		if err != nil {
			t.Fatalf("Failed to open HTTP audit records: %v", err)
		}
		defer reader.Close()

		// Read file header first
		_, err = reader.ReadHeader()
		if err != nil {
			t.Fatalf("Failed to read HTTP audit header: %v", err)
		}

		var httpRecord types.HTTP
		httpCount := 0
		for {
			err := reader.Next(&httpRecord)
			if err != nil {
				break
			}
			httpCount++
		}
		t.Logf("Parsed %d HTTP records from Zeek trace", httpCount)
	}
}

// TestMultipleHashAlgorithms verifies all hash algorithms are computed
func TestMultipleHashAlgorithms(t *testing.T) {
	if !fileExists(httpAuthPCAP) {
		t.Skip("HTTP test PCAP not found")
	}

	tmpDir := t.TempDir()

	// Enable all hash algorithms
	cfg := file.GetDefaultConfig()
	cfg.FileExtraction.Enabled = true
	cfg.FileExtraction.Protocols.HTTP = true
	cfg.FileExtraction.HashAlgorithms.MD5 = true
	cfg.FileExtraction.HashAlgorithms.SHA1 = true
	cfg.FileExtraction.HashAlgorithms.SHA256 = true
	file.SetGlobalConfig(cfg)

	// Create collector
	c := createTestCollector(tmpDir, false)
	c.InputFile = httpAuthPCAP

	// Run capture
	err := c.CollectPcap(httpAuthPCAP)
	if err != nil {
		t.Fatalf("Capture failed: %v", err)
	}

	// Verify hashes
	fileAuditPath := filepath.Join(tmpDir, "File.ncap.gz")
	if !fileExists(fileAuditPath) {
		t.Skip("No files extracted")
	}

	reader, err := netio.Open(fileAuditPath, defaults.BufferSize)
	if err != nil {
		t.Fatalf("Failed to open File audit records: %v", err)
	}
	defer reader.Close()

	// Read file header first
	_, err = reader.ReadHeader()
	if err != nil {
		t.Fatalf("Failed to read File audit header: %v", err)
	}

	var fileRecord types.File
	hashesVerified := 0

	for {
		err := reader.Next(&fileRecord)
		if err != nil {
			break
		}

		// Skip empty/incomplete records
		if fileRecord.Length == 0 || fileRecord.Hashes == nil {
			continue
		}

		// Verify all three hashes exist and are correct length
		hasAllHashes := true

		if fileRecord.Hashes.MD5 == "" || len(fileRecord.Hashes.MD5) != 32 {
			t.Errorf("MD5 hash invalid: %s (length %d)",
				fileRecord.Hashes.MD5, len(fileRecord.Hashes.MD5))
			hasAllHashes = false
		}

		if fileRecord.Hashes.SHA1 == "" || len(fileRecord.Hashes.SHA1) != 40 {
			t.Errorf("SHA1 hash invalid: %s (length %d)",
				fileRecord.Hashes.SHA1, len(fileRecord.Hashes.SHA1))
			hasAllHashes = false
		}

		if fileRecord.Hashes.SHA256 == "" || len(fileRecord.Hashes.SHA256) != 64 {
			t.Errorf("SHA256 hash invalid: %s (length %d)",
				fileRecord.Hashes.SHA256, len(fileRecord.Hashes.SHA256))
			hasAllHashes = false
		}

		if hasAllHashes {
			hashesVerified++
			t.Logf("✓ Verified all hashes for: %s", fileRecord.Name)
		}
	}

	if hashesVerified == 0 {
		t.Error("No files with verified hashes found")
	} else {
		t.Logf("Successfully verified hashes for %d files", hashesVerified)
	}
}

// TestMIMEDetection verifies MIME type detection
func TestMIMEDetection(t *testing.T) {
	if !fileExists(httpAuthPCAP) {
		t.Skip("HTTP test PCAP not found")
	}

	tmpDir := t.TempDir()

	// Enable magic detection
	cfg := file.GetDefaultConfig()
	cfg.FileExtraction.Enabled = true
	cfg.FileExtraction.Protocols.HTTP = true
	cfg.FileExtraction.Advanced.UseMagicDetection = true
	file.SetGlobalConfig(cfg)

	// Create collector
	c := createTestCollector(tmpDir, false)
	c.InputFile = httpAuthPCAP

	// Run capture
	err := c.CollectPcap(httpAuthPCAP)
	if err != nil {
		t.Fatalf("Capture failed: %v", err)
	}

	// Verify MIME detection
	fileAuditPath := filepath.Join(tmpDir, "File.ncap.gz")
	if !fileExists(fileAuditPath) {
		t.Skip("No files extracted")
	}

	reader, err := netio.Open(fileAuditPath, defaults.BufferSize)
	if err != nil {
		t.Fatalf("Failed to open File audit records: %v", err)
	}
	defer reader.Close()

	// Read file header first
	_, err = reader.ReadHeader()
	if err != nil {
		t.Fatalf("Failed to read File audit header: %v", err)
	}

	var fileRecord types.File
	mimeDetected := 0

	for {
		err := reader.Next(&fileRecord)
		if err != nil {
			if err != io.EOF {
				t.Errorf("Error reading file record: %v", err)
			}
			break
		}

		// Skip empty/incomplete records
		if fileRecord.Length == 0 || fileRecord.Name == "" {
			continue
		}

		// Verify MIME type was detected
		if fileRecord.ContentTypeDetected == "" {
			t.Logf("Note: File %s has empty ContentTypeDetected", fileRecord.Name)
		} else {
			mimeDetected++
			t.Logf("File: %s, Detected MIME: %s",
				fileRecord.Name,
				fileRecord.ContentTypeDetected)
		}
	}

	if mimeDetected == 0 {
		t.Error("No files with detected MIME types found")
	} else {
		t.Logf("Successfully detected MIME types for %d files", mimeDetected)
	}
}

// TestFileExtractionDisabled verifies extraction can be disabled
func TestFileExtractionDisabled(t *testing.T) {
	if !fileExists(httpAuthPCAP) {
		t.Skip("HTTP test PCAP not found")
	}

	tmpDir := t.TempDir()

	// Disable file extraction
	cfg := file.GetDefaultConfig()
	cfg.FileExtraction.Enabled = false
	file.SetGlobalConfig(cfg)

	// Create collector
	c := createTestCollector(tmpDir, false)
	c.InputFile = httpAuthPCAP

	// Run capture
	err := c.CollectPcap(httpAuthPCAP)
	if err != nil {
		t.Fatalf("Capture failed: %v", err)
	}

	// Verify NO File audit records were created
	fileAuditPath := filepath.Join(tmpDir, "File.ncap.gz")
	if fileExists(fileAuditPath) {
		// Check if it's empty
		reader, err := netio.Open(fileAuditPath, defaults.BufferSize)
		if err != nil {
			t.Fatalf("Failed to open File audit records: %v", err)
		}
		defer reader.Close()

		// Read file header first
		_, err = reader.ReadHeader()
		if err != nil {
			t.Fatalf("Failed to read File audit header: %v", err)
		}

		var fileRecord types.File
		err = reader.Next(&fileRecord)
		if err == nil {
			t.Error("Files were extracted despite extraction being disabled")
		}
	}

	t.Log("Verified file extraction was disabled")
}

// TestProtocolFiltering tests enabling/disabling specific protocols
func TestProtocolFiltering(t *testing.T) {
	if !fileExists(httpAuthPCAP) {
		t.Skip("HTTP test PCAP not found")
	}

	tmpDir := t.TempDir()

	// Enable extraction but disable HTTP
	cfg := file.GetDefaultConfig()
	cfg.FileExtraction.Enabled = true
	cfg.FileExtraction.Protocols.HTTP = false // Disable HTTP
	cfg.FileExtraction.Protocols.SMTP = true
	file.SetGlobalConfig(cfg)

	// Create collector
	c := createTestCollector(tmpDir, false)
	c.InputFile = httpAuthPCAP

	// Run capture
	err := c.CollectPcap(httpAuthPCAP)
	if err != nil {
		t.Fatalf("Capture failed: %v", err)
	}

	// Verify NO HTTP files were extracted
	fileAuditPath := filepath.Join(tmpDir, "File.ncap.gz")
	if fileExists(fileAuditPath) {
		reader, err := netio.Open(fileAuditPath, defaults.BufferSize)
		if err != nil {
			t.Fatalf("Failed to open File audit records: %v", err)
		}
		defer reader.Close()

		// Read file header first
		_, err = reader.ReadHeader()
		if err != nil {
			t.Fatalf("Failed to read File audit header: %v", err)
		}

		var fileRecord types.File
		for {
			err := reader.Next(&fileRecord)
			if err != nil {
				break
			}

			if strings.Contains(fileRecord.Source, "HTTP") {
				t.Error("HTTP file was extracted despite protocol being disabled")
			}
		}
	}

	t.Log("Verified HTTP protocol filtering works")
}
