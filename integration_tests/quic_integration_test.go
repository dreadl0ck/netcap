/*
 * NETCAP - Traffic Analysis Framework
 * Copyright (c) Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
 * License: GNU General Public License v3.0
 */

package integration_tests

import (
	"fmt"
	stdio "io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dreadl0ck/netcap/collector"
	decoderconfig "github.com/dreadl0ck/netcap/decoder/config"
	netio "github.com/dreadl0ck/netcap/io"
	"github.com/dreadl0ck/netcap/types"
)

const quicTestdataDir = "../decoder/stream/quic/testdata"

// TestQUICIntegration is a full integration test that processes QUIC pcap files
// through the netcap collector and verifies QUICClientHello audit records are produced.
func TestQUICIntegration(t *testing.T) {
	testCases := []struct {
		name            string
		pcapFile        string
		expectedSNI     string
		expectedALPN    string
		expectJA4Start  string
		minRecords      int
		isGQUIC         bool // gQUIC uses different ClientHello format
		expectNoRecords bool // Some pcaps may not produce QUIC records (e.g., encrypted or TCP)
		description     string
	}{
		{
			name:           "IETF_QUIC_Draft29",
			pcapFile:       "wireshark-quic_follow_multistream.pcapng",
			expectedSNI:    "www.youtube.com",
			expectedALPN:   "h3-29",
			expectJA4Start: "q",
			minRecords:     1,
			isGQUIC:        false,
			description:    "IETF QUIC draft-29 multistream to YouTube",
		},
		{
			name:           "IETF_QUIC_v1_WithTokens",
			pcapFile:       "nDPI-quic_crypto_aes_auth_size.pcap",
			expectedSNI:    "gcp.api.snapchat.com", // One of the SNIs in the pcap
			expectedALPN:   "h3",
			expectJA4Start: "q",
			minRecords:     2, // Both packets contain ClientHello
			isGQUIC:        false,
			description:    "IETF QUIC v1 Initial packets with tokens (Snapchat endpoints)",
		},
		{
			name:           "gQUIC_Google",
			pcapFile:       "nDPI-quic.pcap",
			expectedSNI:    "i.ytimg.com", // One of the SNIs in the pcap
			expectedALPN:   "",            // gQUIC doesn't use ALPN
			expectJA4Start: "q",           // JA4 starts with 'q' for all QUIC
			minRecords:     10,
			isGQUIC:        true, // Primarily gQUIC (may have mixed records)
			description:    "gQUIC traffic to Google services (Q024, Q025, Q030)",
		},
		{
			name:           "gQUIC_YouTube",
			pcapFile:       "nDPI-youtube_quic.pcap",
			expectedSNI:    "www.youtube.com",
			expectedALPN:   "",
			expectJA4Start: "q", // JA4 starts with 'q' for all QUIC
			minRecords:     10,
			isGQUIC:        true, // Primarily gQUIC (may have mixed records)
			description:    "gQUIC traffic to YouTube",
		},
		{
			name:           "QUIC_With_Secrets",
			pcapFile:       "wireshark-quic-with-secrets.pcapng",
			expectedSNI:    "cloudflare-quic.com", // IETF QUIC traffic to Cloudflare
			expectedALPN:   "h3",
			expectJA4Start: "q", // JA4 starts with 'q' for all QUIC
			minRecords:     1,   // One Initial with ClientHello (others are server responses)
			isGQUIC:        false, // IETF QUIC v1
			description:    "IETF QUIC v1 traffic to Cloudflare with embedded TLS secrets",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Logf("Testing: %s", tc.description)

			pcapPath := filepath.Join(quicTestdataDir, tc.pcapFile)

			if _, err := os.Stat(pcapPath); os.IsNotExist(err) {
				t.Skipf("Test pcap file not found: %s", pcapPath)
			}

			// Create a temporary output directory
			outDir, err := os.MkdirTemp("", "quic-integration-test-*")
			if err != nil {
				t.Fatalf("Failed to create temp dir: %v", err)
			}
			defer os.RemoveAll(outDir)

			// Process the pcap using netcap collector
			err = processQUICWithCollector(pcapPath, outDir)
			if err != nil {
				t.Fatalf("Failed to process pcap with collector: %v", err)
			}

			// Check if QUICClientHello.ncap.gz was created
			quicFile := filepath.Join(outDir, "QUICClientHello.ncap.gz")
			info, err := os.Stat(quicFile)

			if tc.expectNoRecords {
				// For pcaps that aren't expected to produce QUIC records
				if os.IsNotExist(err) || (err == nil && info.Size() == 0) {
					t.Logf("✓ No QUICClientHello records produced (expected for %s)", tc.description)
					return
				}
				// If records were produced unexpectedly, log them but don't fail
				if err == nil && info.Size() > 0 {
					records, readErr := readQUICClientHelloRecords(quicFile)
					if readErr == nil && len(records) > 0 {
						t.Logf("Note: %d QUICClientHello record(s) produced (unexpected but not an error)", len(records))
						for i, rec := range records {
							t.Logf("  Record %d: SNI=%s, IsGQUIC=%v, IsIETFQUIC=%v",
								i+1, rec.SNI, !rec.IsIETFQUIC, rec.IsIETFQUIC)
						}
					}
				}
				return
			}

			// For pcaps expected to produce records
			if os.IsNotExist(err) {
				t.Fatalf("QUICClientHello.ncap.gz was not created")
			}
			if err != nil {
				t.Fatalf("Failed to stat QUICClientHello file: %v", err)
			}

			if info.Size() == 0 {
				t.Fatalf("QUICClientHello.ncap.gz is empty")
			}

			t.Logf("QUICClientHello.ncap.gz created with %d bytes", info.Size())

			// Read and verify the QUICClientHello records
			records, err := readQUICClientHelloRecords(quicFile)
			if err != nil {
				t.Fatalf("Failed to read QUICClientHello records: %v", err)
			}

			if len(records) < tc.minRecords {
				t.Errorf("Expected at least %d QUICClientHello record(s), got %d", tc.minRecords, len(records))
			}

			t.Logf("Found %d QUICClientHello record(s)", len(records))

			// Verify the content of records
			foundExpectedSNI := false
			foundExpectedALPN := false

			for i, rec := range records {
				t.Logf("Record %d:", i+1)
				t.Logf("  SNI: %s", rec.SNI)
				t.Logf("  ALPNs: %v", rec.ALPNs)
				t.Logf("  JA4: %s", rec.Ja4)
				t.Logf("  Version: %s", rec.QUICVersion)
				t.Logf("  IsIETFQUIC: %v", rec.IsIETFQUIC)
				t.Logf("  CipherSuites: %v", rec.CipherSuites)

				// Check for expected SNI
				if tc.expectedSNI != "" && rec.SNI == tc.expectedSNI {
					foundExpectedSNI = true
				}

				// Check for expected ALPN
				if tc.expectedALPN != "" {
					for _, alpn := range rec.ALPNs {
						if alpn == tc.expectedALPN {
							foundExpectedALPN = true
						}
					}
				}

				// Verify QUIC type matches expectation
				if tc.isGQUIC && rec.IsIETFQUIC {
					t.Logf("Warning: Expected gQUIC but got IETF QUIC record")
				}
				if !tc.isGQUIC && !rec.IsIETFQUIC && len(records) > 0 {
					t.Logf("Warning: Expected IETF QUIC but got gQUIC record")
				}

				// JA4 should start with expected prefix for QUIC
				if rec.Ja4 != "" && tc.expectJA4Start != "" && !strings.HasPrefix(rec.Ja4, tc.expectJA4Start) {
					t.Errorf("Record %d JA4 should start with '%s' for QUIC, got: %s", i+1, tc.expectJA4Start, rec.Ja4)
				}
			}

			if tc.expectedSNI != "" && !foundExpectedSNI {
				t.Errorf("Expected to find SNI=%s in records", tc.expectedSNI)
			}

			if tc.expectedALPN != "" && !foundExpectedALPN {
				t.Errorf("Expected to find ALPN=%s in records", tc.expectedALPN)
			}
		})
	}
}

// processQUICWithCollector processes a pcap file using the netcap collector
func processQUICWithCollector(pcapPath, outDir string) error {
	// Start with default config
	cfg := collector.DefaultConfig

	// Copy the default decoder config and modify it
	decoderCfg := *decoderconfig.DefaultConfig
	decoderCfg.Out = outDir
	decoderCfg.Source = pcapPath

	cfg.DecoderConfig = &decoderCfg

	// Enable TCP/UDP reassembly on the collector config
	cfg.ReassembleConnections = true

	// Create collector
	c := collector.New(cfg)

	// Process based on file type
	if filepath.Ext(pcapPath) == ".pcapng" {
		return c.CollectPcapNG(pcapPath)
	}
	return c.CollectPcap(pcapPath)
}

// readQUICClientHelloRecords reads QUICClientHello records from an ncap file
func readQUICClientHelloRecords(filename string) ([]*types.QUICClientHello, error) {
	r, err := netio.Open(filename, 4096)
	if err != nil {
		return nil, err
	}
	defer r.Close()

	// Read header
	header, err := r.ReadHeader()
	if err != nil {
		return nil, fmt.Errorf("failed to read header: %w", err)
	}

	if header.Type != types.Type_NC_QUICClientHello {
		return nil, fmt.Errorf("unexpected record type: %s", header.Type)
	}

	var records []*types.QUICClientHello

	for {
		rec := new(types.QUICClientHello)
		err = r.Next(rec)
		if err != nil {
			if err == stdio.EOF {
				break
			}
			return nil, fmt.Errorf("failed to read record: %w", err)
		}
		records = append(records, rec)
	}

	return records, nil
}
