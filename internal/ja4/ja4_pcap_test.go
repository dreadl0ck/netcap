/*
 * NETCAP - Traffic Analysis Framework
 * Copyright (c) Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
 * License: GNU General Public License v3.0
 */

package ja4_test

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/dreadl0ck/netcap/internal/ja4"
	"github.com/dreadl0ck/tlsx"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/pcap"
)

// TestJA4FromPCAP tests JA4 fingerprint computation against actual TLS traffic from PCAP files.
// This validates our implementation against real-world TLS handshakes.
func TestJA4FromPCAP(t *testing.T) {
	// Get project root
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("failed to get current file path")
	}
	projectRoot := filepath.Join(filepath.Dir(filename), "..", "..")

	// Test cases: PCAP files with known TLS traffic
	testCases := []struct {
		pcapFile    string
		description string
		expectJA4   bool // Whether we expect to find JA4 fingerprints
	}{
		{
			pcapFile:    "pcaps/nDPI-443-chrome.pcap",
			description: "Chrome TLS 1.3 traffic",
			expectJA4:   false, // Only 1 packet - incomplete handshake
		},
		{
			pcapFile:    "pcaps/nDPI-443-firefox.pcap",
			description: "Firefox TLS traffic",
			expectJA4:   true,
		},
		{
			pcapFile:    "pcaps/nDPI-443-curl.pcap",
			description: "curl HTTPS traffic",
			expectJA4:   true,
		},
		{
			pcapFile:    "pcaps/nDPI-443-safari.pcap",
			description: "Safari TLS traffic",
			expectJA4:   true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.description, func(t *testing.T) {
			pcapPath := filepath.Join(projectRoot, tc.pcapFile)

			// Check if PCAP exists
			if _, err := os.Stat(pcapPath); os.IsNotExist(err) {
				t.Skipf("PCAP file not found: %s", pcapPath)
				return
			}

			// Open PCAP file
			handle, err := pcap.OpenOffline(pcapPath)
			if err != nil {
				t.Fatalf("failed to open PCAP: %v", err)
			}
			defer handle.Close()

			// Process packets
			packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

			var ja4Count, ja4sCount int
			var ja4Fingerprints, ja4sFingerprints []string

			for packet := range packetSource.Packets() {
				// Try to extract TLS Client Hello
				ch := tlsx.GetClientHello(packet)
				if ch != nil {
					// Convert cipher suites
					cipherSuites := make([]uint16, len(ch.CipherSuites))
					for i, cs := range ch.CipherSuites {
						cipherSuites[i] = uint16(cs)
					}

					// Detect TLS 1.3 via cipher suites
					var supportedVers uint16
					for _, cs := range ch.CipherSuites {
						if uint16(cs) >= 0x1301 && uint16(cs) <= 0x1305 {
							supportedVers = 0x0304 // TLS 1.3
							break
						}
					}

					fp := ja4.ComputeJA4(&ja4.ClientHelloData{
						Version:       uint16(ch.Version),
						CipherSuites:  cipherSuites,
						Extensions:    ch.AllExtensions,
						SNI:           ch.SNI,
						ALPNs:         ch.ALPNs,
						SupportedVers: supportedVers,
						IsQUIC:        false,
					})

					if fp != "" {
						ja4Count++
						ja4Fingerprints = append(ja4Fingerprints, fp)
						t.Logf("JA4 fingerprint: %s (SNI: %s)", fp, ch.SNI)

						// Validate format
						if !ja4.ValidateJA4(fp) {
							t.Errorf("Invalid JA4 format: %s", fp)
						}
					}
				}

				// Try to extract TLS Server Hello
				sh := tlsx.GetServerHello(packet)
				if sh != nil {
					// Convert extensions
					extensions := make([]uint16, len(sh.Extensions))
					for i, ext := range sh.Extensions {
						extensions[i] = uint16(ext)
					}

					fp := ja4.ComputeJA4S(&ja4.ServerHelloData{
						Version:       uint16(sh.Vers),
						CipherSuite:   uint16(sh.CipherSuite),
						Extensions:    extensions,
						SupportedVers: sh.SupportedVersion,
						IsQUIC:        false,
					})

					if fp != "" {
						ja4sCount++
						ja4sFingerprints = append(ja4sFingerprints, fp)
						t.Logf("JA4S fingerprint: %s", fp)

						// Validate format
						if !ja4.ValidateJA4S(fp) {
							t.Errorf("Invalid JA4S format: %s", fp)
						}
					}
				}
			}

			// Report results
			t.Logf("Found %d JA4 fingerprints, %d JA4S fingerprints", ja4Count, ja4sCount)

			if tc.expectJA4 && ja4Count == 0 {
				t.Errorf("Expected JA4 fingerprints but found none")
			}

			// Verify uniqueness in fingerprints
			ja4Unique := make(map[string]int)
			for _, fp := range ja4Fingerprints {
				ja4Unique[fp]++
			}
			t.Logf("Unique JA4 fingerprints: %d", len(ja4Unique))

			// Log unique fingerprints with counts
			for fp, count := range ja4Unique {
				t.Logf("  %s (count: %d)", fp, count)
			}
		})
	}
}

// TestJA4FormatConsistency tests that JA4 fingerprints have consistent format
// according to the FoxIO specification.
func TestJA4FormatConsistency(t *testing.T) {
	// Test cases with expected format components
	testCases := []struct {
		name          string
		data          *ja4.ClientHelloData
		expectProto   string // t or q
		expectVersion string // 13, 12, 11, 10, s3
		expectSNI     string // d or i
	}{
		{
			name: "TLS 1.3 with domain",
			data: &ja4.ClientHelloData{
				Version:       0x0303, // TLS 1.2 (advertised)
				SupportedVers: 0x0304, // TLS 1.3 (negotiated)
				CipherSuites:  []uint16{0x1301, 0x1302},
				Extensions:    []uint16{0, 5, 10, 11},
				SNI:           "example.com",
				ALPNs:         []string{"h2"},
				IsQUIC:        false,
			},
			expectProto:   "t",
			expectVersion: "13",
			expectSNI:     "d",
		},
		{
			name: "TLS 1.2 without SNI",
			data: &ja4.ClientHelloData{
				Version:      0x0303,
				CipherSuites: []uint16{0xc02f, 0xc030},
				Extensions:   []uint16{5, 10, 11},
				SNI:          "",
				ALPNs:        nil,
				IsQUIC:       false,
			},
			expectProto:   "t",
			expectVersion: "12",
			expectSNI:     "i",
		},
		{
			name: "QUIC with IP as SNI",
			data: &ja4.ClientHelloData{
				Version:       0x0303,
				SupportedVers: 0x0304,
				CipherSuites:  []uint16{0x1301},
				Extensions:    []uint16{0, 5},
				SNI:           "192.168.1.1",
				ALPNs:         []string{"h3"},
				IsQUIC:        true,
			},
			expectProto:   "q",
			expectVersion: "13",
			expectSNI:     "i",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			fp := ja4.ComputeJA4(tc.data)
			t.Logf("JA4: %s", fp)

			// Parse and verify components
			if len(fp) < 10 {
				t.Fatalf("JA4 fingerprint too short: %s", fp)
			}

			// Extract ja4_a (first 10 chars before underscore)
			parts := splitJA4(fp)
			if len(parts) != 3 {
				t.Fatalf("Expected 3 parts in JA4, got %d: %s", len(parts), fp)
			}

			ja4a := parts[0]

			// Check protocol
			if string(ja4a[0]) != tc.expectProto {
				t.Errorf("Expected protocol %s, got %s", tc.expectProto, string(ja4a[0]))
			}

			// Check version
			if ja4a[1:3] != tc.expectVersion {
				t.Errorf("Expected version %s, got %s", tc.expectVersion, ja4a[1:3])
			}

			// Check SNI indicator
			if string(ja4a[3]) != tc.expectSNI {
				t.Errorf("Expected SNI indicator %s, got %s", tc.expectSNI, string(ja4a[3]))
			}
		})
	}
}

// splitJA4 splits a JA4 fingerprint into its three components
func splitJA4(fp string) []string {
	var parts []string
	var current string
	for _, c := range fp {
		if c == '_' {
			parts = append(parts, current)
			current = ""
		} else {
			current += string(c)
		}
	}
	if current != "" {
		parts = append(parts, current)
	}
	return parts
}

// TestJA4SDeterminism tests that JA4S produces consistent results
func TestJA4SDeterminism(t *testing.T) {
	data := &ja4.ServerHelloData{
		Version:     0x0303,
		CipherSuite: 0x1301,
		Extensions:  []uint16{0, 5, 11, 43, 51},
		IsQUIC:      false,
	}

	// Compute multiple times
	results := make(map[string]int)
	for range 100 {
		fp := ja4.ComputeJA4S(data)
		results[fp]++
	}

	if len(results) != 1 {
		t.Errorf("JA4S should be deterministic, got %d different results: %v", len(results), results)
	}

	for fp := range results {
		t.Logf("JA4S: %s", fp)
	}
}

// BenchmarkJA4 benchmarks JA4 computation performance
func BenchmarkJA4(b *testing.B) {
	data := &ja4.ClientHelloData{
		Version:       0x0303,
		SupportedVers: 0x0304,
		CipherSuites: []uint16{
			0x1301, 0x1302, 0x1303, 0xc02c, 0xc02b, 0xc030, 0xc02f,
			0x009f, 0x009e, 0xccaa, 0xccac, 0xc0a3, 0xc09f,
		},
		Extensions: []uint16{
			0, 5, 10, 11, 13, 16, 17, 23, 27, 35, 43, 45, 51, 65281,
		},
		SNI:   "www.example.com",
		ALPNs: []string{"h2", "http/1.1"},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ja4.ComputeJA4(data)
	}
}

// BenchmarkJA4S benchmarks JA4S computation performance
func BenchmarkJA4S(b *testing.B) {
	data := &ja4.ServerHelloData{
		Version:     0x0303,
		CipherSuite: 0x1301,
		Extensions:  []uint16{0, 5, 11, 43, 51},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ja4.ComputeJA4S(data)
	}
}
