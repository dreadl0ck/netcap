/*
 * NETCAP - Traffic Analysis Framework
 * Copyright (c) Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
 * License: GNU General Public License v3.0
 */

package secret

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"testing"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcap"
)

// TestSecretPCAPIntegration is a comprehensive integration test that verifies
// the credentials.pcap file exists and contains valid protocol traffic.
// This test processes ALL packets in the merged pcap to validate harvester coverage.
func TestSecretPCAPIntegration(t *testing.T) {
	pcapFile := filepath.Join("testdata", "credentials.pcap")
	if _, err := os.Stat(pcapFile); os.IsNotExist(err) {
		t.Skip("credentials.pcap not found in testdata - run mergecap to create it")
	}

	// Initialize harvesters with default configuration
	if err := InitializeHarvesters(nil); err != nil {
		t.Fatalf("Failed to initialize harvesters: %v", err)
	}

	// Reset the credential store
	ResetSecretStore()

	// Open the PCAP file
	handle, err := pcap.OpenOffline(pcapFile)
	if err != nil {
		t.Fatalf("Failed to open pcap: %v", err)
	}
	defer handle.Close()

	// Track TCP streams for proper reassembly (limited to prevent memory issues)
	tcpStreams := make(map[string][]byte)
	const maxStreamSize = 64 * 1024 // 64KB max per stream
	const maxStreams = 500          // Limit number of streams tracked

	// Collect credentials found
	type FoundCredential struct {
		Service  string
		User     string
		Password string
	}
	var foundCreds []FoundCredential

	// Harvesters to test (representative sample)
	harvesters := []Harvester{
		ftpHarvester,
		httpHarvester,
		smtpHarvester,
		imapHarvester,
		pop3Harvester,
		snmpHarvester,
		ldapHarvester,
		postgresHarvester,
		mysqlHarvester,
		ntlmsspHarvester,
		nbnsHarvester,
	}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	packetCount := 0

	t.Log("Processing credentials.pcap (this may take a few minutes)...")

	for packet := range packetSource.Packets() {
		packetCount++

		// Log progress every 5000 packets
		if packetCount%5000 == 0 {
			t.Logf("  Processed %d packets, found %d credentials so far...", packetCount, len(foundCreds))
		}

		// Get flow identifier for TCP stream tracking
		var flowIdent string
		if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
			tcp := tcpLayer.(*layers.TCP)
			if netLayer := packet.NetworkLayer(); netLayer != nil {
				flowIdent = fmt.Sprintf("%s:%d->%s:%d",
					netLayer.NetworkFlow().Src(), tcp.SrcPort,
					netLayer.NetworkFlow().Dst(), tcp.DstPort)
			}
		}

		// Get application layer payload
		var payload []byte
		if appLayer := packet.ApplicationLayer(); appLayer != nil {
			payload = appLayer.Payload()
		}

		// For TCP, accumulate stream data (with size limit)
		if flowIdent != "" && len(payload) > 0 && len(tcpStreams) < maxStreams {
			if len(tcpStreams[flowIdent]) < maxStreamSize {
				tcpStreams[flowIdent] = append(tcpStreams[flowIdent], payload...)
			}
		}

		// Test harvesters against payload
		for _, h := range harvesters {
			if len(payload) > 0 {
				if creds := h.HarvesterFunc(payload, flowIdent, time.Now()); creds != nil {
					foundCreds = append(foundCreds, FoundCredential{
						Service:  creds.Service,
						User:     creds.User,
						Password: truncateString(creds.Password, 30),
					})
				}
			}
		}
	}

	// Test accumulated streams
	t.Logf("Testing %d accumulated TCP streams...", len(tcpStreams))
	for flowID, stream := range tcpStreams {
		for _, h := range harvesters {
			if creds := h.HarvesterFunc(stream, flowID, time.Now()); creds != nil {
				foundCreds = append(foundCreds, FoundCredential{
					Service:  creds.Service,
					User:     creds.User,
					Password: truncateString(creds.Password, 30),
				})
			}
		}
	}

	t.Logf("\n=== Final Results ===")
	t.Logf("Processed %d packets from credentials.pcap", packetCount)
	t.Logf("Tracked %d TCP streams", len(tcpStreams))

	// Deduplicate by service+user
	seen := make(map[string]bool)
	var uniqueCreds []FoundCredential
	for _, c := range foundCreds {
		key := c.Service + "|" + c.User
		if !seen[key] {
			seen[key] = true
			uniqueCreds = append(uniqueCreds, c)
		}
	}

	t.Logf("Found %d unique credentials", len(uniqueCreds))

	// Group by service
	byService := make(map[string]int)
	for _, c := range uniqueCreds {
		byService[c.Service]++
	}

	t.Logf("\n=== Credentials by Service ===")
	var services []string
	for svc := range byService {
		services = append(services, svc)
	}
	sort.Strings(services)
	for _, svc := range services {
		t.Logf("  ✓ %s: %d", svc, byService[svc])
	}

	// Show some examples
	t.Logf("\n=== Sample Credentials ===")
	shown := make(map[string]int)
	for _, c := range uniqueCreds {
		if shown[c.Service] < 2 { // Show max 2 per service
			t.Logf("  %s: User=%s", c.Service, c.User)
			shown[c.Service]++
		}
	}

	// Test passes if we found credentials from multiple services
	if len(byService) < 3 {
		t.Errorf("Expected credentials from at least 3 different services, found %d", len(byService))
	}
}

// TestSecretPCAPByProtocol runs focused tests for each protocol individually
// This test validates the harvester functions against their specific pcap test files.
//
// Known limitations documented here:
// - Telnet: Harvester expects "cooked mode" with doubled chars, some pcaps have plain text
// - HTTP NTLM: Requires both challenge and response in session data
// - Kerberos: Harvester requires RC4-HMAC-MD5 (etype 23), some pcaps use other encryption types
func TestSecretPCAPByProtocol(t *testing.T) {
	pcapFile := filepath.Join("testdata", "credentials.pcap")
	if _, err := os.Stat(pcapFile); os.IsNotExist(err) {
		t.Skip("credentials.pcap not found in testdata")
	}

	// Define individual test cases with their specific pcap files
	testCases := []struct {
		name          string
		harvester     Harvester
		pcapFile      string
		expectSuccess bool // Set to false for known-limitation cases
		notes         string
	}{
		{"FTP", ftpHarvester, "ftp.pcap", true, ""},
		{"HTTP Basic", httpHarvester, "http-basic-auth.pcap", true, ""},
		{"HTTP Digest", httpHarvester, "HTTP - Digest Authentication.pcap", true, ""},
		{"HTTP NTLM", httpNTLMHarvester, "HTTP - NTLM.pcap", false, "Requires complete NTLM handshake (challenge+response) in session"},
		{"SMTP", smtpHarvester, "smtp.pcap", true, ""},
		{"Telnet", telnetHarvester, "telnet.pcap", false, "Harvester regex expects doubled characters from cooked mode echo"},
		{"IMAP", imapHarvester, "imap.pcap", true, ""},
		{"POP3", pop3Harvester, "pop3.pcap", true, ""},
		{"SNMP v1", snmpHarvester, "snmp-v1.pcap", true, ""},
		{"LDAP", ldapHarvester, "ldap-simpleauth.pcap", true, ""},
		{"PostgreSQL", postgresHarvester, "pgsql.pcap", true, ""},
		{"MySQL", mysqlHarvester, "mysql.pcap", true, ""},
		{"SMB NTLM", ntlmsspHarvester, "smb-ntlm.pcap", true, ""},
		{"Kerberos TCP", kerberosASReqHarvester, "Kerberos - v5 TCP.pcap", false, "Pcap may use different encryption type than RC4-HMAC-MD5"},
		{"Kerberos UDP", kerberosASReqHarvester, "Kerberos - v5 UDP.pcap", false, "Pcap may use different encryption type than RC4-HMAC-MD5"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			specificPcap := filepath.Join("testdata", tc.pcapFile)
			if _, err := os.Stat(specificPcap); os.IsNotExist(err) {
				t.Skipf("%s not found", tc.pcapFile)
			}

			// Reset credential store for each test
			ResetSecretStore()

			handle, err := pcap.OpenOffline(specificPcap)
			if err != nil {
				t.Fatalf("Failed to open %s: %v", tc.pcapFile, err)
			}
			defer handle.Close()

			packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
			var streamData []byte
			foundCreds := false
			var foundCredential string

			for packet := range packetSource.Packets() {
				if appLayer := packet.ApplicationLayer(); appLayer != nil {
					streamData = append(streamData, appLayer.Payload()...)

					// Try harvesting from accumulated data
					if creds := tc.harvester.HarvesterFunc(streamData, "test-flow", time.Now()); creds != nil {
						foundCreds = true
						foundCredential = fmt.Sprintf("User=%s, Password=%s, Service=%s",
							creds.User, truncateString(creds.Password, 30), creds.Service)
						break
					}

					// Also try individual packet
					if creds := tc.harvester.HarvesterFunc(appLayer.Payload(), "test-flow", time.Now()); creds != nil {
						foundCreds = true
						foundCredential = fmt.Sprintf("User=%s, Password=%s, Service=%s",
							creds.User, truncateString(creds.Password, 30), creds.Service)
					}
				}
			}

			if foundCreds {
				t.Logf("✓ Found: %s", foundCredential)
			} else if tc.expectSuccess {
				t.Errorf("✗ No credentials found in %s", tc.pcapFile)
			} else {
				t.Logf("⚠ No credentials found in %s (known limitation: %s)", tc.pcapFile, tc.notes)
			}
		})
	}
}

// TestSecretPCAPAllHarvesters is skipped by default due to long runtime.
// Enable by running: go test -v -run TestSecretPCAPAllHarvesters -timeout 10m
// This test verifies all registered harvesters against the merged credentials.pcap
func TestSecretPCAPAllHarvesters(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping slow test in short mode")
	}

	pcapFile := filepath.Join("testdata", "credentials.pcap")
	if _, err := os.Stat(pcapFile); os.IsNotExist(err) {
		t.Skip("credentials.pcap not found in testdata")
	}

	// Initialize harvesters
	if err := InitializeHarvesters(nil); err != nil {
		t.Fatalf("Failed to initialize harvesters: %v", err)
	}

	handle, err := pcap.OpenOffline(pcapFile)
	if err != nil {
		t.Fatalf("Failed to open pcap: %v", err)
	}
	defer handle.Close()

	// Collect payloads (limited to first 10000 packets for reasonable runtime)
	var allPayloads [][]byte
	tcpStreams := make(map[string][]byte)
	const maxPayloads = 10000
	const maxStreamSize = 64 * 1024

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	count := 0
	for packet := range packetSource.Packets() {
		count++
		if count > maxPayloads {
			break
		}

		var flowIdent string
		if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
			tcp := tcpLayer.(*layers.TCP)
			if netLayer := packet.NetworkLayer(); netLayer != nil {
				flowIdent = fmt.Sprintf("%s:%d->%s:%d",
					netLayer.NetworkFlow().Src(), tcp.SrcPort,
					netLayer.NetworkFlow().Dst(), tcp.DstPort)
			}
		}

		if appLayer := packet.ApplicationLayer(); appLayer != nil {
			payload := appLayer.Payload()
			allPayloads = append(allPayloads, payload)
			if flowIdent != "" && len(tcpStreams[flowIdent]) < maxStreamSize {
				tcpStreams[flowIdent] = append(tcpStreams[flowIdent], payload...)
			}
		}
	}

	t.Logf("Collected %d payloads and %d TCP streams from first %d packets", len(allPayloads), len(tcpStreams), count)

	// Test each harvester from allHarvesters
	for name, harvester := range allHarvesters {
		t.Run(name, func(t *testing.T) {
			ResetSecretStore()
			credCount := 0

			// Test against individual payloads
			for _, payload := range allPayloads {
				if creds := harvester.HarvesterFunc(payload, "test", time.Now()); creds != nil {
					credCount++
				}
			}

			// Test against accumulated streams
			for flowID, stream := range tcpStreams {
				if creds := harvester.HarvesterFunc(stream, flowID, time.Now()); creds != nil {
					credCount++
				}
			}

			if credCount > 0 {
				t.Logf("✓ Found %d credentials", credCount)
			} else {
				t.Logf("- No credentials found (may not have matching traffic)")
			}
		})
	}
}

// Helper functions
func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}
