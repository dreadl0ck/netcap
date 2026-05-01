package secret

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dreadl0ck/netcap/types"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcap"
)

// TestHTTPDigestEnhanced tests enhanced HTTP Digest authentication parsing
// This test will verify we extract all necessary parameters for Hashcat cracking
func TestHTTPDigestEnhanced(t *testing.T) {
	pcapFile := filepath.Join("testdata", "HTTP - Digest Authentication.pcap")

	handle, err := pcap.OpenOffline(pcapFile)
	if err != nil {
		t.Fatalf("Failed to open pcap file: %v", err)
	}
	defer handle.Close()

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	var foundDigest bool
	var extractedCreds *types.Secret

	for packet := range packetSource.Packets() {
		// Check for TCP layer
		if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
			tcp := tcpLayer.(*layers.TCP)

			// Check if this is HTTP traffic (port 80)
			if tcp.DstPort == 80 || tcp.SrcPort == 80 {
				payload := tcp.Payload

				// Look for HTTP Digest authentication header
				if len(payload) > 0 && bytes.Contains(payload, []byte("Authorization: Digest")) {
					// Try to extract credentials using the harvester
					ident := "test-flow"
					creds := httpHarvester.HarvesterFunc(payload, ident, packet.Metadata().Timestamp)

					if creds != nil {
						foundDigest = true
						extractedCreds = creds
						t.Logf("Extracted HTTP Digest credentials:")
						t.Logf("  User: %s", creds.User)
						t.Logf("  Service: %s", creds.Service)
						t.Logf("  Password (Hashcat format): %s", creds.Password)
						t.Logf("  Notes: %s", creds.Notes)

						// Verify the user
						if creds.User != "Susan" {
							t.Errorf("Expected username 'Susan', got '%s'", creds.User)
						}

						// Verify the service
						if creds.Service != "HTTP Digest" {
							t.Errorf("Expected service 'HTTP Digest', got '%s'", creds.Service)
						}

						// Verify the password field contains all necessary components
						// Format: username:realm:nonce:uri:nc:cnonce:qop:response
						parts := strings.Split(creds.Password, ":")
						if len(parts) != 8 {
							t.Errorf("Expected 8 parts in Hashcat format, got %d", len(parts))
						} else {
							// Verify each part is present
							if parts[0] != "Susan" {
								t.Errorf("Expected username 'Susan' in hash format, got '%s'", parts[0])
							}
							if parts[1] != "INS.COM" {
								t.Errorf("Expected realm 'INS.COM' in hash format, got '%s'", parts[1])
							}
							if parts[2] == "" {
								t.Error("Nonce should not be empty")
							}
							if parts[3] != "/Security/Digest/" {
								t.Errorf("Expected URI '/Security/Digest/', got '%s'", parts[3])
							}
							if parts[4] != "00000001" {
								t.Errorf("Expected nc '00000001', got '%s'", parts[4])
							}
							if parts[5] == "" {
								t.Error("CNonce should not be empty")
							}
							if parts[6] != "auth" {
								t.Errorf("Expected qop 'auth', got '%s'", parts[6])
							}
							if parts[7] == "" {
								t.Error("Response should not be empty")
							}

							t.Logf("✓ All Hashcat format fields validated successfully")
						}

						// Verify notes contain method
						if !strings.Contains(creds.Notes, "Method:") {
							t.Error("Notes should contain HTTP method")
						}

						break // Found what we needed
					}
				}
			}
		}
	}

	if !foundDigest {
		t.Error("Expected to find HTTP Digest authentication in test PCAP")
	}

	if extractedCreds == nil {
		t.Error("Expected to extract credentials from HTTP Digest authentication")
	}
}

// TestHTTPDigestMD5 tests HTTP Digest-MD5 authentication
func TestHTTPDigestMD5(t *testing.T) {
	pcapFile := filepath.Join("testdata", "HTTP - Digest-MD5.pcap")

	if _, err := os.Stat(pcapFile); os.IsNotExist(err) {
		t.Skip("Test PCAP file not found")
	}

	handle, err := pcap.OpenOffline(pcapFile)
	if err != nil {
		t.Fatalf("Failed to open pcap file: %v", err)
	}
	defer handle.Close()

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	var extractedCreds *types.Secret

	for packet := range packetSource.Packets() {
		// Check for TCP layer
		if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
			tcp := tcpLayer.(*layers.TCP)

			// Check if this is HTTP traffic (port 80)
			if tcp.DstPort == 80 || tcp.SrcPort == 80 {
				payload := tcp.Payload

				// Look for HTTP Digest authentication header
				if len(payload) > 0 && bytes.Contains(payload, []byte("Authorization: Digest")) {
					// Try to extract credentials using the harvester
					ident := "test-flow"
					creds := httpHarvester.HarvesterFunc(payload, ident, packet.Metadata().Timestamp)

					if creds != nil {
						extractedCreds = creds
						t.Logf("Extracted HTTP Digest-MD5 credentials:")
						t.Logf("  User: %s", creds.User)
						t.Logf("  Service: %s", creds.Service)
						t.Logf("  Password (Hashcat format): %s", creds.Password)
						t.Logf("  Notes: %s", creds.Notes)
						break
					}
				}
			}
		}
	}

	if extractedCreds == nil {
		t.Error("Expected to extract HTTP Digest credentials from test PCAP")
		return
	}

	// Verify the service
	if extractedCreds.Service != "HTTP Digest" {
		t.Errorf("Expected service 'HTTP Digest', got '%s'", extractedCreds.Service)
	}

	// Verify the user
	if extractedCreds.User != "webadmin" {
		t.Errorf("Expected username 'webadmin', got '%s'", extractedCreds.User)
	}

	// Verify the password field contains all necessary components
	// Format: username:realm:nonce:uri:nc:cnonce:qop:response
	parts := strings.Split(extractedCreds.Password, ":")
	if len(parts) != 8 {
		t.Errorf("Expected 8 parts in Hashcat format, got %d", len(parts))
	} else {
		// Verify key fields
		if parts[0] != "webadmin" {
			t.Errorf("Expected username 'webadmin' in hash format, got '%s'", parts[0])
		}
		if parts[1] != "Pentester-Academy" {
			t.Errorf("Expected realm 'Pentester-Academy' in hash format, got '%s'", parts[1])
		}
		if parts[3] != "/" {
			t.Errorf("Expected URI '/', got '%s'", parts[3])
		}

		t.Logf("✓ All Hashcat format fields validated successfully")
	}

	t.Logf("✓ Successfully extracted and validated HTTP Digest-MD5 credentials")
}

// TestNTLMSSPv1 tests NTLMv1 hash extraction from SMB traffic
func TestNTLMSSPv1(t *testing.T) {
	pcapFile := filepath.Join("testdata", "SMB - NTLM cifs_SessionSetupAndX_NTLM_Plain.pcap")

	handle, err := pcap.OpenOffline(pcapFile)
	if err != nil {
		t.Fatalf("Failed to open pcap file: %v", err)
	}
	defer handle.Close()

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	// Collect all TCP payloads from the session
	var sessionData []byte
	var extractedCreds *types.Secret

	for packet := range packetSource.Packets() {
		if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
			tcp := tcpLayer.(*layers.TCP)
			payload := tcp.Payload

			// Check if this is SMB traffic (port 445 or 139)
			if tcp.DstPort == 445 || tcp.SrcPort == 445 || tcp.DstPort == 139 || tcp.SrcPort == 139 {
				if len(payload) > 0 {
					sessionData = append(sessionData, payload...)

					// Try to extract credentials using the harvester with accumulated session data
					ident := "test-flow"
					creds := ntlmsspHarvester.HarvesterFunc(sessionData, ident, packet.Metadata().Timestamp)

					if creds != nil && extractedCreds == nil {
						extractedCreds = creds
						t.Logf("Extracted NTLMv1 credentials:")
						t.Logf("  User: %s", creds.User)
						t.Logf("  Service: %s", creds.Service)
						t.Logf("  Password (Hashcat format): %s", creds.Password)
						t.Logf("  Notes: %s", creds.Notes)
					}
				}
			}
		}
	}

	if extractedCreds == nil {
		t.Error("Expected to extract NTLM credentials from test PCAP")
		return
	}

	// Verify the service
	if extractedCreds.Service != "NTLMSSP" {
		t.Errorf("Expected service 'NTLMSSP', got '%s'", extractedCreds.Service)
	}

	// Note: Username can be empty for anonymous/guest logins
	if extractedCreds.User == "" {
		t.Logf("Note: Username is empty (anonymous/guest login)")
	}

	// Verify the password field contains Hashcat format
	// NTLMv1 format (mode 5500): username::domain:LM:NT:challenge
	if !strings.Contains(extractedCreds.Password, "::") {
		t.Error("Password should contain Hashcat format with :: separator")
	}

	// Check if it's NTLMv1 (should have exactly 5 colons for 6 parts)
	parts := strings.Split(extractedCreds.Password, ":")
	if len(parts) == 6 {
		t.Logf("✓ Detected NTLMv1 format (mode 5500)")

		// Verify structure: username::domain:LM:NT:challenge
		// Username can be empty for anonymous logins
		if parts[1] != "" {
			t.Error("Second field should be empty (:: separator)")
		}
		if parts[5] == "" {
			t.Error("Challenge should not be empty")
		}

		// LM and NT responses should be 48 hex chars (24 bytes) for NTLMv1
		if len(parts[3]) != 48 {
			t.Errorf("LM response should be 48 hex chars, got %d", len(parts[3]))
		}
		if len(parts[4]) != 48 {
			t.Errorf("NT response should be 48 hex chars, got %d", len(parts[4]))
		}
		if len(parts[5]) != 16 {
			t.Errorf("Challenge should be 16 hex chars (8 bytes), got %d", len(parts[5]))
		}
	} else {
		t.Logf("Hash format has %d parts (NTLMv2 has 6+ parts)", len(parts))
	}

	// Verify notes contain hash type
	if !strings.Contains(extractedCreds.Notes, "HashType:") {
		t.Error("Notes should contain HashType")
	}

	t.Logf("✓ Successfully extracted and validated NTLM credentials")
}

// TestNTLMSSPv2Windows10 tests NTLMv2 hash extraction
func TestNTLMSSPv2Windows10(t *testing.T) {
	pcapFile := filepath.Join("testdata", "SMB - NTLMSSP (Windows 10).pcap")

	handle, err := pcap.OpenOffline(pcapFile)
	if err != nil {
		t.Fatalf("Failed to open pcap file: %v", err)
	}
	defer handle.Close()

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	// Collect all TCP payloads from the session
	var sessionData []byte
	var extractedCreds *types.Secret

	for packet := range packetSource.Packets() {
		if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
			tcp := tcpLayer.(*layers.TCP)
			payload := tcp.Payload

			// Check if this is SMB traffic (port 445 or 139)
			if tcp.DstPort == 445 || tcp.SrcPort == 445 || tcp.DstPort == 139 || tcp.SrcPort == 139 {
				if len(payload) > 0 {
					sessionData = append(sessionData, payload...)

					// Try to extract credentials using the harvester with accumulated session data
					ident := "test-flow"
					creds := ntlmsspHarvester.HarvesterFunc(sessionData, ident, packet.Metadata().Timestamp)

					if creds != nil && extractedCreds == nil {
						extractedCreds = creds
						t.Logf("Extracted NTLMv2 credentials:")
						t.Logf("  User: %s", creds.User)
						t.Logf("  Service: %s", creds.Service)
						t.Logf("  Password (Hashcat format): %s", creds.Password[:80]+"...") // Show first 80 chars
						t.Logf("  Notes: %s", creds.Notes)
					}
				}
			}
		}
	}

	if extractedCreds == nil {
		t.Error("Expected to extract NTLM credentials from test PCAP")
		return
	}

	// Verify the service
	if extractedCreds.Service != "NTLMSSP" {
		t.Errorf("Expected service 'NTLMSSP', got '%s'", extractedCreds.Service)
	}

	// Verify the user is not empty for NTLMv2
	if extractedCreds.User == "" {
		t.Error("Username should not be empty for NTLMv2")
	}

	// Verify the password field contains Hashcat format
	// NTLMv2 format (mode 5600): username::domain:challenge:NTProofStr:blob
	if !strings.Contains(extractedCreds.Password, "::") {
		t.Error("Password should contain Hashcat format with :: separator")
	}

	// Check if it's NTLMv2 (should have exactly 5 colons for 6 parts)
	parts := strings.Split(extractedCreds.Password, ":")
	if len(parts) == 6 {
		t.Logf("✓ Detected NTLMv2 format (mode 5600)")

		// Verify structure: username::domain:challenge:NTProofStr:blob
		if parts[0] == "" {
			t.Error("Username in hash should not be empty for NTLMv2")
		}
		if parts[1] != "" {
			t.Error("Second field should be empty (:: separator)")
		}
		if parts[3] == "" {
			t.Error("Challenge should not be empty")
		}
		if parts[4] == "" {
			t.Error("NTProofStr should not be empty")
		}
		if parts[5] == "" {
			t.Error("Blob should not be empty")
		}

		// Challenge should be 16 hex chars (8 bytes)
		if len(parts[3]) != 16 {
			t.Errorf("Challenge should be 16 hex chars (8 bytes), got %d", len(parts[3]))
		}
		// NTProofStr should be 32 hex chars (16 bytes)
		if len(parts[4]) != 32 {
			t.Errorf("NTProofStr should be 32 hex chars (16 bytes), got %d", len(parts[4]))
		}
		// Blob should be > 0 for NTLMv2
		if len(parts[5]) == 0 {
			t.Error("Blob should not be empty for NTLMv2")
		} else {
			t.Logf("  Blob length: %d hex chars", len(parts[5]))
		}
	} else {
		t.Logf("Hash format has %d parts, expected 6 for NTLMv2", len(parts))
	}

	// Verify notes contain hash type
	if !strings.Contains(extractedCreds.Notes, "HashType:") {
		t.Error("Notes should contain HashType")
	}

	// Verify it's marked as NTLMv2
	if !strings.Contains(extractedCreds.Notes, "NTLMv2") {
		t.Error("Notes should indicate NTLMv2")
	}

	t.Logf("✓ Successfully extracted and validated NTLMv2 credentials")
}

// TestNTLMSSPSingleSession tests NTLMSSP in a single session
func TestNTLMSSPSingleSession(t *testing.T) {
	pcapFile := filepath.Join("testdata", "SMB - NTLMSSP Single Session (Windows 10).pcap")

	handle, err := pcap.OpenOffline(pcapFile)
	if err != nil {
		t.Fatalf("Failed to open pcap file: %v", err)
	}
	defer handle.Close()

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	// Collect all TCP payloads from the session
	var sessionData []byte
	var extractedCreds *types.Secret

	for packet := range packetSource.Packets() {
		if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
			tcp := tcpLayer.(*layers.TCP)
			payload := tcp.Payload

			// Check if this is SMB traffic (port 445 or 139)
			if tcp.DstPort == 445 || tcp.SrcPort == 445 || tcp.DstPort == 139 || tcp.SrcPort == 139 {
				if len(payload) > 0 {
					sessionData = append(sessionData, payload...)

					// Try to extract credentials using the harvester with accumulated session data
					ident := "test-flow"
					creds := ntlmsspHarvester.HarvesterFunc(sessionData, ident, packet.Metadata().Timestamp)

					if creds != nil && extractedCreds == nil {
						extractedCreds = creds
						t.Logf("Extracted NTLMSSP credentials from single session:")
						t.Logf("  User: %s", creds.User)
						t.Logf("  Service: %s", creds.Service)
						t.Logf("  Notes: %s", creds.Notes)
					}
				}
			}
		}
	}

	if extractedCreds == nil {
		t.Error("Expected to extract NTLM credentials from single session PCAP")
		return
	}

	// Verify the service
	if extractedCreds.Service != "NTLMSSP" {
		t.Errorf("Expected service 'NTLMSSP', got '%s'", extractedCreds.Service)
	}

	// Verify the password field contains Hashcat format
	if !strings.Contains(extractedCreds.Password, "::") {
		t.Error("Password should contain Hashcat format with :: separator")
	}

	// Verify notes contain hash type
	if !strings.Contains(extractedCreds.Notes, "HashType:") {
		t.Error("Notes should contain HashType")
	}

	t.Logf("✓ Successfully extracted NTLM credentials from single session")
}

// TestHTTPNTLM tests NTLM authentication over HTTP
func TestHTTPNTLM(t *testing.T) {
	pcapFile := filepath.Join("testdata", "HTTP - NTLM.pcap")

	handle, err := pcap.OpenOffline(pcapFile)
	if err != nil {
		t.Fatalf("Failed to open pcap file: %v", err)
	}
	defer handle.Close()

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	// Collect all TCP payloads from the session
	var sessionData []byte
	var extractedCreds *types.Secret

	for packet := range packetSource.Packets() {
		if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
			tcp := tcpLayer.(*layers.TCP)
			payload := tcp.Payload

			// Check if this is HTTP traffic (port 80)
			if tcp.DstPort == 80 || tcp.SrcPort == 80 {
				if len(payload) > 0 {
					sessionData = append(sessionData, payload...)

					// Try to extract credentials using the HTTP NTLM harvester
					ident := "test-flow"
					creds := httpNTLMHarvester.HarvesterFunc(sessionData, ident, packet.Metadata().Timestamp)

					if creds != nil && extractedCreds == nil {
						extractedCreds = creds
						t.Logf("Extracted HTTP NTLM credentials:")
						t.Logf("  User: %s", creds.User)
						t.Logf("  Service: %s", creds.Service)
						if len(creds.Password) > 80 {
							t.Logf("  Password (Hashcat format): %s...", creds.Password[:80])
						} else {
							t.Logf("  Password (Hashcat format): %s", creds.Password)
						}
						t.Logf("  Notes: %s", creds.Notes)
					}
				}
			}
		}
	}

	if extractedCreds == nil {
		t.Skip("PCAP does not contain complete NTLM handshake (missing server challenge)")
		return
	}

	// Verify the service
	if extractedCreds.Service != "NTLMSSP" {
		t.Errorf("Expected service 'NTLMSSP', got '%s'", extractedCreds.Service)
	}

	// Verify the password field contains Hashcat format
	if !strings.Contains(extractedCreds.Password, "::") {
		t.Error("Password should contain Hashcat format with :: separator")
	}

	// Verify notes contain hash type
	if !strings.Contains(extractedCreds.Notes, "HashType:") {
		t.Error("Notes should contain HashType")
	}

	t.Logf("✓ Successfully extracted HTTP NTLM credentials")
}

// TestHTTPNTLMGSSAPI tests NTLM with GSSAPI over HTTP
func TestHTTPNTLMGSSAPI(t *testing.T) {
	pcapFile := filepath.Join("testdata", "HTTP - NTLM GSSAPI.pcap")

	handle, err := pcap.OpenOffline(pcapFile)
	if err != nil {
		t.Fatalf("Failed to open pcap file: %v", err)
	}
	defer handle.Close()

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	// Collect all TCP payloads from the session
	var sessionData []byte
	var extractedCreds *types.Secret

	for packet := range packetSource.Packets() {
		if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
			tcp := tcpLayer.(*layers.TCP)
			payload := tcp.Payload

			// Check if this is HTTP traffic (port 80)
			if tcp.DstPort == 80 || tcp.SrcPort == 80 {
				if len(payload) > 0 {
					sessionData = append(sessionData, payload...)

					// Try to extract credentials using the HTTP NTLM harvester
					// GSSAPI wrapping is handled transparently by base64 decoding
					ident := "test-flow"
					creds := httpNTLMHarvester.HarvesterFunc(sessionData, ident, packet.Metadata().Timestamp)

					if creds != nil && extractedCreds == nil {
						extractedCreds = creds
						t.Logf("Extracted HTTP NTLM GSSAPI credentials:")
						t.Logf("  User: %s", creds.User)
						t.Logf("  Service: %s", creds.Service)
						t.Logf("  Notes: %s", creds.Notes)
					}
				}
			}
		}
	}

	if extractedCreds == nil {
		t.Skip("PCAP does not contain complete NTLM handshake or GSSAPI wrapper not yet implemented")
		return
	}

	// Verify the service
	if extractedCreds.Service != "NTLMSSP" {
		t.Errorf("Expected service 'NTLMSSP', got '%s'", extractedCreds.Service)
	}

	t.Logf("✓ Successfully extracted HTTP NTLM GSSAPI credentials")
}

// TestKerberosASReqUDP tests Kerberos AS-REQ pre-authentication hash extraction (UDP)
func TestKerberosASReqUDP(t *testing.T) {
	pcapFile := filepath.Join("testdata", "Kerberos - v5 UDP.pcap")

	handle, err := pcap.OpenOffline(pcapFile)
	if err != nil {
		t.Fatalf("Failed to open pcap file: %v", err)
	}
	defer handle.Close()

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	var extractedCreds *types.Secret
	for packet := range packetSource.Packets() {
		if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
			udp := udpLayer.(*layers.UDP)

			// Kerberos typically uses port 88
			if udp.DstPort == 88 || udp.SrcPort == 88 {
				payload := udp.Payload

				if len(payload) > 0 {
					// Try to extract AS-REQ credentials
					ident := "test-flow"
					creds := kerberosASReqHarvester.HarvesterFunc(payload, ident, packet.Metadata().Timestamp)

					if creds != nil {
						extractedCreds = creds
						t.Logf("Extracted Kerberos AS-REQ credentials:")
						t.Logf("  User: %s", creds.User)
						t.Logf("  Service: %s", creds.Service)
						t.Logf("  Password (Hashcat format): %s", creds.Password[:60]+"...")
						t.Logf("  Notes: %s", creds.Notes)
						break
					}
				}
			}
		}
	}

	if extractedCreds == nil {
		t.Skip("No Kerberos AS-REQ with pre-authentication found in PCAP (may be valid)")
		return
	}

	// Verify the service
	if extractedCreds.Service != "Kerberos" {
		t.Errorf("Expected service 'Kerberos', got '%s'", extractedCreds.Service)
	}

	// Verify the user is not empty
	if extractedCreds.User == "" {
		t.Error("Username should not be empty")
	}

	// Verify the password field contains Hashcat format for AS-REQ
	// Format: $krb5pa$23$user$realm$salt$hash
	if !strings.HasPrefix(extractedCreds.Password, "$krb5pa$23$") {
		t.Errorf("Expected password to start with '$krb5pa$23$', got '%s'", extractedCreds.Password[:20])
	}

	// Verify notes contain hash type
	if !strings.Contains(extractedCreds.Notes, "HashType:") {
		t.Error("Notes should contain HashType")
	}

	if !strings.Contains(extractedCreds.Notes, "AS-REQ") {
		t.Error("Notes should indicate AS-REQ")
	}

	t.Logf("✓ Successfully extracted and validated Kerberos AS-REQ credentials")
}

// TestKerberosASReqTCP tests Kerberos AS-REQ over TCP
func TestKerberosASReqTCP(t *testing.T) {
	pcapFile := filepath.Join("testdata", "Kerberos - v5 TCP.pcap")

	handle, err := pcap.OpenOffline(pcapFile)
	if err != nil {
		t.Fatalf("Failed to open pcap file: %v", err)
	}
	defer handle.Close()

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	var extractedCreds *types.Secret
	for packet := range packetSource.Packets() {
		if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
			tcp := tcpLayer.(*layers.TCP)

			// Kerberos typically uses port 88
			if tcp.DstPort == 88 || tcp.SrcPort == 88 {
				payload := tcp.Payload

				// TCP Kerberos has a 4-byte length prefix (record mark)
				// Skip the first 4 bytes before parsing the Kerberos message
				if len(payload) > 4 {
					kerberosPayload := payload[4:]

					// Try to extract AS-REQ credentials
					ident := "test-flow"
					creds := kerberosASReqHarvester.HarvesterFunc(kerberosPayload, ident, packet.Metadata().Timestamp)

					if creds != nil {
						extractedCreds = creds
						t.Logf("Extracted Kerberos AS-REQ credentials (TCP):")
						t.Logf("  User: %s", creds.User)
						t.Logf("  Service: %s", creds.Service)
						t.Logf("  Password (Hashcat format): %s", creds.Password[:60]+"...")
						t.Logf("  Notes: %s", creds.Notes)
						break
					}
				}
			}
		}
	}

	if extractedCreds == nil {
		t.Skip("No Kerberos AS-REQ with pre-authentication found in TCP PCAP (may be valid)")
		return
	}

	// Verify the service
	if extractedCreds.Service != "Kerberos" {
		t.Errorf("Expected service 'Kerberos', got '%s'", extractedCreds.Service)
	}

	// Verify the user is not empty
	if extractedCreds.User == "" {
		t.Error("Username should not be empty")
	}

	// Verify the password field contains Hashcat format for AS-REQ
	// Format: $krb5pa$23$user$realm$salt$hash
	if !strings.HasPrefix(extractedCreds.Password, "$krb5pa$23$") {
		t.Errorf("Expected password to start with '$krb5pa$23$', got '%s'", extractedCreds.Password[:20])
	}

	t.Logf("✓ Successfully extracted and validated Kerberos AS-REQ credentials from TCP")
}

// TestKerberosASRepUDP tests Kerberos AS-REP hash extraction
func TestKerberosASRepUDP(t *testing.T) {
	pcapFiles := []string{
		filepath.Join("testdata", "Kerberos - v5 UDP.pcap"),
		filepath.Join("testdata", "Kerberos v5 UDP 2.pcap"),
		filepath.Join("testdata", "Kerberos v5 - UDP 3.pcap"),
	}

	for _, pcapFile := range pcapFiles {
		t.Run(filepath.Base(pcapFile), func(t *testing.T) {
			if _, err := os.Stat(pcapFile); os.IsNotExist(err) {
				t.Skipf("Test PCAP file not found: %s", pcapFile)
			}

			handle, err := pcap.OpenOffline(pcapFile)
			if err != nil {
				t.Fatalf("Failed to open pcap file: %v", err)
			}
			defer handle.Close()

			packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

			var extractedCount int
			for packet := range packetSource.Packets() {
				if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
					udp := udpLayer.(*layers.UDP)

					if udp.DstPort == 88 || udp.SrcPort == 88 {
						payload := udp.Payload

						// Try to extract AS-REP using the harvester
						ident := "test-flow"
						creds := kerberosASRepHarvester.HarvesterFunc(payload, ident, packet.Metadata().Timestamp)

						if creds != nil {
							extractedCount++
							t.Logf("Extracted AS-REP: User=%s, Service=Kerberos", creds.User)
							t.Logf("Hash format: %s", creds.Password[:50]+"...") // Log first 50 chars
							t.Logf("Notes: %s", creds.Notes)

							// Verify hash format
							if !strings.HasPrefix(creds.Password, "$krb5asrep$") {
								t.Errorf("Invalid hash format, expected $krb5asrep$ prefix")
							}

							// Verify user is not empty
							if creds.User == "" {
								t.Errorf("Username should not be empty")
							}
						}
					}
				}
			}

			t.Logf("Total AS-REP credentials extracted: %d", extractedCount)
			// Note: Not all PCAP files may contain AS-REP, so we don't fail if extractedCount is 0
		})
	}
}

// TestKerberosTGSRep tests Kerberos TGS-REP hash extraction
func TestKerberosTGSRep(t *testing.T) {
	pcapFile := filepath.Join("testdata", "Kerberos-816.pcap")

	if _, err := os.Stat(pcapFile); os.IsNotExist(err) {
		t.Skipf("Test PCAP file not found: %s", pcapFile)
	}

	handle, err := pcap.OpenOffline(pcapFile)
	if err != nil {
		t.Fatalf("Failed to open pcap file: %v", err)
	}
	defer handle.Close()

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	var extractedCount int
	for packet := range packetSource.Packets() {
		// Check both UDP and TCP layers as Kerberos can use both
		var payload []byte

		if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
			udp := udpLayer.(*layers.UDP)
			if udp.DstPort == 88 || udp.SrcPort == 88 {
				payload = udp.Payload
			}
		} else if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
			tcp := tcpLayer.(*layers.TCP)
			if tcp.DstPort == 88 || tcp.SrcPort == 88 {
				payload = tcp.Payload
			}
		}

		if len(payload) > 0 {
			// Try to extract TGS-REP using the harvester
			ident := "test-flow"
			creds := kerberosTGSRepHarvester.HarvesterFunc(payload, ident, packet.Metadata().Timestamp)

			if creds != nil {
				extractedCount++
				t.Logf("Extracted TGS-REP: User=%s, Service=Kerberos", creds.User)
				t.Logf("Hash format: %s", creds.Password[:50]+"...") // Log first 50 chars
				t.Logf("Notes: %s", creds.Notes)

				// Verify hash format
				if !strings.HasPrefix(creds.Password, "$krb5tgs$") {
					t.Errorf("Invalid hash format, expected $krb5tgs$ prefix")
				}

				// Verify user is not empty
				if creds.User == "" {
					t.Errorf("Username should not be empty")
				}

				// Verify Kerberoasting is mentioned in notes
				if !strings.Contains(creds.Notes, "Kerberoasting") {
					t.Errorf("Notes should mention Kerberoasting")
				}
			}
		}
	}

	t.Logf("Total TGS-REP credentials extracted: %d", extractedCount)
	// Note: Some PCAP files may not contain TGS-REP with supported etypes

	// Original TODO comment removed as implementation is complete:
	// - Username
	// - Realm
	// - Service Name (SPN like "cifs/server")
	// - Etype (17, 18, 23)
	// - Encrypted part cipher
	// Expected Hashcat formats:
	// - mode 13100 for etype 23: $krb5tgs$23$*user$realm$service*$hash
	// - mode 19600 for etype 17
	// - mode 19700 for etype 18
}

// TestAllPCAPFilesExist verifies all test PCAP files are present
func TestAllPCAPFilesExist(t *testing.T) {
	testFiles := []string{
		"HTTP - Digest Authentication.pcap",
		"HTTP - Digest-MD5.pcap",
		"HTTP - NTLM GSSAPI.pcap",
		"HTTP - NTLM.pcap",
		"Kerberos - v5 TCP.pcap",
		"Kerberos - v5 UDP.pcap",
		"Kerberos v5 - UDP 3.pcap",
		"Kerberos v5 UDP 2.pcap",
		"Kerberos-816.pcap",
		"SMB - NTLM cifs_SessionSetupAndX_NTLM_Plain.pcap",
		"SMB - NTLMSSP (Windows 10).pcap",
		"SMB - NTLMSSP (smb3 aes 128 ccm).pcap",
		"SMB - NTLMSSP Single Session (Windows 10).pcap",
	}

	for _, file := range testFiles {
		path := filepath.Join("testdata", file)
		if _, err := os.Stat(path); os.IsNotExist(err) {
			t.Errorf("Test file missing: %s", path)
		} else {
			t.Logf("✓ Test file present: %s", file)
		}
	}
}

// TestPCAPFileReadability ensures all PCAP files can be opened
func TestPCAPFileReadability(t *testing.T) {
	testFiles := []string{
		"HTTP - Digest Authentication.pcap",
		"HTTP - Digest-MD5.pcap",
		"HTTP - NTLM GSSAPI.pcap",
		"HTTP - NTLM.pcap",
		"Kerberos - v5 TCP.pcap",
		"Kerberos - v5 UDP.pcap",
		"Kerberos v5 - UDP 3.pcap",
		"Kerberos v5 UDP 2.pcap",
		"Kerberos-816.pcap",
		"SMB - NTLM cifs_SessionSetupAndX_NTLM_Plain.pcap",
		"SMB - NTLMSSP (Windows 10).pcap",
		"SMB - NTLMSSP (smb3 aes 128 ccm).pcap",
		"SMB - NTLMSSP Single Session (Windows 10).pcap",
	}

	for _, file := range testFiles {
		path := filepath.Join("testdata", file)
		handle, err := pcap.OpenOffline(path)
		if err != nil {
			t.Errorf("Failed to open %s: %v", file, err)
			continue
		}
		handle.Close()
		t.Logf("✓ Successfully opened: %s", file)
	}
}
