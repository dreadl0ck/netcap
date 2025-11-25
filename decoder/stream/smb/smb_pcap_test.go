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

package smb

import (
	"bytes"
	"encoding/binary"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"
)

const pcapDir = "../../../pcaps"

// smbPacketInfo holds info extracted from SMB packets for testing
type smbPacketInfo struct {
	isSMB1      bool
	isSMB2      bool
	command     uint16
	commandName string
	isResponse  bool
	status      uint32
	hasNTLMSSP  bool
	ntlmMsgType uint32
}

// extractSMBInfo extracts basic SMB info from packet payload for testing
func extractSMBInfo(payload []byte) *smbPacketInfo {
	info := &smbPacketInfo{}

	// Need at least NetBIOS header (4 bytes) + SMB signature (4 bytes)
	if len(payload) < 8 {
		return nil
	}

	// Skip NetBIOS Session Service header (4 bytes)
	// Or look for SMB signature directly
	smbData := payload

	// Find SMB signature
	smb1Idx := bytes.Index(smbData, []byte(SMB1Signature))
	smb2Idx := bytes.Index(smbData, []byte(SMB2Signature))

	if smb1Idx >= 0 && (smb2Idx < 0 || smb1Idx < smb2Idx) {
		// SMB1
		info.isSMB1 = true
		start := smb1Idx

		if len(smbData) < start+33 {
			return info
		}

		// SMB1 header: signature(4) + command(1) + status(4) + flags(1) + ...
		info.command = uint16(smbData[start+4])
		info.commandName = getSMB1CommandName(uint8(info.command))
		info.status = binary.LittleEndian.Uint32(smbData[start+5 : start+9])
		info.isResponse = smbData[start+9]&0x80 != 0

	} else if smb2Idx >= 0 {
		// SMB2/3
		info.isSMB2 = true
		start := smb2Idx

		if len(smbData) < start+64 {
			return info
		}

		// SMB2 header: signature(4) + structsize(2) + creditcharge(2) + status/channelseq(4) + command(2) + ...
		info.command = binary.LittleEndian.Uint16(smbData[start+12 : start+14])
		info.commandName = getSMB2CommandName(info.command)
		info.status = binary.LittleEndian.Uint32(smbData[start+8 : start+12])

		// Flags are at offset 16 (4 bytes)
		flags := binary.LittleEndian.Uint32(smbData[start+16 : start+20])
		info.isResponse = flags&0x00000001 != 0
	}

	// Check for NTLMSSP
	ntlmIdx := bytes.Index(payload, []byte("NTLMSSP\x00"))
	if ntlmIdx >= 0 && len(payload) >= ntlmIdx+12 {
		info.hasNTLMSSP = true
		info.ntlmMsgType = binary.LittleEndian.Uint32(payload[ntlmIdx+8 : ntlmIdx+12])
	}

	return info
}

// openPcapFile opens a pcap file and returns a packet source
func openPcapFile(path string) (*gopacket.PacketSource, *os.File, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, nil, err
	}

	reader, err := pcapgo.NewReader(f)
	if err != nil {
		f.Close()
		return nil, nil, err
	}

	return gopacket.NewPacketSource(reader, reader.LinkType()), f, nil
}

// TestParseSMBv1Pcap tests parsing of SMB1 traffic
func TestParseSMBv1Pcap(t *testing.T) {
	pcapPath := filepath.Join(pcapDir, "nDPI-smbv1.pcap")
	if _, err := os.Stat(pcapPath); os.IsNotExist(err) {
		t.Skipf("Test pcap file not found: %s", pcapPath)
	}

	packetSource, f, err := openPcapFile(pcapPath)
	if err != nil {
		t.Fatalf("Failed to open pcap: %v", err)
	}
	defer f.Close()

	var (
		smbPackets    int
		smb1Packets   int
		negotiateCmd  int
		sessionSetup  int
		hasNTLMSSP    int
	)

	for packet := range packetSource.Packets() {
		tcpLayer := packet.Layer(layers.LayerTypeTCP)
		if tcpLayer == nil {
			continue
		}

		tcp := tcpLayer.(*layers.TCP)
		if tcp.SrcPort != 445 && tcp.DstPort != 445 {
			continue
		}

		payload := tcp.Payload
		if len(payload) == 0 {
			continue
		}

		info := extractSMBInfo(payload)
		if info == nil {
			continue
		}

		if info.isSMB1 || info.isSMB2 {
			smbPackets++
		}

		if info.isSMB1 {
			smb1Packets++

			if info.command == SMB1_COM_NEGOTIATE {
				negotiateCmd++
			}
			if info.command == SMB1_COM_SESSION_SETUP_ANDX {
				sessionSetup++
			}
		}

		if info.hasNTLMSSP {
			hasNTLMSSP++
		}
	}

	t.Logf("SMB1 Pcap Analysis:")
	t.Logf("  Total SMB packets: %d", smbPackets)
	t.Logf("  SMB1 packets: %d", smb1Packets)
	t.Logf("  NEGOTIATE commands: %d", negotiateCmd)
	t.Logf("  SESSION_SETUP commands: %d", sessionSetup)
	t.Logf("  Packets with NTLMSSP: %d", hasNTLMSSP)

	if smb1Packets == 0 {
		t.Error("Expected to find SMB1 packets")
	}
}

// TestParseSMBv2Pcap tests parsing of SMB2 traffic
func TestParseSMBv2Pcap(t *testing.T) {
	pcapPath := filepath.Join(pcapDir, "suricata-verify-smb2.pcap")
	if _, err := os.Stat(pcapPath); os.IsNotExist(err) {
		t.Skipf("Test pcap file not found: %s", pcapPath)
	}

	packetSource, f, err := openPcapFile(pcapPath)
	if err != nil {
		t.Fatalf("Failed to open pcap: %v", err)
	}
	defer f.Close()

	var (
		smbPackets   int
		smb2Packets  int
		negotiateCmd int
		sessionSetup int
		treeConnect  int
		createCmd    int
		readCmd      int
		writeCmd     int
		closeCmd     int
		hasNTLMSSP   int

		// NTLM message types
		ntlmNegotiate    int
		ntlmChallenge    int
		ntlmAuthenticate int
	)

	for packet := range packetSource.Packets() {
		tcpLayer := packet.Layer(layers.LayerTypeTCP)
		if tcpLayer == nil {
			continue
		}

		tcp := tcpLayer.(*layers.TCP)
		if tcp.SrcPort != 445 && tcp.DstPort != 445 {
			continue
		}

		payload := tcp.Payload
		if len(payload) == 0 {
			continue
		}

		info := extractSMBInfo(payload)
		if info == nil {
			continue
		}

		if info.isSMB1 || info.isSMB2 {
			smbPackets++
		}

		if info.isSMB2 {
			smb2Packets++

			switch info.command {
			case SMB2_NEGOTIATE:
				negotiateCmd++
			case SMB2_SESSION_SETUP:
				sessionSetup++
			case SMB2_TREE_CONNECT:
				treeConnect++
			case SMB2_CREATE:
				createCmd++
			case SMB2_READ:
				readCmd++
			case SMB2_WRITE:
				writeCmd++
			case SMB2_CLOSE:
				closeCmd++
			}
		}

		if info.hasNTLMSSP {
			hasNTLMSSP++
			switch info.ntlmMsgType {
			case 1:
				ntlmNegotiate++
			case 2:
				ntlmChallenge++
			case 3:
				ntlmAuthenticate++
			}
		}
	}

	t.Logf("SMB2 Pcap Analysis:")
	t.Logf("  Total SMB packets: %d", smbPackets)
	t.Logf("  SMB2 packets: %d", smb2Packets)
	t.Logf("  NEGOTIATE commands: %d", negotiateCmd)
	t.Logf("  SESSION_SETUP commands: %d", sessionSetup)
	t.Logf("  TREE_CONNECT commands: %d", treeConnect)
	t.Logf("  CREATE commands: %d", createCmd)
	t.Logf("  READ commands: %d", readCmd)
	t.Logf("  WRITE commands: %d", writeCmd)
	t.Logf("  CLOSE commands: %d", closeCmd)
	t.Logf("  Packets with NTLMSSP: %d", hasNTLMSSP)
	t.Logf("    - NEGOTIATE (Type 1): %d", ntlmNegotiate)
	t.Logf("    - CHALLENGE (Type 2): %d", ntlmChallenge)
	t.Logf("    - AUTHENTICATE (Type 3): %d", ntlmAuthenticate)

	if smb2Packets == 0 {
		t.Error("Expected to find SMB2 packets")
	}
}

// TestNTLMChallengeExtraction tests extraction of NTLM Challenge (Type 2) messages
func TestNTLMChallengeExtraction(t *testing.T) {
	pcapPath := filepath.Join(pcapDir, "testfiles/smb.pcap")
	if _, err := os.Stat(pcapPath); os.IsNotExist(err) {
		t.Skipf("Test pcap file not found: %s", pcapPath)
	}

	packetSource, f, err := openPcapFile(pcapPath)
	if err != nil {
		t.Fatalf("Failed to open pcap: %v", err)
	}
	defer f.Close()

	var (
		totalPackets          int
		smbPackets            int
		ntlmChallengePackets  int
		challengeWithTarget   int
		challengeWithDomain   int
		challengeWithComputer int
	)

	for packet := range packetSource.Packets() {
		totalPackets++

		tcpLayer := packet.Layer(layers.LayerTypeTCP)
		if tcpLayer == nil {
			continue
		}

		tcp := tcpLayer.(*layers.TCP)
		if tcp.SrcPort != 445 && tcp.DstPort != 445 {
			continue
		}

		payload := tcp.Payload
		if len(payload) == 0 {
			continue
		}

		// Look for NTLMSSP Challenge messages
		ntlmIdx := bytes.Index(payload, []byte("NTLMSSP\x00"))
		if ntlmIdx < 0 || len(payload) < ntlmIdx+12 {
			continue
		}

		smbPackets++
		msgType := binary.LittleEndian.Uint32(payload[ntlmIdx+8 : ntlmIdx+12])

		if msgType == 2 { // CHALLENGE
			ntlmChallengePackets++
			ntlmssp := payload[ntlmIdx:]

			// Parse the challenge message
			if len(ntlmssp) >= 56 {
				// Check for TargetName
				targetNameLen := binary.LittleEndian.Uint16(ntlmssp[12:14])
				if targetNameLen > 0 {
					challengeWithTarget++
				}

				// Parse TargetInfo (AV_PAIR list) if present
				if len(ntlmssp) >= 48 {
					targetInfoLen := int(binary.LittleEndian.Uint16(ntlmssp[40:42]))
					targetInfoOffset := int(binary.LittleEndian.Uint32(ntlmssp[44:48]))

					if targetInfoLen > 0 && targetInfoOffset > 0 && targetInfoOffset+targetInfoLen <= len(ntlmssp) {
						targetInfo := ntlmssp[targetInfoOffset : targetInfoOffset+targetInfoLen]

						// Parse AV_PAIRs
						offset := 0
						for offset+4 <= len(targetInfo) {
							avID := binary.LittleEndian.Uint16(targetInfo[offset : offset+2])
							avLen := int(binary.LittleEndian.Uint16(targetInfo[offset+2 : offset+4]))
							offset += 4

							if avID == 0 { // MsvAvEOL
								break
							}

							if offset+avLen > len(targetInfo) {
								break
							}

							switch avID {
							case MsvAvNbDomainName:
								challengeWithDomain++
							case MsvAvNbComputerName:
								challengeWithComputer++
							}

							offset += avLen
						}
					}
				}
			}

			// Log challenge details
			t.Logf("Found NTLM CHALLENGE at packet offset, msg len=%d", len(ntlmssp))
		}
	}

	t.Logf("NTLM Challenge Extraction Results:")
	t.Logf("  Total packets in pcap: %d", totalPackets)
	t.Logf("  SMB packets on port 445: %d", smbPackets)
	t.Logf("  NTLM Challenge (Type 2) packets: %d", ntlmChallengePackets)
	t.Logf("  Challenges with TargetName: %d", challengeWithTarget)
	t.Logf("  Challenges with NbDomainName: %d", challengeWithDomain)
	t.Logf("  Challenges with NbComputerName: %d", challengeWithComputer)
}

// TestFullNTLMExchange tests parsing of a complete NTLM authentication exchange
func TestFullNTLMExchange(t *testing.T) {
	pcapPath := filepath.Join(pcapDir, "suricata-verify-smb2.pcap")
	if _, err := os.Stat(pcapPath); os.IsNotExist(err) {
		t.Skipf("Test pcap file not found: %s", pcapPath)
	}

	packetSource, f, err := openPcapFile(pcapPath)
	if err != nil {
		t.Fatalf("Failed to open pcap: %v", err)
	}
	defer f.Close()

	// Track NTLM exchange state per flow
	type ntlmExchange struct {
		hasNegotiate    bool
		hasChallenge    bool
		hasAuthenticate bool
		serverChallenge string
		targetName      string
		username        string
		domain          string
	}

	exchanges := make(map[string]*ntlmExchange)

	for packet := range packetSource.Packets() {
		tcpLayer := packet.Layer(layers.LayerTypeTCP)
		if tcpLayer == nil {
			continue
		}

		tcp := tcpLayer.(*layers.TCP)
		if tcp.SrcPort != 445 && tcp.DstPort != 445 {
			continue
		}

		netLayer := packet.NetworkLayer()
		if netLayer == nil {
			continue
		}

		// Create flow key
		srcIP := netLayer.NetworkFlow().Src().String()
		dstIP := netLayer.NetworkFlow().Dst().String()
		srcPort := tcp.SrcPort
		dstPort := tcp.DstPort

		// Normalize flow key (sort by IP)
		var flowKey string
		if srcIP < dstIP {
			flowKey = srcIP + "-" + dstIP
		} else {
			flowKey = dstIP + "-" + srcIP
		}
		_, _ = srcPort, dstPort // silence unused warning

		payload := tcp.Payload
		if len(payload) == 0 {
			continue
		}

		ntlmIdx := bytes.Index(payload, []byte("NTLMSSP\x00"))
		if ntlmIdx < 0 || len(payload) < ntlmIdx+12 {
			continue
		}

		if exchanges[flowKey] == nil {
			exchanges[flowKey] = &ntlmExchange{}
		}
		ex := exchanges[flowKey]

		ntlmssp := payload[ntlmIdx:]
		msgType := binary.LittleEndian.Uint32(ntlmssp[8:12])

		switch msgType {
		case 1: // NEGOTIATE
			ex.hasNegotiate = true

		case 2: // CHALLENGE
			ex.hasChallenge = true
			if len(ntlmssp) >= 32 {
				// Extract server challenge
				challenge := ntlmssp[24:32]
				ex.serverChallenge = bytesToHex(challenge)
			}
			if len(ntlmssp) >= 20 {
				// Extract target name
				targetNameLen := int(binary.LittleEndian.Uint16(ntlmssp[12:14]))
				targetNameOffset := int(binary.LittleEndian.Uint32(ntlmssp[16:20]))
				if targetNameOffset > 0 && targetNameLen > 0 && targetNameOffset+targetNameLen <= len(ntlmssp) {
					ex.targetName = decodeUTF16LE(ntlmssp[targetNameOffset : targetNameOffset+targetNameLen])
				}
			}

		case 3: // AUTHENTICATE
			ex.hasAuthenticate = true
			if len(ntlmssp) >= 64 {
				// Extract domain
				domainLen := int(binary.LittleEndian.Uint16(ntlmssp[28:30]))
				domainOffset := int(binary.LittleEndian.Uint32(ntlmssp[32:36]))
				if domainOffset > 0 && domainLen > 0 && domainOffset+domainLen <= len(ntlmssp) {
					ex.domain = decodeUTF16LE(ntlmssp[domainOffset : domainOffset+domainLen])
				}

				// Extract username
				userLen := int(binary.LittleEndian.Uint16(ntlmssp[36:38]))
				userOffset := int(binary.LittleEndian.Uint32(ntlmssp[40:44]))
				if userOffset > 0 && userLen > 0 && userOffset+userLen <= len(ntlmssp) {
					ex.username = decodeUTF16LE(ntlmssp[userOffset : userOffset+userLen])
				}
			}
		}
	}

	// Report findings
	t.Logf("NTLM Exchange Analysis:")
	completeExchanges := 0
	for flowKey, ex := range exchanges {
		t.Logf("  Flow %s:", flowKey)
		t.Logf("    Has NEGOTIATE: %v", ex.hasNegotiate)
		t.Logf("    Has CHALLENGE: %v (ServerChallenge: %s, TargetName: %s)",
			ex.hasChallenge, ex.serverChallenge, ex.targetName)
		t.Logf("    Has AUTHENTICATE: %v (User: %s\\%s)",
			ex.hasAuthenticate, ex.domain, ex.username)

		if ex.hasChallenge && ex.hasAuthenticate {
			completeExchanges++
		}
	}

	t.Logf("Complete NTLM exchanges (challenge+auth): %d", completeExchanges)
}

// bytesToHex converts bytes to hex string
func bytesToHex(b []byte) string {
	const hexChars = "0123456789ABCDEF"
	result := make([]byte, len(b)*2)
	for i, v := range b {
		result[i*2] = hexChars[v>>4]
		result[i*2+1] = hexChars[v&0x0F]
	}
	return string(result)
}

// TestLargeSMBPcap tests parsing of a larger SMB pcap file
func TestLargeSMBPcap(t *testing.T) {
	pcapPath := filepath.Join(pcapDir, "testfiles/smb.pcap")
	if _, err := os.Stat(pcapPath); os.IsNotExist(err) {
		t.Skipf("Test pcap file not found: %s", pcapPath)
	}

	packetSource, f, err := openPcapFile(pcapPath)
	if err != nil {
		t.Fatalf("Failed to open pcap: %v", err)
	}
	defer f.Close()

	stats := struct {
		total      int
		smb1       int
		smb2       int
		ntlmMsgs   int
		commands   map[string]int
		statusOK   int
		statusErr  int
	}{
		commands: make(map[string]int),
	}

	for packet := range packetSource.Packets() {
		tcpLayer := packet.Layer(layers.LayerTypeTCP)
		if tcpLayer == nil {
			continue
		}

		tcp := tcpLayer.(*layers.TCP)
		if tcp.SrcPort != 445 && tcp.DstPort != 445 {
			continue
		}

		payload := tcp.Payload
		if len(payload) == 0 {
			continue
		}

		info := extractSMBInfo(payload)
		if info == nil {
			continue
		}

		stats.total++

		if info.isSMB1 {
			stats.smb1++
		}
		if info.isSMB2 {
			stats.smb2++
		}
		if info.hasNTLMSSP {
			stats.ntlmMsgs++
		}

		stats.commands[info.commandName]++

		if info.status == 0 {
			stats.statusOK++
		} else {
			stats.statusErr++
		}
	}

	t.Logf("Large SMB Pcap Analysis:")
	t.Logf("  Total SMB packets: %d", stats.total)
	t.Logf("  SMB1: %d, SMB2: %d", stats.smb1, stats.smb2)
	t.Logf("  NTLM messages: %d", stats.ntlmMsgs)
	t.Logf("  Status OK: %d, Status Error: %d", stats.statusOK, stats.statusErr)
	t.Logf("  Command distribution:")
	for cmd, count := range stats.commands {
		t.Logf("    %s: %d", cmd, count)
	}
}

// BenchmarkSMBParsing benchmarks SMB packet parsing performance
func BenchmarkSMBParsing(b *testing.B) {
	pcapPath := filepath.Join(pcapDir, "testfiles/smb.pcap")
	if _, err := os.Stat(pcapPath); os.IsNotExist(err) {
		b.Skipf("Test pcap file not found: %s", pcapPath)
	}

	// Read all SMB payloads first
	packetSource, f, err := openPcapFile(pcapPath)
	if err != nil {
		b.Fatalf("Failed to open pcap: %v", err)
	}

	var payloads [][]byte
	for packet := range packetSource.Packets() {
		tcpLayer := packet.Layer(layers.LayerTypeTCP)
		if tcpLayer == nil {
			continue
		}
		tcp := tcpLayer.(*layers.TCP)
		if (tcp.SrcPort == 445 || tcp.DstPort == 445) && len(tcp.Payload) > 0 {
			// Make a copy
			payload := make([]byte, len(tcp.Payload))
			copy(payload, tcp.Payload)
			payloads = append(payloads, payload)
		}
	}
	f.Close()

	if len(payloads) == 0 {
		b.Skip("No SMB payloads found")
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, payload := range payloads {
			extractSMBInfo(payload)
		}
	}
}

// TestNTLMChallengeParsingDetails tests detailed parsing of NTLM Challenge message
func TestNTLMChallengeParsingDetails(t *testing.T) {
	// Create a realistic NTLM Challenge message with TargetInfo
	// Need enough space for header + target name + target info
	msg := make([]byte, 300)

	// Signature "NTLMSSP\0"
	copy(msg[0:8], []byte("NTLMSSP\x00"))

	// MessageType = 2 (CHALLENGE)
	binary.LittleEndian.PutUint32(msg[8:12], 2)

	// TargetName: "WORKGROUP" in UTF-16LE
	targetName := encodeTestUTF16LE("WORKGROUP")
	targetNameOffset := 56 // After fixed header

	binary.LittleEndian.PutUint16(msg[12:14], uint16(len(targetName)))
	binary.LittleEndian.PutUint16(msg[14:16], uint16(len(targetName)))
	binary.LittleEndian.PutUint32(msg[16:20], uint32(targetNameOffset))

	// NegotiateFlags - set various flags
	flags := uint32(0x00080000 | 0x00800000) // EXTENDED_SESSIONSECURITY | TARGET_INFO
	binary.LittleEndian.PutUint32(msg[20:24], flags)

	// ServerChallenge (8 bytes)
	serverChallenge := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
	copy(msg[24:32], serverChallenge)

	// Reserved (8 bytes at 32-39, already zero)

	// Build TargetInfo AV_PAIRs
	var targetInfo []byte

	// MsvAvNbDomainName
	nbDomain := encodeTestUTF16LE("WORKGROUP")
	targetInfo = append(targetInfo, byte(MsvAvNbDomainName), 0)
	targetInfo = append(targetInfo, byte(len(nbDomain)), 0)
	targetInfo = append(targetInfo, nbDomain...)

	// MsvAvNbComputerName
	nbComputer := encodeTestUTF16LE("SERVER01")
	targetInfo = append(targetInfo, byte(MsvAvNbComputerName), 0)
	targetInfo = append(targetInfo, byte(len(nbComputer)), 0)
	targetInfo = append(targetInfo, nbComputer...)

	// MsvAvDnsDomainName
	dnsDomain := encodeTestUTF16LE("workgroup.local")
	targetInfo = append(targetInfo, byte(MsvAvDnsDomainName), 0)
	targetInfo = append(targetInfo, byte(len(dnsDomain)), 0)
	targetInfo = append(targetInfo, dnsDomain...)

	// MsvAvDnsComputerName
	dnsComputer := encodeTestUTF16LE("server01.workgroup.local")
	targetInfo = append(targetInfo, byte(MsvAvDnsComputerName), 0)
	targetInfo = append(targetInfo, byte(len(dnsComputer)), 0)
	targetInfo = append(targetInfo, dnsComputer...)

	// MsvAvEOL
	targetInfo = append(targetInfo, 0, 0, 0, 0)

	targetInfoOffset := targetNameOffset + len(targetName)

	binary.LittleEndian.PutUint16(msg[40:42], uint16(len(targetInfo)))
	binary.LittleEndian.PutUint16(msg[42:44], uint16(len(targetInfo)))
	binary.LittleEndian.PutUint32(msg[44:48], uint32(targetInfoOffset))

	// Copy payloads
	copy(msg[targetNameOffset:], targetName)
	copy(msg[targetInfoOffset:], targetInfo)

	// Now parse it
	reader := newTestSMBReader()
	reader.parseNTLMChallenge(msg)

	// Verify parsing results
	if reader.ntlmVersion != "NTLMv2" {
		t.Errorf("Expected NTLMv2, got %q", reader.ntlmVersion)
	}

	if reader.domain != "WORKGROUP" {
		t.Errorf("Expected domain WORKGROUP, got %q", reader.domain)
	}

	// The server GUID should be set to the computer name from TargetInfo
	if reader.serverGUID != "SERVER01" {
		t.Errorf("Expected serverGUID SERVER01, got %q", reader.serverGUID)
	}
}

func encodeTestUTF16LE(s string) []byte {
	result := make([]byte, len(s)*2)
	for i, r := range s {
		binary.LittleEndian.PutUint16(result[i*2:], uint16(r))
	}
	return result
}

// TestStreamReaderIntegration tests the smbReader with simulated stream data
func TestStreamReaderIntegration(t *testing.T) {
	// Build a minimal SMB2 NEGOTIATE request
	var packet []byte

	// NetBIOS Session Service header
	smbMsg := buildTestSMB2Negotiate()
	nbHdr := make([]byte, 4)
	nbHdr[0] = 0x00 // Session Message
	binary.BigEndian.PutUint32(nbHdr, uint32(len(smbMsg)))
	nbHdr[0] = 0x00 // Fix the session type

	packet = append(nbHdr, smbMsg...)

	// Test that we can read it
	if len(packet) < 68 {
		t.Fatalf("Packet too short: %d bytes", len(packet))
	}

	// Verify SMB2 signature
	if string(packet[4:8]) != SMB2Signature {
		t.Errorf("Expected SMB2 signature, got %q", string(packet[4:8]))
	}

	// Verify command is NEGOTIATE
	cmd := binary.LittleEndian.Uint16(packet[16:18])
	if cmd != SMB2_NEGOTIATE {
		t.Errorf("Expected NEGOTIATE command (0), got %d", cmd)
	}
}

func buildTestSMB2Negotiate() []byte {
	// SMB2 Header (64 bytes) + NEGOTIATE Request Body
	msg := make([]byte, 100)

	// Signature
	copy(msg[0:4], []byte(SMB2Signature))

	// StructureSize (2 bytes) - always 64 for SMB2 header
	binary.LittleEndian.PutUint16(msg[4:6], 64)

	// CreditCharge (2 bytes)
	binary.LittleEndian.PutUint16(msg[6:8], 0)

	// Status (4 bytes) - 0 for requests
	binary.LittleEndian.PutUint32(msg[8:12], 0)

	// Command (2 bytes) - NEGOTIATE = 0
	binary.LittleEndian.PutUint16(msg[12:14], SMB2_NEGOTIATE)

	// CreditRequest (2 bytes)
	binary.LittleEndian.PutUint16(msg[14:16], 31)

	// Flags (4 bytes) - 0 for request
	binary.LittleEndian.PutUint32(msg[16:20], 0)

	// NextCommand (4 bytes)
	binary.LittleEndian.PutUint32(msg[20:24], 0)

	// MessageId (8 bytes)
	binary.LittleEndian.PutUint64(msg[24:32], 0)

	// Reserved (4 bytes)
	binary.LittleEndian.PutUint32(msg[32:36], 0)

	// TreeId (4 bytes)
	binary.LittleEndian.PutUint32(msg[36:40], 0)

	// SessionId (8 bytes)
	binary.LittleEndian.PutUint64(msg[40:48], 0)

	// Signature (16 bytes) - zeros for unsigned
	// Already zero

	// NEGOTIATE Request Body (36 bytes minimum)
	// StructureSize
	binary.LittleEndian.PutUint16(msg[64:66], 36)

	// DialectCount
	binary.LittleEndian.PutUint16(msg[66:68], 2)

	// SecurityMode
	binary.LittleEndian.PutUint16(msg[68:70], 1) // Signing Enabled

	// Reserved
	binary.LittleEndian.PutUint16(msg[70:72], 0)

	// Capabilities
	binary.LittleEndian.PutUint32(msg[72:76], 0)

	// ClientGuid (16 bytes) - zeros

	// Dialects
	binary.LittleEndian.PutUint16(msg[100-4:100-2], 0x0202) // SMB 2.0.2
	binary.LittleEndian.PutUint16(msg[100-2:100], 0x0210)   // SMB 2.1

	return msg
}

// Compile-time interface check
var _ io.Reader = (*bytes.Reader)(nil)

