# Credential Harvesters Implementation Guide

This document provides detailed implementation guidance for the missing credential harvesters in netcap, based on analysis of the [BruteShark](https://github.com/odedshimon/BruteShark) project.

## Table of Contents
1. [Overview](#overview)
2. [Protobuf Schema Updates](#protobuf-schema-updates)
3. [NTLMSSP Harvester](#ntlmssp-harvester)
4. [Kerberos AS-REQ Harvester](#kerberos-as-req-harvester)
5. [Kerberos AS-REP Harvester](#kerberos-as-rep-harvester)
6. [Kerberos TGS-REP Harvester](#kerberos-tgs-rep-harvester)
7. [Enhanced HTTP Digest](#enhanced-http-digest)
8. [Hashcat Export Functionality](#hashcat-export-functionality)

---

## Overview

### Missing Harvesters Priority

| Priority | Harvester | Protocols | Hashcat Modes | Impact |
|----------|-----------|-----------|---------------|--------|
| HIGH | NTLMSSP | SMB, HTTP, IMAP, SMTP | 5500, 5600 | Very common in Windows environments |
| HIGH | Kerberos AS-REQ | Kerberos | 7500 | Pre-auth hash extraction |
| HIGH | Kerberos AS-REP | Kerberos | 18200, 19600, 19700 | AS-REP roasting |
| HIGH | Kerberos TGS-REP | Kerberos | 13100, 19600, 19700 | Kerberoasting |
| MEDIUM | HTTP Digest Enhanced | HTTP | 11400 | Improved digest cracking |

---

## Protobuf Schema Updates

**File**: `netcap.proto`

The current `Credentials` message needs additional fields to support hash-based credentials:

```protobuf
message Credentials {
  int64 Timestamp = 1;
  string Service = 2;
  string Flow = 3;
  string User = 4;
  string Password = 5;      // For plaintext passwords
  string Notes = 6;
  
  // New fields for hash-based credentials
  string Hash = 7;          // The actual hash value
  string HashType = 8;      // e.g., "NTLMv2", "Kerberos AS-REP etype 23"
  string Domain = 9;        // For Kerberos, NTLM
  string Realm = 10;        // For Kerberos
  string Challenge = 11;    // For NTLM, CRAM-MD5
  string ServiceName = 12;  // For Kerberos (SPN)
  int32 Etype = 13;        // For Kerberos encryption type
  string HashcatFormat = 14; // Optional: pre-formatted for Hashcat
  
  // For HTTP Digest
  string Method = 15;       // GET, POST, etc.
  string Nonce = 16;
  string Uri = 17;
  string Qop = 18;          // Quality of Protection
  string Nc = 19;           // Nonce Count
  string Cnonce = 20;       // Client Nonce
  
  // For NTLM
  string Workstation = 21;
  string LmHash = 22;       // LM response
  string NtHash = 23;       // NT response
}
```

**After updating the proto file:**
```bash
# Regenerate Go code
make proto
```

---

## NTLMSSP Harvester

### Overview
NTLMSSP (NT LAN Manager Security Support Provider) is used for authentication in:
- SMB/CIFS file sharing
- HTTP (IIS servers)
- IMAP/POP3/SMTP (Exchange servers)
- LDAP
- RDP

### Architecture

**File**: `decoder/stream/credentials/ntlmssp.go`

```go
package credentials

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"time"

	"github.com/dreadl0ck/netcap/types"
)

// NTLMSSP Message Types
const (
	ntlmsspNegotiate = 0x01
	ntlmsspChallenge = 0x02
	ntlmsspAuth      = 0x03
)

// NTLMSSP Signature
var ntlmsspSignature = []byte{0x4e, 0x54, 0x4c, 0x4d, 0x53, 0x53, 0x50, 0x00}

type ntlmState int

const (
	ntlmStateWaitChallenge ntlmState = iota
	ntlmStateWaitResponse
)

// ntlmsspHarvester extracts NTLM credentials from a TCP session
// It implements a state machine to match challenge-response pairs
func ntlmsspHarvester(data []byte, ident string, ts time.Time) *types.Credentials {
	var (
		challenge  []byte
		username   string
		domain     string
		workstation string
		lmHash     string
		ntHash     string
		state      = ntlmStateWaitChallenge
	)

	// Search for NTLMSSP messages in the session data
	pos := 0
	for pos < len(data) {
		// Look for NTLMSSP signature
		idx := bytes.Index(data[pos:], ntlmsspSignature)
		if idx == -1 {
			break
		}
		
		pos += idx
		if pos+12 > len(data) {
			break
		}

		// Check message type
		msgType := binary.LittleEndian.Uint32(data[pos+8 : pos+12])
		
		switch msgType {
		case ntlmsspChallenge:
			if state == ntlmStateWaitChallenge {
				// Extract 8-byte challenge at offset 24
				if pos+32 <= len(data) {
					challenge = data[pos+24 : pos+32]
					state = ntlmStateWaitResponse
				}
			}
			
		case ntlmsspAuth:
			if state == ntlmStateWaitResponse && len(challenge) > 0 {
				// Extract all fields using offset/length pairs
				lmHash, ntHash, domain, username, workstation = extractNTLMAuthFields(data[pos:])
				
				// Determine if NTLMv1 or NTLMv2
				var hashType string
				var finalHash string
				
				if len(ntHash) == 48 { // 24 bytes hex = 48 chars
					hashType = "NTLMv1"
					finalHash = lmHash
				} else if len(ntHash) > 48 {
					hashType = "NTLMv2"
					finalHash = ntHash
				}
				
				if finalHash != "" {
					return &types.Credentials{
						Timestamp:   ts.UnixNano(),
						Service:     "NTLMSSP",
						Flow:        ident,
						User:        username,
						Domain:      domain,
						Workstation: workstation,
						Challenge:   hex.EncodeToString(challenge),
						LmHash:      lmHash,
						NtHash:      ntHash,
						Hash:        finalHash,
						HashType:    hashType,
						HashcatFormat: formatNTLMForHashcat(username, domain, challenge, lmHash, ntHash, hashType),
					}
				}
			}
		}
		
		pos++
	}
	
	return nil
}

// extractNTLMAuthFields extracts fields from NTLMSSP AUTH message
// Fields are encoded as [length:2][maxlen:2][offset:4]
func extractNTLMAuthFields(data []byte) (lmHash, ntHash, domain, username, workstation string) {
	if len(data) < 64 {
		return
	}
	
	// LM Response: offset 14
	lmLen := int(binary.LittleEndian.Uint16(data[14:16]))
	lmOff := int(binary.LittleEndian.Uint32(data[16:20]))
	if lmOff+lmLen <= len(data) {
		lmHash = hex.EncodeToString(data[lmOff : lmOff+lmLen])
	}
	
	// NTLM Response: offset 22
	ntLen := int(binary.LittleEndian.Uint16(data[22:24]))
	ntOff := int(binary.LittleEndian.Uint32(data[24:28]))
	if ntOff+ntLen <= len(data) {
		ntHash = hex.EncodeToString(data[ntOff : ntOff+ntLen])
	}
	
	// Domain: offset 30
	domLen := int(binary.LittleEndian.Uint16(data[30:32]))
	domOff := int(binary.LittleEndian.Uint32(data[32:36]))
	if domOff+domLen <= len(data) {
		domain = decodeUnicode(data[domOff : domOff+domLen])
	}
	
	// Username: offset 38
	userLen := int(binary.LittleEndian.Uint16(data[38:40]))
	userOff := int(binary.LittleEndian.Uint32(data[40:44]))
	if userOff+userLen <= len(data) {
		username = decodeUnicode(data[userOff : userOff+userLen])
	}
	
	// Workstation: offset 46
	wsLen := int(binary.LittleEndian.Uint16(data[46:48]))
	wsOff := int(binary.LittleEndian.Uint32(data[48:52]))
	if wsOff+wsLen <= len(data) {
		workstation = decodeUnicode(data[wsOff : wsOff+wsLen])
	}
	
	return
}

// decodeUnicode converts UTF-16LE to string
func decodeUnicode(data []byte) string {
	var result []rune
	for i := 0; i < len(data)-1; i += 2 {
		r := rune(binary.LittleEndian.Uint16(data[i : i+2]))
		if r != 0 {
			result = append(result, r)
		}
	}
	return string(result)
}

// formatNTLMForHashcat formats NTLM credentials for Hashcat
func formatNTLMForHashcat(username, domain string, challenge []byte, lmHash, ntHash, hashType string) string {
	chalStr := hex.EncodeToString(challenge)
	
	if hashType == "NTLMv1" {
		// Mode 5500: username::domain:LM:NT:challenge
		return username + "::" + domain + ":" + lmHash + ":" + ntHash + ":" + chalStr
	} else if hashType == "NTLMv2" {
		// Mode 5600: username::domain:challenge:NT:blob
		// Note: For v2, the NT hash contains both the response and the blob
		return username + "::" + domain + ":" + chalStr + ":" + ntHash[:32] + ":" + ntHash[32:]
	}
	
	return ""
}
```

### Integration

Add to `harvester.go`:

```go
// Add to tcpConnectionHarvesters slice
tcpConnectionHarvesters = []credentialHarvester{
	ftpHarvester,
	httpHarvester,
	smtpHarvester,
	telnetHarvester,
	imapHarvester,
	ntlmsspHarvester,  // NEW
}

// Add to port mapping
harvesterPortMapping = map[int]credentialHarvester{
	21:  ftpHarvester,
	80:  httpHarvester,
	445: ntlmsspHarvester,  // SMB
	587: smtpHarvester,
	465: smtpHarvester,
	25:  smtpHarvester,
	23:  telnetHarvester,
	143: imapHarvester,
}
```

---

## Kerberos AS-REQ Harvester

### Overview
Extracts pre-authentication data from Kerberos AS-REQ (Authentication Service Request) packets. This hash can be cracked offline without triggering account lockouts.

### Architecture

**File**: `decoder/stream/credentials/kerberos_asreq.go`

```go
package credentials

import (
	"encoding/hex"
	"time"

	"github.com/dreadl0ck/netcap/types"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

// Kerberos constants
const (
	kerberosPort = 88
	asMsgType    = 0x0a
	rc4EncType   = 0x17
)

// PA-DATA signatures (pre-authentication data)
var (
	paDataSig1 = []byte{0xa2, 0x36, 0x04, 0x34} // Hash length = 54
	paDataSig2 = []byte{0xa2, 0x35, 0x04, 0x33} // Hash length = 53
)

// kerberosASReqHarvester extracts AS-REQ pre-authentication hashes
// This is a UDP packet-based harvester (not session-based)
func kerberosASReqHarvester(packet gopacket.Packet, ts time.Time) *types.Credentials {
	udpLayer := packet.Layer(layers.LayerTypeUDP)
	if udpLayer == nil {
		return nil
	}
	
	udp := udpLayer.(*layers.UDP)
	if udp.DstPort != kerberosPort && udp.SrcPort != kerberosPort {
		return nil
	}
	
	data := udp.Payload
	if len(data) < 150 {
		return nil
	}
	
	// Check for AS-REQ message type and RC4 encryption
	if len(data) > 39 && data[17] == asMsgType && data[39] == rc4EncType {
		// Look for PA-DATA signature
		if len(data) > 44 {
			sigPart := data[40:44]
			
			var paddingLen, hashOffset, userNameOffset, hashItemLen int
			
			if bytes.Equal(sigPart, paDataSig1) || bytes.Equal(sigPart, paDataSig2) {
				hashItemLen = int(data[41])
				
				if hashItemLen == 53 {
					paddingLen = 1
				} else if hashItemLen == 54 {
					paddingLen = 0
				} else {
					// Alternative structure
					hashItemLen = int(data[48])
					hashOffset = 49
					userNameOffset = hashItemLen + 97
				}
				
				if hashOffset == 0 {
					hashOffset = 44
					userNameOffset = 144
				}
				
				hashLen := 52 - paddingLen
				if hashOffset+hashLen > len(data) {
					return nil
				}
				
				hash := data[hashOffset : hashOffset+hashLen]
				
				// Switch byte order: last 36 bytes first, then first 16 bytes
				switchedHash := make([]byte, hashLen)
				copy(switchedHash[0:], hash[16:52])
				copy(switchedHash[36:], hash[0:16])
				
				username := extractKerberosItem(data, userNameOffset-paddingLen)
				domain := extractKerberosItem(data, userNameOffset+len(username)-paddingLen+4)
				
				return &types.Credentials{
					Timestamp:   ts.UnixNano(),
					Service:     "Kerberos",
					User:        username,
					Domain:      domain,
					Hash:        hex.EncodeToString(switchedHash),
					HashType:    "Kerberos V5 AS-REQ Pre-Auth etype 23",
					Etype:       23,
					HashcatFormat: formatKerberosASReqForHashcat(username, domain, switchedHash),
				}
			}
		}
	}
	
	return nil
}

// extractKerberosItem extracts a length-prefixed item from Kerberos message
func extractKerberosItem(data []byte, offset int) string {
	if offset >= len(data) {
		return ""
	}
	
	itemLen := int(data[offset])
	if offset+1+itemLen > len(data) {
		return ""
	}
	
	return string(data[offset+1 : offset+1+itemLen])
}

// formatKerberosASReqForHashcat formats for Hashcat mode 7500
func formatKerberosASReqForHashcat(username, realm string, hash []byte) string {
	// $krb5pa$23$user$realm$salt$hash
	return "$krb5pa$23$" + username + "$" + realm + "$$" + hex.EncodeToString(hash)
}
```

### Integration Notes

- Kerberos AS-REQ requires UDP packet processing, not session-based
- Need to add UDP packet harvester support to the credentials decoder
- Port 88 is standard for Kerberos

---

## Kerberos AS-REP Harvester

### Overview
Extracts encrypted tickets from AS-REP responses. Useful for AS-REP roasting attacks against accounts with "Do not require Kerberos preauthentication" enabled.

### Dependencies
Requires ASN.1 parsing library:
```go
import "encoding/asn1"
```

### Architecture

**File**: `decoder/stream/credentials/kerberos_asrep.go`

```go
package credentials

import (
	"encoding/asn1"
	"encoding/hex"
	"time"

	"github.com/dreadl0ck/netcap/types"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

// ASN.1 structures for Kerberos
// Based on RFC 4120

type PrincipalName struct {
	NameType int      `asn1:"explicit,tag:0"`
	Name     []string `asn1:"explicit,tag:1"`
}

type EncryptedData struct {
	Etype  int    `asn1:"explicit,tag:0"`
	Kvno   int    `asn1:"explicit,optional,tag:1"`
	Cipher []byte `asn1:"explicit,tag:2"`
}

type Ticket struct {
	TktVno int           `asn1:"explicit,tag:0"`
	Realm  string        `asn1:"explicit,tag:1"`
	Sname  PrincipalName `asn1:"explicit,tag:2"`
	EncPart EncryptedData `asn1:"explicit,tag:3"`
}

type ASRep struct {
	Pvno    int           `asn1:"explicit,tag:0"`
	MsgType int           `asn1:"explicit,tag:1"`
	Crealm  string        `asn1:"explicit,tag:3"`
	Cname   PrincipalName `asn1:"explicit,tag:4"`
	Ticket  Ticket        `asn1:"explicit,tag:5"`
}

// kerberosASRepHarvester extracts AS-REP hashes
func kerberosASRepHarvester(packet gopacket.Packet, ts time.Time) *types.Credentials {
	var data []byte
	var protocol string
	
	// Check UDP
	if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
		udp := udpLayer.(*layers.UDP)
		if udp.DstPort != kerberosPort && udp.SrcPort != kerberosPort {
			return nil
		}
		data = udp.Payload
		protocol = "UDP"
	} else if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		// Check TCP
		tcp := tcpLayer.(*layers.TCP)
		if tcp.DstPort != kerberosPort && tcp.SrcPort != kerberosPort {
			return nil
		}
		data = tcp.Payload
		protocol = "TCP"
		
		// TCP Kerberos has 4-byte length prefix
		if len(data) > 4 {
			data = data[4:]
		}
	} else {
		return nil
	}
	
	if len(data) < 20 {
		return nil
	}
	
	// Find ASN.1 BER data
	asnData := findBER(data)
	if asnData == nil {
		return nil
	}
	
	// Try to decode as AS-REP
	var asrep ASRep
	_, err := asn1.Unmarshal(asnData, &asrep)
	if err != nil {
		return nil
	}
	
	// AS-REP message type is 11
	if asrep.MsgType != 11 {
		return nil
	}
	
	// Only extract for supported etypes
	if asrep.Ticket.EncPart.Etype == 23 || asrep.Ticket.EncPart.Etype == 18 || asrep.Ticket.EncPart.Etype == 17 {
		username := asrep.Cname.Name[0]
		serviceName := asrep.Ticket.Sname.Name[0]
		
		var hashcatMode int
		switch asrep.Ticket.EncPart.Etype {
		case 17:
			hashcatMode = 19600
		case 18:
			hashcatMode = 19700
		case 23:
			hashcatMode = 18200
		}
		
		return &types.Credentials{
			Timestamp:   ts.UnixNano(),
			Service:     "Kerberos",
			User:        username,
			Realm:       asrep.Ticket.Realm,
			ServiceName: serviceName,
			Hash:        hex.EncodeToString(asrep.Ticket.EncPart.Cipher),
			HashType:    fmt.Sprintf("Kerberos V5 AS-REP etype %d", asrep.Ticket.EncPart.Etype),
			Etype:       int32(asrep.Ticket.EncPart.Etype),
			HashcatFormat: formatKerberosASRepForHashcat(username, asrep.Ticket.Realm, asrep.Ticket.EncPart.Cipher, asrep.Ticket.EncPart.Etype, hashcatMode),
		}
	}
	
	return nil
}

// findBER searches for ASN.1 BER encoded data
func findBER(data []byte) []byte {
	// Look for ASN.1 application tag
	for i := 0; i < len(data)-5; i++ {
		if data[i]&0x60 == 0x60 { // Application class
			return data[i:]
		}
	}
	return nil
}

// formatKerberosASRepForHashcat formats for Hashcat
func formatKerberosASRepForHashcat(username, realm string, cipher []byte, etype, mode int) string {
	switch mode {
	case 18200: // etype 23
		return "$krb5asrep$23$" + username + "@" + realm + ":" + hex.EncodeToString(cipher)
	case 19600, 19700: // etype 17, 18
		return "$krb5asrep$" + fmt.Sprintf("%d", etype) + "$" + username + "@" + realm + ":" + hex.EncodeToString(cipher)
	}
	return ""
}
```

---

## Kerberos TGS-REP Harvester

### Overview
Extracts service ticket hashes from TGS-REP responses. Used for Kerberoasting attacks to crack service account passwords.

### Architecture

**File**: `decoder/stream/credentials/kerberos_tgsrep.go`

```go
package credentials

// Similar structure to AS-REP but for TGS-REP

type TGSRep struct {
	Pvno    int           `asn1:"explicit,tag:0"`
	MsgType int           `asn1:"explicit,tag:1"`
	Crealm  string        `asn1:"explicit,tag:3"`
	Cname   PrincipalName `asn1:"explicit,tag:4"`
	Ticket  Ticket        `asn1:"explicit,tag:5"`
}

// kerberosTGSRepHarvester extracts TGS-REP hashes
func kerberosTGSRepHarvester(packet gopacket.Packet, ts time.Time) *types.Credentials {
	// Very similar to AS-REP harvester
	// Main difference: message type is 13 (TGS-REP) instead of 11 (AS-REP)
	
	// [Implementation similar to AS-REP with TGS-REP message type = 13]
	
	// Hashcat format for mode 13100 (etype 23):
	// $krb5tgs$23$*user$realm$service*$hash
}
```

---

## Enhanced HTTP Digest

### Current Implementation Issue
The current HTTP harvester only extracts the username for Digest auth:

```go
if len(matchesDigest) > 1 {
	username = string(matchesDigest[1])
	password = "" // This doesn't retrieve creds per se
}
```

### Enhanced Implementation

**File**: `decoder/stream/credentials/http.go` (update)

```go
type httpDigestParams struct {
	Username string
	Realm    string
	Nonce    string
	URI      string
	QoP      string
	NC       string
	CNonce   string
	Response string
	Method   string
}

func parseHTTPDigest(data []byte) *httpDigestParams {
	// Find the HTTP method
	methodEnd := bytes.IndexByte(data, ' ')
	if methodEnd == -1 {
		return nil
	}
	method := string(data[:methodEnd])
	
	// Find Authorization: Digest header
	digestIdx := bytes.Index(data, []byte("Authorization: Digest"))
	if digestIdx == -1 {
		return nil
	}
	
	// Extract header line
	lineEnd := bytes.Index(data[digestIdx:], []byte("\r\n"))
	if lineEnd == -1 {
		return nil
	}
	
	headerLine := string(data[digestIdx : digestIdx+lineEnd])
	
	// Parse key=value pairs
	params := &httpDigestParams{Method: method}
	
	// Split by comma and parse each part
	parts := strings.Split(headerLine, ",")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		
		if strings.Contains(part, "username=") {
			params.Username = extractValue(part, "username")
		} else if strings.Contains(part, "realm=") {
			params.Realm = extractValue(part, "realm")
		} else if strings.Contains(part, "nonce=") {
			params.Nonce = extractValue(part, "nonce")
		} else if strings.Contains(part, "uri=") {
			params.URI = extractValue(part, "uri")
		} else if strings.Contains(part, "qop=") {
			params.QoP = extractValue(part, "qop")
		} else if strings.Contains(part, "nc=") {
			params.NC = extractValue(part, "nc")
		} else if strings.Contains(part, "cnonce=") {
			params.CNonce = extractValue(part, "cnonce")
		} else if strings.Contains(part, "response=") {
			params.Response = extractValue(part, "response")
		}
	}
	
	return params
}

func extractValue(part, key string) string {
	idx := strings.Index(part, key+"=")
	if idx == -1 {
		return ""
	}
	
	value := part[idx+len(key)+1:]
	value = strings.Trim(value, "\" ")
	return value
}

// Update httpHarvester to use this
func httpHarvester(data []byte, ident string, ts time.Time) *types.Credentials {
	// ... existing basic auth code ...
	
	// Enhanced digest handling
	if digestParams := parseHTTPDigest(data); digestParams != nil {
		hashcatFormat := fmt.Sprintf("%s:%s:%s:%s:%s:%s:%s:%s",
			digestParams.Username,
			digestParams.Realm,
			digestParams.Nonce,
			digestParams.URI,
			digestParams.NC,
			digestParams.CNonce,
			digestParams.QoP,
			digestParams.Response,
		)
		
		return &types.Credentials{
			Timestamp:     ts.UnixNano(),
			Service:       "HTTP Digest",
			Flow:          ident,
			User:          digestParams.Username,
			Realm:         digestParams.Realm,
			Nonce:         digestParams.Nonce,
			Uri:           digestParams.URI,
			Qop:           digestParams.QoP,
			Nc:            digestParams.NC,
			Cnonce:        digestParams.CNonce,
			Hash:          digestParams.Response,
			HashType:      "HTTP-Digest",
			Method:        digestParams.Method,
			HashcatFormat: hashcatFormat,
		}
	}
	
	return nil
}
```

---

## Hashcat Export Functionality

### Overview
Add ability to export credentials in Hashcat-ready format.

**File**: `cmd/export/credentials_hashcat.go` (new)

```go
package export

import (
	"fmt"
	"io"
	
	"github.com/dreadl0ck/netcap/types"
)

// ExportCredentialsHashcat exports credentials in Hashcat format
func ExportCredentialsHashcat(creds []*types.Credentials, w io.Writer) error {
	// Group by hash type
	byType := make(map[string][]*types.Credentials)
	
	for _, c := range creds {
		if c.HashcatFormat != "" {
			byType[c.HashType] = append(byType[c.HashType], c)
		}
	}
	
	// Write each type to separate section
	for hashType, credentials := range byType {
		fmt.Fprintf(w, "# %s\n", hashType)
		fmt.Fprintf(w, "# Hashcat mode: %s\n", getHashcatMode(hashType))
		fmt.Fprintf(w, "# Count: %d\n\n", len(credentials))
		
		for _, c := range credentials {
			fmt.Fprintln(w, c.HashcatFormat)
		}
		
		fmt.Fprintln(w)
	}
	
	return nil
}

func getHashcatMode(hashType string) string {
	modes := map[string]string{
		"NTLMv1":                                  "5500",
		"NTLMv2":                                  "5600",
		"Kerberos V5 AS-REQ Pre-Auth etype 23":   "7500",
		"Kerberos V5 AS-REP etype 23":            "18200",
		"Kerberos V5 AS-REP etype 17":            "19600",
		"Kerberos V5 AS-REP etype 18":            "19700",
		"Kerberos V5 TGS-REP etype 23":           "13100",
		"Kerberos V5 TGS-REP etype 17":           "19600",
		"Kerberos V5 TGS-REP etype 18":           "19700",
		"HTTP-Digest":                             "11400",
		"CRAM-MD5":                                "16400",
	}
	
	if mode, ok := modes[hashType]; ok {
		return mode
	}
	return "unknown"
}
```

### CLI Integration

Add flag to export command:

```bash
netcap export -r credentials.ncap.gz -format hashcat -out hashes.txt
```

---

## Testing Strategy

### Unit Tests
- Use the PCAP files in `testdata/`
- Create tests for each protocol/scenario
- Verify extracted values match expected results

### Integration Tests
- Process complete PCAP files
- Verify credentials are written to audit records
- Test deduplication logic

### Validation
- Compare outputs with BruteShark results
- Test Hashcat format with actual Hashcat
- Verify hash cracking works

---

## Implementation Checklist

### Phase 1: Foundation
- [ ] Update protobuf schema
- [ ] Regenerate Go code
- [ ] Update CSV/JSON exports

### Phase 2: NTLMSSP (Priority 1)
- [ ] Implement NTLMSSP parser
- [ ] Add state machine
- [ ] Support NTLMv1 and NTLMv2
- [ ] Add unit tests
- [ ] Test with all NTLM PCAPs

### Phase 3: Kerberos (Priority 1)
- [ ] Implement AS-REQ harvester
- [ ] Implement AS-REP harvester (with ASN.1)
- [ ] Implement TGS-REP harvester
- [ ] Handle both UDP and TCP
- [ ] Add unit tests
- [ ] Test with all Kerberos PCAPs

### Phase 4: Enhancements (Priority 2)
- [ ] Enhance HTTP Digest parser
- [ ] Add Hashcat export functionality
- [ ] Update documentation
- [ ] Add WebUI support for new fields

### Phase 5: Validation
- [ ] Compare with BruteShark outputs
- [ ] Test Hashcat formats
- [ ] Performance testing
- [ ] Security review

---

## References

- [BruteShark Source Code](https://github.com/odedshimon/BruteShark)
- [Hashcat Example Hashes](https://hashcat.net/wiki/doku.php?id=example_hashes)
- [NTLM Protocol Specification](http://davenport.sourceforge.net/ntlm.html)
- [Kerberos RFC 4120](https://www.rfc-editor.org/rfc/rfc4120)
- [HTTP Digest RFC 7616](https://www.rfc-editor.org/rfc/rfc7616)
- [ASN.1 Go Package](https://pkg.go.dev/encoding/asn1)

