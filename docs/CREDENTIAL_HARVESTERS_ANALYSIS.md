# BruteShark vs Netcap Credential Harvesters Analysis

**Date**: November 23, 2025  
**Analysis Source**: BruteShark project at `/Users/pmieden/Development/BruteShark`

## Executive Summary

This document provides a comprehensive comparison between BruteShark's credential harvesting capabilities and netcap's existing implementation, identifying gaps and providing implementation guidance.

### Key Findings

✅ **Already Implemented in Netcap**:
- FTP plaintext credentials
- HTTP Basic Authentication
- HTTP Digest (partial - needs enhancement)
- Telnet plaintext credentials
- SMTP (Auth Plain, Auth Login, CRAM-MD5)
- IMAP (Login, Authenticate Plain, CRAM-MD5)

❌ **Missing in Netcap** (High-Value Targets):
1. **NTLMSSP Hash Extraction** (NTLMv1 & NTLMv2) - Critical for Windows environments
2. **Kerberos AS-REQ** - Pre-authentication hash extraction
3. **Kerberos AS-REP** - AS-REP roasting support
4. **Kerberos TGS-REP** - Kerberoasting support

⚠️ **Needs Enhancement**:
- HTTP Digest - Currently incomplete, missing parameters needed for Hashcat

---

## Gap Analysis

### 1. NTLMSSP Hash Harvester (CRITICAL PRIORITY)

**Impact**: 🔴 **VERY HIGH**

**Why Important**:
- Used across multiple protocols (SMB, HTTP, IMAP, SMTP, LDAP, RDP)
- Extremely common in Windows/Active Directory environments
- Hashes can be cracked offline with Hashcat
- No account lockout risk

**Protocols Affected**:
- SMB/CIFS (Port 445)
- HTTP/HTTPS (IIS servers)
- IMAP/POP3/SMTP (Exchange servers)
- LDAP (Active Directory)

**Technical Requirements**:
- Session-based analysis (not single packet)
- State machine: WaitForChallenge → WaitForResponse
- Binary protocol parsing (not text-based)
- Support for both NTLMv1 (24-byte response) and NTLMv2 (>24 bytes)

**Hashcat Integration**:
- Mode 5500 (NTLMv1): `username::domain:LM:NT:challenge`
- Mode 5600 (NTLMv2): `username::domain:challenge:NT:blob`

**Test Files Available**:
```
testdata/SMB - NTLM cifs_SessionSetupAndX_NTLM_Plain.pcap  (NTLMv1)
testdata/SMB - NTLMSSP (Windows 10).pcap                   (NTLMv2)
testdata/SMB - NTLMSSP Single Session (Windows 10).pcap    (Clean test case)
testdata/HTTP - NTLM.pcap                                   (HTTP variant)
testdata/HTTP - NTLM GSSAPI.pcap                           (GSSAPI wrapped)
```

**Estimated Effort**: 3-5 days
- Day 1-2: NTLMSSP parser implementation
- Day 3: State machine and session tracking
- Day 4: Testing and validation
- Day 5: Integration and documentation

---

### 2. Kerberos AS-REQ Hash Harvester (HIGH PRIORITY)

**Impact**: 🔴 **HIGH**

**Why Important**:
- Extracts pre-authentication hashes
- Can crack passwords offline without triggering lockouts
- Critical for Active Directory penetration testing
- Works even if pre-auth is required (unlike AS-REP roasting)

**Technical Requirements**:
- UDP packet processing (port 88)
- Binary protocol parsing
- Specific byte pattern matching
- Hash byte order transformation required

**Hashcat Integration**:
- Mode 7500: `$krb5pa$23$user$realm$salt$hash`

**Test Files Available**:
```
testdata/Kerberos - v5 UDP.pcap
testdata/Kerberos v5 UDP 2.pcap
testdata/Kerberos v5 - UDP 3.pcap
```

**Estimated Effort**: 2-3 days
- Day 1: UDP packet processing and pattern matching
- Day 2: Hash extraction and formatting
- Day 3: Testing and validation

---

### 3. Kerberos AS-REP Hash Harvester (HIGH PRIORITY)

**Impact**: 🔴 **HIGH**

**Why Important**:
- AS-REP roasting attack vector
- Targets accounts with "Do not require Kerberos preauthentication"
- Growing attack surface in misconfigured environments
- Multiple encryption types supported

**Technical Requirements**:
- ASN.1 DER/BER parsing required
- Both UDP and TCP support
- Handle 4-byte TCP length prefix
- Support etypes: 17 (AES128), 18 (AES256), 23 (RC4)

**Hashcat Integration**:
- Mode 18200 (etype 23): `$krb5asrep$23$user@domain:hash`
- Mode 19600 (etype 17): AES128-CTS-HMAC-SHA1-96
- Mode 19700 (etype 18): AES256-CTS-HMAC-SHA1-96

**Test Files Available**:
```
testdata/Kerberos - v5 UDP.pcap
testdata/Kerberos - v5 TCP.pcap
testdata/Kerberos v5 UDP 2.pcap
```

**Estimated Effort**: 4-5 days
- Day 1-2: ASN.1 parser implementation
- Day 3: Packet processing (UDP and TCP)
- Day 4: Testing multiple etypes
- Day 5: Integration and validation

---

### 4. Kerberos TGS-REP Hash Harvester (HIGH PRIORITY)

**Impact**: 🔴 **HIGH**

**Why Important**:
- Kerberoasting attack - crack service account passwords
- Very common attack technique
- Service accounts often have weak passwords
- Multiple encryption types

**Technical Requirements**:
- Similar to AS-REP but different message type (13 vs 11)
- ASN.1 parsing
- Extract service principal name (SPN)
- Support multiple etypes

**Hashcat Integration**:
- Mode 13100 (etype 23): `$krb5tgs$23$*user$realm$service*$hash`
- Mode 19600 (etype 17): AES128
- Mode 19700 (etype 18): AES256

**Test Files Available**:
```
testdata/Kerberos-816.pcap
testdata/Kerberos - v5 UDP.pcap
```

**Estimated Effort**: 3-4 days (can leverage AS-REP code)

---

### 5. Enhanced HTTP Digest Harvester (MEDIUM PRIORITY)

**Impact**: 🟡 **MEDIUM**

**Why Important**:
- Complete the existing partial implementation
- Enable offline cracking of HTTP Digest hashes
- Still used by some web applications

**Current Issue**:
```go
// Current code only extracts username
if len(matchesDigest) > 1 {
    username = string(matchesDigest[1])
    password = "" // This doesn't retrieve creds per se
}
```

**What's Needed**:
Parse all digest parameters:
- username, realm, nonce, uri, qop, nc, cnonce, response, method

**Hashcat Integration**:
- Mode 11400: `username:realm:nonce:uri:nc:cnonce:qop:response`

**Test Files Available**:
```
testdata/HTTP - Digest Authentication.pcap
testdata/HTTP - Digest-MD5.pcap
```

**Estimated Effort**: 1-2 days

---

## Implementation Roadmap

### Phase 1: Foundation (Week 1)
**Goal**: Prepare infrastructure for hash-based credentials

- [ ] Update `netcap.proto` with new fields
- [ ] Regenerate protobuf code
- [ ] Update CSV/JSON export logic
- [ ] Test existing harvesters still work

**Files Modified**:
- `netcap.proto`
- `types/credentials.go`

### Phase 2: NTLMSSP (Week 2-3)
**Goal**: Implement NTLMSSP hash extraction

- [ ] Create `decoder/stream/credentials/ntlmssp.go`
- [ ] Implement state machine
- [ ] Support NTLMv1 and NTLMv2
- [ ] Add Hashcat formatting
- [ ] Write unit tests
- [ ] Validate with all test PCAPs

**New Files**:
- `decoder/stream/credentials/ntlmssp.go`
- Tests in `harvesters_new_test.go`

### Phase 3: Kerberos (Week 4-6)
**Goal**: Complete Kerberos support

#### Week 4: AS-REQ
- [ ] Create `decoder/stream/credentials/kerberos_asreq.go`
- [ ] Implement UDP packet processing
- [ ] Add pattern matching logic
- [ ] Test with UDP PCAPs

#### Week 5: AS-REP
- [ ] Create `decoder/stream/credentials/kerberos_asrep.go`
- [ ] Implement ASN.1 parsing
- [ ] Support UDP and TCP
- [ ] Handle multiple etypes
- [ ] Test thoroughly

#### Week 6: TGS-REP
- [ ] Create `decoder/stream/credentials/kerberos_tgsrep.go`
- [ ] Leverage AS-REP code
- [ ] Add SPN extraction
- [ ] Complete testing

**New Files**:
- `decoder/stream/credentials/kerberos_asreq.go`
- `decoder/stream/credentials/kerberos_asrep.go`
- `decoder/stream/credentials/kerberos_tgsrep.go`
- `decoder/stream/credentials/kerberos_common.go` (shared code)

### Phase 4: Enhancements (Week 7)
**Goal**: Polish and additional features

- [ ] Enhance HTTP Digest harvester
- [ ] Implement Hashcat export functionality
- [ ] Add WebUI support for new fields
- [ ] Update documentation

**New Files**:
- `cmd/export/credentials_hashcat.go`
- Frontend updates for credentials page

### Phase 5: Validation & Release (Week 8)
**Goal**: Ensure quality and prepare for release

- [ ] Compare outputs with BruteShark
- [ ] Test Hashcat formats with actual Hashcat
- [ ] Performance testing
- [ ] Security review
- [ ] Update user documentation
- [ ] Create examples/tutorials

---

## Technical Architecture Notes

### Why These Are Not Yet Implemented

1. **Complexity**: Hash-based credentials require binary protocol parsing, not simple regex
2. **State Management**: NTLM requires tracking challenge-response pairs across multiple packets
3. **ASN.1 Parsing**: Kerberos requires ASN.1 DER/BER decoding
4. **Packet vs Session**: Current harvesters are session-based; some Kerberos needs packet-based

### Key Differences from BruteShark

| Aspect | BruteShark | Netcap |
|--------|-----------|---------|
| Language | C# | Go |
| Architecture | Layer separation (DAL/BLL/PL) | Stream-based decoders |
| Parser Interface | IPasswordParser | credentialHarvester func |
| Session Reconstruction | TcpRecon library | Built into stream package |
| ASN.1 Parsing | Asn1 NuGet package | encoding/asn1 (standard lib) |
| Hash Types | NetworkHash separate from NetworkPassword | Single Credentials type (needs extension) |

### Implementation Patterns

#### Pattern 1: Session-Based (NTLM, Telnet)
```go
func harvester(sessionData []byte, ident string, ts time.Time) *types.Credentials
```
- Receives complete bidirectional session data
- Good for: FTP, Telnet, SMTP, IMAP, NTLM
- Current netcap pattern

#### Pattern 2: Packet-Based (Kerberos AS-REQ)
```go
func harvester(packet gopacket.Packet, ts time.Time) *types.Credentials
```
- Receives individual packets
- Good for: Kerberos AS-REQ (UDP single packet)
- Requires new integration point

#### Pattern 3: ASN.1 Based (Kerberos AS-REP/TGS-REP)
```go
func harvester(packet gopacket.Packet, ts time.Time) *types.Credentials {
    // 1. Extract payload
    // 2. Find ASN.1 BER data
    // 3. Decode with asn1.Unmarshal
    // 4. Extract fields
}
```
- Requires ASN.1 struct definitions
- Good for: Kerberos AS-REP, TGS-REP
- Most complex pattern

---

## Testing Strategy

### Unit Tests
Located in: `decoder/stream/credentials/harvesters_new_test.go`

Current status:
- ✅ Test file existence validation
- ✅ Test file readability validation
- ⏳ Protocol-specific tests (stubbed with t.Skip)

### Integration Testing
1. Process each test PCAP through netcap
2. Verify credentials are extracted
3. Compare with BruteShark output
4. Validate Hashcat format

### Validation Commands
```bash
# Extract from PCAP
netcap -r testdata/SMB\ -\ NTLMSSP\ \(Windows\ 10\).pcap -out results/

# View credentials
netcap -r results/Credentials.ncap.gz

# Export for Hashcat
netcap export -r results/Credentials.ncap.gz -format hashcat -out hashes.txt

# Test with Hashcat
hashcat -m 5600 hashes.txt wordlist.txt
```

---

## Expected Outputs

### Example NTLMSSP Output
```
Service: NTLMSSP
User: Administrator
Domain: WORKGROUP
Workstation: DESKTOP-PC
Challenge: a1b2c3d4e5f6g7h8
HashType: NTLMv2
Hash: <full NT response hex>
HashcatFormat: Administrator::WORKGROUP:a1b2c3d4e5f6g7h8:NT:blob
```

### Example Kerberos AS-REQ Output
```
Service: Kerberos
User: jdoe
Domain: EXAMPLE.COM
HashType: Kerberos V5 AS-REQ Pre-Auth etype 23
Etype: 23
Hash: <52-byte hash hex>
HashcatFormat: $krb5pa$23$jdoe$EXAMPLE.COM$$<hash>
```

### Example Kerberos AS-REP Output
```
Service: Kerberos
User: testuser
Realm: EXAMPLE.COM
ServiceName: krbtgt/EXAMPLE.COM
HashType: Kerberos V5 AS-REP etype 23
Etype: 23
Hash: <encrypted ticket hex>
HashcatFormat: $krb5asrep$23$testuser@EXAMPLE.COM:<hash>
```

---

## Resources

### Documentation
- [Full Implementation Guide](./decoder/stream/credentials/IMPLEMENTATION_GUIDE.md)
- [Test Data README](./decoder/stream/credentials/testdata/README.md)
- [Unit Tests](./decoder/stream/credentials/harvesters_new_test.go)

### External References
- [BruteShark Project](https://github.com/odedshimon/BruteShark)
- [Hashcat Example Hashes](https://hashcat.net/wiki/doku.php?id=example_hashes)
- [NTLM Protocol Specification](http://davenport.sourceforge.net/ntlm.html)
- [Kerberos RFC 4120](https://www.rfc-editor.org/rfc/rfc4120)
- [HTTP Digest RFC 7616](https://www.rfc-editor.org/rfc/rfc7616)

### BruteShark Source Files Analyzed
```
BruteShark/PcapAnalyzer/Modules/PasswordsModule/CredentialsParsers/
├── FtpPasswordParser.cs
├── HttpBasicPasswordParser.cs
├── HttpDigestHashParser.cs
├── ImapPasswordParser.cs
├── KerberosAsReqHashParser.cs
├── KerberosTicketHashParser.cs (AS-REP & TGS-REP)
├── NtlmsspHashParser.cs
├── SmtpPasswordParser.cs
└── TelnetPasswordParser.cs
```

---

## Success Metrics

Upon completion, netcap will be able to:

1. ✅ Extract **all credential types** that BruteShark can extract
2. ✅ Format hashes for **direct use with Hashcat**
3. ✅ Process **13 different test PCAP files** successfully
4. ✅ Export in **Hashcat-compatible formats**
5. ✅ Display hash-based credentials in **WebUI**
6. ✅ Support **both Windows and Unix authentication** methods

### Performance Targets
- Process 1GB PCAP in < 2 minutes
- Memory usage < 1GB for typical captures
- Zero credential duplicates in output

### Quality Targets
- 100% unit test coverage for new harvesters
- All test PCAPs produce expected results
- Hashcat formats validate with hashcat tool
- Zero false positives in testing

---

## Conclusion

Implementing these credential harvesters will significantly enhance netcap's capability for network forensics and security assessment, bringing it to feature parity with BruteShark while maintaining netcap's architectural advantages and cross-platform compatibility.

**Total Estimated Effort**: 6-8 weeks full-time development

**Primary Blocker**: ASN.1 parsing complexity for Kerberos

**Highest ROI**: NTLMSSP harvester (affects multiple protocols, widely used)

**Next Steps**:
1. Update protobuf schema
2. Implement NTLMSSP harvester (highest impact)
3. Implement Kerberos harvesters (high security value)
4. Enhance HTTP Digest (quick win)
5. Add Hashcat export (user convenience)

