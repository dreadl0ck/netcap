# Kerberos AS-REP & TGS-REP Implementation Plan

## Overview

This document outlines the implementation plan for the remaining Kerberos credential harvesters that require ASN.1 (Abstract Syntax Notation One) parsing support.

## Current Status

### ✅ Completed
- NTLMSSP (NTLMv1 & NTLMv2) - Session-based, binary parsing
- HTTP Digest (Enhanced) - Text-based header parsing
- Kerberos AS-REQ - Binary pattern matching, no ASN.1 required

### ⏳ Remaining
- **Kerberos AS-REP** - Requires ASN.1 DER/BER decoding
- **Kerberos TGS-REP** - Requires ASN.1 DER/BER decoding

---

## Why ASN.1 is Required

### The Problem
Kerberos messages (AS-REP, TGS-REP) are encoded using ASN.1 DER (Distinguished Encoding Rules) or BER (Basic Encoding Rules). Unlike AS-REQ which has a predictable binary structure we can pattern-match, AS-REP and TGS-REP contain:

1. **Variable-length fields** with type-length-value (TLV) encoding
2. **Nested structures** (tickets contain encrypted data, which contains ciphers)
3. **Optional fields** that may or may not be present
4. **Tagged fields** using explicit/implicit ASN.1 tags

### Example AS-REP Structure (RFC 4120)
```asn1
AS-REP ::= [APPLICATION 11] SEQUENCE {
    pvno            [0] INTEGER (5),
    msg-type        [1] INTEGER (11),
    padata          [2] SEQUENCE OF PA-DATA OPTIONAL,
    crealm          [3] Realm,
    cname           [4] PrincipalName,
    ticket          [5] Ticket,
    enc-part        [6] EncryptedData
}

Ticket ::= [APPLICATION 1] SEQUENCE {
    tkt-vno         [0] INTEGER (5),
    realm           [1] Realm,
    sname           [2] PrincipalName,
    enc-part        [3] EncryptedData
}

EncryptedData ::= SEQUENCE {
    etype           [0] Int32 -- EncryptionType,
    kvno            [1] UInt32 OPTIONAL,
    cipher          [2] OCTET STRING -- ciphertext
}
```

**Without ASN.1 parser**: We cannot reliably navigate these nested, tagged structures.

---

## Implementation Approaches

### Option 1: Use Go's Standard Library `encoding/asn1`

#### Pros
- ✅ Standard library - no external dependencies
- ✅ Well-tested and maintained
- ✅ Supports basic ASN.1 DER decoding
- ✅ Type-safe struct mapping

#### Cons
- ❌ Limited support for EXPLICIT/IMPLICIT tagging (common in Kerberos)
- ❌ No built-in support for APPLICATION tags
- ❌ May require manual tag handling
- ❌ Kerberos uses complex tagging that `encoding/asn1` struggles with

#### Example Usage
```go
import "encoding/asn1"

type EncryptedData struct {
    Etype  int    `asn1:"explicit,tag:0"`
    Kvno   int    `asn1:"explicit,optional,tag:1"`
    Cipher []byte `asn1:"explicit,tag:2"`
}

var ed EncryptedData
_, err := asn1.Unmarshal(data, &ed)
```

#### Assessment
⚠️ **Challenging** - Kerberos uses APPLICATION tags and complex explicit tagging that `encoding/asn1` doesn't handle well out of the box.

---

### Option 2: Use Third-Party ASN.1 Library

#### Option 2A: `github.com/google/der-ascii`
- Purpose: DER encoding/decoding with ASCII representation
- Status: Well-maintained by Google
- Complexity: Low-level, requires manual parsing

#### Option 2B: `github.com/jcmturner/gokrb5`
- Purpose: **Pure Go Kerberos v5 library**
- Status: ✅ Actively maintained, 1.8k stars
- Features: Full Kerberos protocol implementation
- **RECOMMENDATION**: ⭐ **Best choice**

#### Pros of `gokrb5`
- ✅ Already implements AS-REP and TGS-REP parsing
- ✅ Handles all Kerberos ASN.1 structures
- ✅ Supports multiple encryption types (etype 17, 18, 23)
- ✅ Well-documented and tested
- ✅ Pure Go - no CGO dependencies
- ✅ Can extract exactly what we need (encrypted tickets)

#### Cons of `gokrb5`
- ❌ Adds external dependency (~50KB)
- ❌ Includes more than we need (full Kerberos client)

#### Example with `gokrb5`
```go
import (
    "github.com/jcmturner/gokrb5/v8/messages"
    "github.com/jcmturner/gokrb5/v8/iana/msgtype"
)

// For AS-REP
var asrep messages.ASRep
err := asrep.Unmarshal(packetData)
if err == nil {
    // Extract fields
    username := asrep.CName.NameString[0]
    realm := asrep.CRealm
    etype := asrep.Ticket.EncPart.EType
    cipher := asrep.Ticket.EncPart.Cipher
}

// For TGS-REP
var tgsrep messages.TGSRep
err := tgsrep.Unmarshal(packetData)
```

---

### Option 3: Manual ASN.1 Parsing

Write custom ASN.1 decoder for just the Kerberos structures we need.

#### Pros
- ✅ No dependencies
- ✅ Minimal code
- ✅ Full control

#### Cons
- ❌ High complexity - ASN.1 BER/DER is non-trivial
- ❌ Error-prone - easy to miss edge cases
- ❌ Maintenance burden
- ❌ Would take weeks to implement correctly

#### Assessment
❌ **Not Recommended** - Too complex and time-consuming given that good libraries exist.

---

## Recommended Approach: Use `gokrb5`

### Rationale
1. **Proven Solution**: Library already handles all Kerberos ASN.1 parsing
2. **Low Risk**: Well-tested with 1.8k+ stars, actively maintained
3. **Fast Implementation**: Can be done in 1-2 days vs weeks for manual parsing
4. **Correct Handling**: Properly handles all encryption types and edge cases
5. **Future-Proof**: If Kerberos protocol evolves, library will be updated

### Dependency Addition
```bash
go get github.com/jcmturner/gokrb5/v8
```

---

## Implementation Plan

### Phase 1: Setup (Day 1)
**Goal**: Add dependency and create skeleton code

#### Tasks
- [ ] Add `gokrb5` to `go.mod`
- [ ] Create `kerberos_asrep.go`
- [ ] Create `kerberos_tgsrep.go`
- [ ] Create `kerberos_common.go` (shared utilities)
- [ ] Set up basic packet detection

#### Files
```
decoder/stream/credentials/
├── kerberos_asreq.go      (existing)
├── kerberos_asrep.go      (new)
├── kerberos_tgsrep.go     (new)
└── kerberos_common.go     (new - shared functions)
```

---

### Phase 2: AS-REP Harvester (Day 2-3)

#### Code Structure
```go
// kerberos_asrep.go
package credentials

import (
    "encoding/hex"
    "fmt"
    "time"

    "github.com/dreadl0ck/netcap/types"
    "github.com/jcmturner/gokrb5/v8/messages"
)

func kerberosASRepHarvester(data []byte, ident string, ts time.Time) *types.Credentials {
    // Handle TCP record mark (4-byte length prefix)
    payload := handleKerberosRecordMark(data)
    if payload == nil {
        return nil
    }

    // Try to unmarshal as AS-REP
    var asrep messages.ASRep
    err := asrep.Unmarshal(payload)
    if err != nil {
        return nil
    }

    // Extract required fields
    username := extractPrincipalName(asrep.CName)
    realm := asrep.CRealm
    serviceName := extractPrincipalName(asrep.Ticket.SName)
    etype := asrep.Ticket.EncPart.EType
    cipher := asrep.Ticket.EncPart.Cipher

    // Only process supported etypes
    if !isSupportedEtype(etype) {
        return nil
    }

    // Format for Hashcat
    hashcatFormat := formatASRepForHashcat(username, realm, cipher, etype)
    hashcatMode := getHashcatMode("AS-REP", etype)

    return &types.Credentials{
        Timestamp: ts.UnixNano(),
        Service:   "Kerberos",
        Flow:      ident,
        User:      username,
        Password:  hashcatFormat,
        Notes:     fmt.Sprintf("HashType: Kerberos V5 AS-REP etype %d, Realm: %s, Service: %s, Hashcat mode: %d", 
                              etype, realm, serviceName, hashcatMode),
    }
}
```

#### Hashcat Format Functions
```go
// kerberos_common.go

// Supported encryption types
const (
    EtypeAES128CTS      = 17
    EtypeAES256CTS      = 18
    EtypeRC4HMAC        = 23
)

func isSupportedEtype(etype int32) bool {
    return etype == EtypeAES128CTS || etype == EtypeAES256CTS || etype == EtypeRC4HMAC
}

func getHashcatMode(msgType string, etype int32) int {
    switch msgType {
    case "AS-REP":
        switch etype {
        case EtypeRC4HMAC:
            return 18200
        case EtypeAES128CTS:
            return 19600
        case EtypeAES256CTS:
            return 19700
        }
    case "TGS-REP":
        switch etype {
        case EtypeRC4HMAC:
            return 13100
        case EtypeAES128CTS:
            return 19600
        case EtypeAES256CTS:
            return 19700
        }
    }
    return 0
}

func formatASRepForHashcat(username, realm string, cipher []byte, etype int32) string {
    hash := hex.EncodeToString(cipher)
    
    switch etype {
    case EtypeRC4HMAC:
        // Mode 18200: $krb5asrep$23$user@domain:hash
        return fmt.Sprintf("$krb5asrep$23$%s@%s:%s", username, realm, hash)
    
    case EtypeAES128CTS:
        // Mode 19600: $krb5asrep$17$user@domain:hash
        return fmt.Sprintf("$krb5asrep$17$%s@%s:%s", username, realm, hash)
    
    case EtypeAES256CTS:
        // Mode 19700: $krb5asrep$18$user@domain:hash
        return fmt.Sprintf("$krb5asrep$18$%s@%s:%s", username, realm, hash)
    }
    
    return ""
}

func extractPrincipalName(pname messages.PrincipalName) string {
    if len(pname.NameString) > 0 {
        return pname.NameString[0]
    }
    return ""
}

func handleKerberosRecordMark(data []byte) []byte {
    // TCP Kerberos has 4-byte big-endian length prefix
    // Check if this looks like TCP format
    if len(data) > 4 && data[0] == 0x00 && data[1] == 0x00 {
        // Skip the 4-byte record mark
        return data[4:]
    }
    // Otherwise assume UDP (no record mark)
    return data
}
```

#### Testing
```go
// Test with: testdata/Kerberos - v5 UDP.pcap
// Expected: Extract AS-REP tickets with etypes 17, 18, or 23
```

---

### Phase 3: TGS-REP Harvester (Day 4)

#### Code Structure
```go
// kerberos_tgsrep.go
package credentials

import (
    "encoding/hex"
    "fmt"
    "time"

    "github.com/dreadl0ck/netcap/types"
    "github.com/jcmturner/gokrb5/v8/messages"
)

func kerberosTGSRepHarvester(data []byte, ident string, ts time.Time) *types.Credentials {
    payload := handleKerberosRecordMark(data)
    if payload == nil {
        return nil
    }

    // Try to unmarshal as TGS-REP
    var tgsrep messages.TGSRep
    err := tgsrep.Unmarshal(payload)
    if err != nil {
        return nil
    }

    username := extractPrincipalName(tgsrep.CName)
    realm := tgsrep.CRealm
    serviceName := extractPrincipalName(tgsrep.Ticket.SName)
    etype := tgsrep.Ticket.EncPart.EType
    cipher := tgsrep.Ticket.EncPart.Cipher

    if !isSupportedEtype(etype) {
        return nil
    }

    hashcatFormat := formatTGSRepForHashcat(username, realm, serviceName, cipher, etype)
    hashcatMode := getHashcatMode("TGS-REP", etype)

    return &types.Credentials{
        Timestamp: ts.UnixNano(),
        Service:   "Kerberos",
        Flow:      ident,
        User:      username,
        Password:  hashcatFormat,
        Notes:     fmt.Sprintf("HashType: Kerberos V5 TGS-REP etype %d, Realm: %s, Service: %s (Kerberoasting), Hashcat mode: %d", 
                              etype, realm, serviceName, hashcatMode),
    }
}

func formatTGSRepForHashcat(username, realm, service string, cipher []byte, etype int32) string {
    hash := hex.EncodeToString(cipher)
    
    switch etype {
    case EtypeRC4HMAC:
        // Mode 13100: $krb5tgs$23$*user$realm$service*$hash
        return fmt.Sprintf("$krb5tgs$23$*%s$%s$%s*$%s", username, realm, service, hash)
    
    case EtypeAES128CTS:
        // Mode 19600: $krb5tgs$17$*user$realm$service*$hash
        return fmt.Sprintf("$krb5tgs$17$*%s$%s$%s*$%s", username, realm, service, hash)
    
    case EtypeAES256CTS:
        // Mode 19700: $krb5tgs$18$*user$realm$service*$hash
        return fmt.Sprintf("$krb5tgs$18$*%s$%s$%s*$%s", username, realm, service, hash)
    }
    
    return ""
}
```

#### Testing
```go
// Test with: testdata/Kerberos-816.pcap
// Expected: Extract TGS-REP service tickets
```

---

### Phase 4: Integration (Day 5)

#### Update Harvester Registry
```go
// harvester.go

tcpConnectionHarvesters = []credentialHarvester{
    ftpHarvester,
    httpHarvester,
    smtpHarvester,
    telnetHarvester,
    imapHarvester,
    ntlmsspHarvester,
    kerberosASReqHarvester,
    kerberosASRepHarvester,   // NEW
    kerberosTGSRepHarvester,  // NEW
}
```

#### Handle Both UDP and TCP
Since Kerberos can use both UDP (port 88) and TCP (port 88 with record mark):

```go
// Both harvesters need to handle:
// 1. UDP packets (direct Kerberos data)
// 2. TCP streams (4-byte length prefix + Kerberos data)

// The handleKerberosRecordMark() function detects and strips TCP record mark
```

---

### Phase 5: Testing & Validation (Day 6)

#### Unit Tests
```go
// Update harvesters_new_test.go

func TestKerberosASRepUDP(t *testing.T) {
    // Remove t.Skip() and implement actual test
    pcapFile := filepath.Join("testdata", "Kerberos - v5 UDP.pcap")
    
    // Process packets
    // Verify AS-REP extraction
    // Validate Hashcat format
}

func TestKerberosTGSRep(t *testing.T) {
    // Remove t.Skip() and implement actual test
    pcapFile := filepath.Join("testdata", "Kerberos-816.pcap")
    
    // Process packets
    // Verify TGS-REP extraction
    // Validate Hashcat format
}
```

#### Integration Tests
```bash
# Test with real PCAP files
netcap -r testdata/Kerberos\ -\ v5\ UDP.pcap -out test-output/
netcap -r test-output/Credentials.ncap.gz

# Verify credentials extracted
# Check Hashcat format is correct
```

#### Validation with BruteShark
Compare output with BruteShark for same PCAP files to ensure accuracy.

---

## Expected Output Examples

### AS-REP (etype 23)
```
Service: Kerberos
User: testuser
Flow: 192.168.1.10:49152->192.168.1.1:88
Password: $krb5asrep$23$testuser@EXAMPLE.COM:a1b2c3d4e5f6...
Notes: HashType: Kerberos V5 AS-REP etype 23, Realm: EXAMPLE.COM, Service: krbtgt/EXAMPLE.COM, Hashcat mode: 18200
```

### TGS-REP (etype 23) - Kerberoasting
```
Service: Kerberos
User: jdoe
Flow: 192.168.1.10:49153->192.168.1.1:88
Password: $krb5tgs$23$*jdoe$EXAMPLE.COM$HTTP/webserver.example.com*$a1b2c3d4e5f6...
Notes: HashType: Kerberos V5 TGS-REP etype 23, Realm: EXAMPLE.COM, Service: HTTP/webserver.example.com (Kerberoasting), Hashcat mode: 13100
```

---

## Error Handling

### Common Issues to Handle

1. **Malformed Packets**
```go
err := asrep.Unmarshal(payload)
if err != nil {
    // Log but don't fail - might be other traffic on port 88
    return nil
}
```

2. **Unsupported Etypes**
```go
// Only extract etypes 17, 18, 23
// Silently skip others (DES, etc.)
if !isSupportedEtype(etype) {
    return nil
}
```

3. **TCP vs UDP Detection**
```go
// Auto-detect record mark
// Handle both transparently
```

4. **Empty Principal Names**
```go
if len(pname.NameString) == 0 {
    return "" // or return "unknown"
}
```

---

## Performance Considerations

### Memory Usage
- `gokrb5` structures are efficient
- Only parse relevant messages
- No buffering of entire streams

### CPU Usage
- ASN.1 parsing is fast (< 1ms per packet)
- Only run on port 88 traffic
- Early exit on unmarshal failure

### Network Traffic
- No additional network calls
- Passive analysis only

---

## Security Considerations

### Hash Handling
- Hashes are already encrypted tickets
- Store in standard Credentials structure
- Follow existing deduplication logic

### Sensitive Data
- Same as existing credential harvesters
- User responsible for secure storage
- Hashes are meant to be cracked

---

## Alternative: Simplified Manual Parser

If we want to avoid the `gokrb5` dependency entirely, we can implement a **minimal ASN.1 parser** for just the fields we need:

### Pros
- ✅ No dependencies
- ✅ Smaller code footprint

### Cons
- ❌ Much more complex (2-3 weeks)
- ❌ Higher bug risk
- ❌ Harder to maintain

### Minimal ASN.1 Parser Approach
```go
// Would need to implement:
// 1. TLV (Type-Length-Value) decoder
// 2. Tag parser (APPLICATION, EXPLICIT, IMPLICIT)
// 3. SEQUENCE parser
// 4. INTEGER parser
// 5. OCTET STRING parser
// 6. Nested structure navigation

// Example (oversimplified):
type asn1Parser struct {
    data []byte
    pos  int
}

func (p *asn1Parser) readTag() (class, constructed bool, tag int) {
    // Parse tag byte
}

func (p *asn1Parser) readLength() int {
    // Parse length (can be 1 byte or multi-byte)
}

func (p *asn1Parser) readValue(length int) []byte {
    // Read value bytes
}

// Then navigate Kerberos structure...
```

**Assessment**: ❌ Not worth the effort when `gokrb5` exists and is well-tested.

---

## Timeline Summary

| Phase | Duration | Description |
|-------|----------|-------------|
| Phase 1 | 1 day | Setup & dependency |
| Phase 2 | 2 days | AS-REP implementation |
| Phase 3 | 1 day | TGS-REP implementation |
| Phase 4 | 1 day | Integration |
| Phase 5 | 1 day | Testing & validation |
| **Total** | **6 days** | Complete implementation |

---

## Risk Assessment

| Risk | Probability | Impact | Mitigation |
|------|-------------|---------|------------|
| `gokrb5` breaking changes | Low | Medium | Pin to specific version, monitor releases |
| ASN.1 parsing errors | Low | High | Extensive testing with real PCAPs |
| Performance impact | Low | Low | Only runs on port 88, fast unmarshaling |
| Missing edge cases | Medium | Medium | Compare with BruteShark output |

---

## Success Criteria

✅ **Complete when:**
1. AS-REP harvester extracts etypes 17, 18, 23
2. TGS-REP harvester extracts etypes 17, 18, 23
3. Hashcat formats match specification
4. All test PCAPs process without errors
5. Output matches BruteShark for same inputs
6. Unit tests pass
7. Integration tests pass
8. Documentation updated

---

## Recommendation

**Proceed with `gokrb5` approach**

### Justification
1. ✅ **Fastest**: 6 days vs 3-4 weeks for manual parser
2. ✅ **Most Reliable**: Battle-tested library with 1.8k stars
3. ✅ **Lowest Risk**: Proven to work correctly
4. ✅ **Future-Proof**: Maintained and updated
5. ✅ **Clean Code**: Simple, readable implementation
6. ⚠️ **Trade-off**: Adds 50KB dependency (acceptable)

### Next Steps
1. Create branch: `feature/kerberos-asn1-harvesters`
2. Add `gokrb5` dependency
3. Implement Phase 1 (setup)
4. Implement Phase 2 (AS-REP)
5. Implement Phase 3 (TGS-REP)
6. Test and validate
7. Submit PR

---

## References

- [RFC 4120: Kerberos V5](https://www.rfc-editor.org/rfc/rfc4120)
- [gokrb5 Documentation](https://github.com/jcmturner/gokrb5)
- [Hashcat Kerberos Modes](https://hashcat.net/wiki/doku.php?id=example_hashes)
- [ASN.1 Complete by John Larmouth](http://www.oss.com/asn1/resources/books-whitepapers-pubs/larmouth-asn1-book.pdf)
- [BruteShark Kerberos Parsers](https://github.com/odedshimon/BruteShark/tree/master/BruteShark/PcapAnalyzer/Modules/PasswordsModule/CredentialsParsers)

