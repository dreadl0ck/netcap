# Credential Harvesters

## Implemented Harvesters

### ✅ Basic Auth
- **FTP** - plaintext credentials (port 21)
- **Telnet** - plaintext credentials (port 23)
- **SMTP** - Auth Plain, Auth Login, CRAM-MD5 (ports 25, 465, 587)
- **IMAP** - Login, Authenticate Plain, CRAM-MD5 (port 143)
- **POP3** - USER/PASS, Auth Plain, Auth Login (ports 110, 995)

### ✅ HTTP Authentication
- **HTTP Basic Auth** - base64 decoded credentials
- **HTTP Digest** (Enhanced) - Full parameter extraction for Hashcat mode 11400
  - Extracts: username, realm, nonce, uri, qop, nc, cnonce, response, method
  - Format: `username:realm:nonce:uri:nc:cnonce:qop:response`
- **HTTP NTLM** - base64-encoded NTLMSSP in HTTP Authorization headers
  - Scans entire session for Challenge and Response
  - Integrates with NTLMSSP harvester

### ✅ NTLMSSP
- **File**: `ntlmssp.go`
- **Protocols**: SMB, HTTP, IMAP, SMTP, LDAP
- **Supports**: NTLMv1 and NTLMv2
- **Hashcat Modes**: 
  - 5500 (NTLMv1): `username::domain:LM:NT:challenge`
  - 5600 (NTLMv2): `username::domain:challenge:NT:blob`
- **Features**:
  - Session-based state machine (Challenge → Response)
  - Extracts: username, domain, workstation, challenge, LM hash, NT hash
  - Auto-detects NTLMv1 vs NTLMv2
  - UTF-16LE decoding for strings

### ✅ Kerberos AS-REQ
- **File**: `kerberos_asreq.go`
- **Protocol**: Kerberos v5 (port 88)
- **Supports**: etype 23 (RC4-HMAC-MD5)
- **Hashcat Mode**: 7500
- **Format**: `$krb5pa$23$user$realm$$hash`
- **Features**:
  - Extracts pre-authentication hashes
  - Hash byte order switching (as per Kerberos spec)
  - Works with UDP and TCP (with 4-byte length prefix)

### ✅ Database Credentials
- **PostgreSQL** (port 5432)
  - Plaintext authentication (user/password)
  - MD5 challenge-response (Hashcat mode 11100)
  - Database name extraction
- **MySQL** (port 3306)
  - Native Password challenge-response (Hashcat mode 11200)
  - Server greeting and client auth parsing
  - Database name extraction
- **MongoDB** (port 27017)
  - SCRAM-SHA-1 and SCRAM-SHA-256
  - SASL message parsing
  - Salt, iterations, and proof extraction
- **Redis** (port 6379)
  - Simple AUTH command
  - RESP protocol format
  - Redis 6+ ACL authentication

### ✅ Directory Services
- **LDAP** (ports 389, 636)
  - Simple Bind authentication (plaintext)
  - ASN.1 BER/DER parsing
  - Distinguished Name (DN) extraction
  - Username extraction from CN/UID

### ✅ Network Management
- **SNMP** (ports 161, 162)
  - v1 and v2c community strings
  - ASN.1 structure parsing
  - Printable ASCII validation

### ✅ Remote Desktop
- **VNC** (ports 5900-5902)
  - DES challenge-response (Hashcat mode 20200)
  - Apple Remote Desktop (ARD) detection
  - VNC MS Logon II (NTLM integration)
  - Entropy checking for challenge/response
- **TeamViewer** (port 5938)
  - Remote desktop session detection
  - Authentication event tracking (AUTH_CHALLENGE, AUTH_RESPONSE, AUTH_RESULT)
  - Session ID and connection monitoring
  - Supports protocol versions 1.x and 2.x

### ✅ Network Discovery
- **TLS SNI** (ports 443, 8443, etc.)
  - Server Name Indication from TLS Client Hello
  - Reveals encrypted HTTPS destinations
  - Useful for threat hunting and network forensics
- **mDNS** (port 5353)
  - Multicast DNS hostname discovery
  - IP address to hostname mappings
  - Service discovery (SRV, TXT records)
  - Works with Bonjour/Avahi
- **NBNS** (port 137)
  - NetBIOS Name Service
  - Windows computer name discovery
  - Workstation, Domain Controller, File Server identification
  - Node status response parsing
- **UPnP** (port 1900)
  - Universal Plug and Play device discovery
  - Router, media server, IoT device identification
  - SSDP M-SEARCH and NOTIFY parsing
  - Device location and service type extraction
- **WSD** (port 3702)
  - Web Services Discovery for Windows
  - SOAP/XML-based device discovery
  - Probe and ProbeMatch detection
  - Device type and address extraction

### ⚠️ Optional (Disabled by Default)
- **Credit Card Detection**
  - Luhn algorithm validation
  - Card type identification (Visa, MasterCard, Amex, Discover, JCB, Diners)
  - Context extraction
  - **NOTE**: Can produce false positives

## TODO: Requires ASN.1 Parsing

### ⏳ Kerberos AS-REP 
- **Hashcat Modes**: 18200 (etype 23), 19600 (etype 17), 19700 (etype 18)
- **Complexity**: High - requires ASN.1 DER/BER decoder
- **Use Case**: AS-REP roasting

### ⏳ Kerberos TGS-REP
- **Hashcat Modes**: 13100 (etype 23), 19600 (etype 17), 19700 (etype 18)
- **Complexity**: High - requires ASN.1 DER/BER decoder
- **Use Case**: Kerberoasting service accounts

## Test Data

Location: `testdata/`

- 13 PCAP files from BruteShark project
- Covers: NTLM, Kerberos, HTTP Digest, HTTP NTLM
- All files verified readable

## Usage

Harvesters run automatically during TCP session analysis. They are invoked by port mapping or by trying all harvesters on unknown ports.

### Port Mapping
- 21: FTP
- 23: Telnet
- 25, 465, 587: SMTP
- 80, 8080: HTTP
- 88: Kerberos
- 110, 995: POP3
- 137: NBNS
- 143: IMAP
- 161, 162: SNMP
- 389, 636: LDAP
- 443, 8443: TLS SNI
- 445: SMB/NTLMSSP
- 1900: UPnP/SSDP
- 3306: MySQL
- 3702: WSD
- 5353: mDNS
- 5432: PostgreSQL
- 5900-5909: VNC
- 5938: TeamViewer
- 6379: Redis
- 27017: MongoDB

### Output Format

Credentials are stored in `Credentials.ncap.gz` with:
- Timestamp
- Service (protocol name)
- Flow (connection identifier)
- User
- Password (plaintext or Hashcat format for hashes)
- Notes (additional metadata)

## Building

```bash
cd decoder/stream/credentials
go build
go test
```

## Testing

```bash
# Run all tests
go test -v

# Run specific test
go test -v -run TestNTLMSSP

# Check test files
go test -v -run TestAllPCAPFilesExist
```

## Implementation Notes

### NTLMSSP
- Searches for signature: `NTLMSSP\x00`
- Challenge message type: 0x02
- Auth message type: 0x03
- Fields encoded as [length:2][maxlen:2][offset:4]
- Strings are UTF-16LE encoded

### Kerberos AS-REQ
- AS-REQ message type: 0x0a
- RC4 encryption type: 0x17
- PA-DATA signatures: `0xa2 0x36 0x04 0x34` or `0xa2 0x35 0x04 0x33`
- Hash requires byte order switching (last 36 bytes, then first 16 bytes)

### HTTP Digest
- Parses Authorization header
- Splits comma-separated key=value pairs
- Strips quotes from values
- Requires: username, response (minimum)

## Future Enhancements

1. **UDP Packet Harvesting**: Direct UDP packet analysis for Kerberos (currently only works on TCP)
2. **ASN.1 Parsing**: Implement AS-REP and TGS-REP harvesters
3. **Hashcat Export**: Dedicated export command for hash files
4. **WebUI Integration**: Display hash-specific fields in credentials page
5. **Additional Protocols**: LDAP, RDP, etc.

