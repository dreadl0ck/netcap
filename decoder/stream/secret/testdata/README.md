# Credential Harvester Test Data

This directory contains PCAP files from multiple sources for testing credential harvesting functionality:
- [BruteShark project](https://github.com/odedshimon/BruteShark) - HTTP, SMB, Kerberos
- [CredSLayer project](https://github.com/ShellCode33/CredSLayer) - FTP, IMAP, LDAP, MySQL, PostgreSQL, POP3, SMTP, SNMP, Telnet, additional HTTP and SMB variants

## Test Files Overview

### HTTP Authentication

#### HTTP - Digest Authentication.pcap
- **Protocol**: HTTP Digest Authentication
- **Purpose**: Test extraction of HTTP Digest parameters for offline cracking
- **Expected Data**: 
  - Username
  - Realm
  - Nonce
  - URI
  - QoP (Quality of Protection)
  - NC (Nonce Count)
  - CNonce (Client Nonce)
  - Response (the hash)
- **Hashcat Mode**: 11400
- **Status**: ⚠️ Partial implementation (needs enhancement)

#### HTTP - Digest-MD5.pcap
- **Protocol**: HTTP Digest-MD5
- **Purpose**: Test Digest-MD5 variant
- **Status**: ⚠️ Needs implementation

#### HTTP - NTLM.pcap
- **Protocol**: HTTP with NTLM authentication
- **Purpose**: Test NTLM over HTTP (common with IIS servers)
- **Expected Data**: NTLM challenge-response in HTTP headers
- **Status**: ❌ Not implemented

#### HTTP - NTLM GSSAPI.pcap
- **Protocol**: HTTP with NTLM wrapped in GSSAPI
- **Purpose**: Test NTLM with GSSAPI wrapper
- **Status**: ❌ Not implemented

### SMB / NTLM Authentication

#### SMB - NTLM cifs_SessionSetupAndX_NTLM_Plain.pcap
- **Protocol**: SMB with NTLM v1 authentication
- **Purpose**: Test NTLMv1 hash extraction from SMB traffic
- **Expected Data**:
  - Server Challenge (8 bytes)
  - LM Response (24 bytes)
  - NT Response (24 bytes)
  - Username, Domain, Workstation
- **Hashcat Mode**: 5500 (NTLMv1)
- **Hashcat Format**: `username::domain:LM:NT:challenge`
- **Status**: ❌ Not implemented

#### SMB - NTLMSSP (Windows 10).pcap
- **Protocol**: SMB with NTLM v2 authentication
- **Purpose**: Test NTLMv2 hash extraction from modern Windows systems
- **Expected Data**:
  - Server Challenge
  - NT Response (>24 bytes for v2)
  - NTProofStr
  - Username, Domain, Workstation
- **Hashcat Mode**: 5600 (NTLMv2)
- **Hashcat Format**: `username::domain:challenge:NT:blob`
- **Status**: ❌ Not implemented

#### SMB - NTLMSSP (smb3 aes 128 ccm).pcap
- **Protocol**: SMB3 with AES-128-CCM encryption and NTLM auth
- **Purpose**: Test NTLM extraction from encrypted SMB3 traffic
- **Status**: ❌ Not implemented

#### SMB - NTLMSSP Single Session (Windows 10).pcap
- **Protocol**: SMB with NTLM in a single complete session
- **Purpose**: Perfect test case for NTLM state machine (Challenge -> Response)
- **Status**: ❌ Not implemented

### Kerberos Authentication

#### Kerberos - v5 UDP.pcap
- **Protocol**: Kerberos v5 over UDP
- **Purpose**: Test AS-REQ, AS-REP, and TGS-REP hash extraction
- **Expected Data**:
  - AS-REQ: Pre-auth data (etype 23)
  - AS-REP: Encrypted ticket
  - TGS-REP: Service ticket
- **Port**: 88
- **Status**: ❌ Not implemented

#### Kerberos - v5 TCP.pcap
- **Protocol**: Kerberos v5 over TCP
- **Purpose**: Test Kerberos over TCP (includes 4-byte length prefix)
- **Note**: TCP format requires handling record mark prefix
- **Status**: ❌ Not implemented

#### Kerberos v5 UDP 2.pcap
- **Protocol**: Kerberos v5 over UDP
- **Purpose**: Additional Kerberos test case
- **Status**: ❌ Not implemented

#### Kerberos v5 - UDP 3.pcap
- **Protocol**: Kerberos v5 over UDP
- **Purpose**: Additional Kerberos test case
- **Status**: ❌ Not implemented

#### Kerberos-816.pcap
- **Protocol**: Kerberos v5
- **Purpose**: Specific test case (possibly TGS-REP focused)
- **Status**: ❌ Not implemented

---

## CredSLayer Test Files

The following files were imported from the CredSLayer project to expand protocol coverage:

### FTP
#### ftp.pcap
- **Protocol**: FTP (File Transfer Protocol)
- **Purpose**: Test USER/PASS command extraction
- **Expected Data**: Clear-text username and password
- **Port**: 21
- **Status**: ✅ Implemented

### HTTP Additional Tests
#### http-basic-auth.pcap
- **Protocol**: HTTP Basic Authentication
- **Purpose**: Test Base64-encoded username:password extraction
- **Expected Data**: Clear-text credentials after decoding
- **Status**: ✅ Implemented

#### http-get-auth.pcap
- **Protocol**: HTTP GET with credentials in URL parameters
- **Purpose**: Test extraction of credentials from GET parameters
- **Expected Data**: Username/password in query strings
- **Status**: ❌ Not implemented (needs POST/GET parameter parsing)

#### http-post-auth.pcap
- **Protocol**: HTTP POST with form data
- **Purpose**: Test extraction of credentials from POST body
- **Expected Data**: Form fields like `username=`, `password=`, `login=`, etc.
- **Status**: ❌ Not implemented (needs POST parameter parsing)

#### http-ntlm.pcap
- **Protocol**: HTTP with NTLM authentication
- **Purpose**: Additional NTLM over HTTP test case
- **Status**: ✅ Implemented

### IMAP
#### imap.pcap
- **Protocol**: IMAP (Internet Message Access Protocol)
- **Purpose**: Test IMAP LOGIN and AUTHENTICATE PLAIN commands
- **Expected Data**: Username and password (may be Base64 encoded)
- **Port**: 143
- **Status**: ✅ Implemented

### LDAP
#### ldap-simpleauth.pcap
- **Protocol**: LDAP Simple Authentication
- **Purpose**: Test LDAP bind requests with simple authentication
- **Expected Data**: Bind DN and password
- **Port**: 389
- **Status**: ❌ Not implemented

### MySQL
#### mysql.pcap
- **Protocol**: MySQL authentication
- **Purpose**: Test MySQL authentication hash extraction
- **Expected Data**: 
  - Username
  - Salt
  - Authentication hash (SHA1 based)
- **Port**: 3306
- **Status**: ❌ Not implemented

#### mysql2.pcap
- **Protocol**: MySQL authentication (variant)
- **Purpose**: Additional MySQL test case
- **Status**: ❌ Not implemented

### PostgreSQL
#### pgsql.pcap
- **Protocol**: PostgreSQL authentication
- **Purpose**: Test PostgreSQL MD5 authentication
- **Expected Data**:
  - Username
  - Salt
  - MD5 hash
- **Port**: 5432
- **Status**: ❌ Not implemented

#### pgsql-nopassword.pcap
- **Protocol**: PostgreSQL authentication
- **Purpose**: Test PostgreSQL trust authentication (no password)
- **Expected Data**: Username only
- **Status**: ❌ Not implemented

### POP3
#### pop3.pcap
- **Protocol**: POP3 (Post Office Protocol v3)
- **Purpose**: Test POP3 USER/PASS commands
- **Expected Data**: Clear-text username and password
- **Port**: 110
- **Status**: ❌ Not implemented

### SMTP
#### smtp.pcap
- **Protocol**: SMTP (Simple Mail Transfer Protocol)
- **Purpose**: Test SMTP AUTH PLAIN, LOGIN, CRAM-MD5
- **Expected Data**: Username and password (often Base64 encoded)
- **Port**: 25, 587, 465
- **Status**: ✅ Implemented

#### smtp-creditcards.pcap
- **Protocol**: SMTP with PII in content
- **Purpose**: Test credit card and email extraction from SMTP traffic
- **Expected Data**: Credit card numbers and email addresses
- **Status**: ❌ Not implemented (PII extraction feature)

### SNMP
#### snmp-v1.pcap
- **Protocol**: SNMP v1
- **Purpose**: Test SNMP community string extraction
- **Expected Data**: Community string (default: "public" or "private")
- **Port**: 161
- **Status**: ❌ Not implemented

#### snmp-v3.pcap
- **Protocol**: SNMP v3
- **Purpose**: Test SNMP v3 username extraction
- **Expected Data**: Username (SNMPv3 has authentication but more complex)
- **Port**: 161
- **Status**: ❌ Not implemented

### Telnet
#### telnet.pcap
- **Protocol**: Telnet
- **Purpose**: Test standard telnet login prompt extraction
- **Expected Data**: Username and password from interactive session
- **Port**: 23
- **Status**: ✅ Implemented

#### telnet-cooked.pcap
- **Protocol**: Telnet (cooked mode)
- **Purpose**: Test telnet with terminal cooked mode
- **Status**: ✅ Implemented

#### telnet-hidden.pcap
- **Protocol**: Telnet with hidden password input
- **Purpose**: Test password extraction when echo is disabled
- **Status**: ✅ Implemented

#### telnet-raw.pcap
- **Protocol**: Telnet (raw mode)
- **Purpose**: Test telnet in raw terminal mode
- **Status**: ✅ Implemented

#### telnet-raw2.pcap
- **Protocol**: Telnet (raw mode variant)
- **Purpose**: Additional raw mode test case
- **Status**: ✅ Implemented

### SMB Additional Tests
#### smb-crash.pcap
- **Protocol**: SMB with malformed packets
- **Purpose**: Test parser robustness with edge cases
- **Status**: ⚠️ Test for error handling

#### smb-ntlm.pcap
- **Protocol**: SMB with NTLM
- **Purpose**: Additional SMB NTLM test case
- **Status**: ✅ Implemented

#### smb-ntlm2.pcap
- **Protocol**: SMB with NTLMv2
- **Purpose**: Additional NTLMv2 test case
- **Status**: ✅ Implemented

#### smb-ntlm3.pcap
- **Protocol**: SMB with NTLM (variant 3)
- **Purpose**: Additional NTLM test case
- **Status**: ✅ Implemented

## Implementation Status

### ✅ Completed
- Test data copied from BruteShark and CredSLayer (39 test files total)
- Unit test structure created
- Test file verification tests passing
- FTP harvester implemented
- HTTP Basic Auth implemented
- IMAP harvester implemented
- SMTP harvester implemented
- Telnet harvester implemented
- NTLMSSP harvester implemented (NTLMv1 and NTLMv2)

### ⚠️ Partial Implementation
- HTTP Digest (basic extraction exists, needs enhancement)
- Kerberos AS-REQ (partial implementation exists)

### ❌ Not Implemented (Priority Order)

1. **LDAP Harvester** (HIGH PRIORITY)
   - Simple bind authentication
   - Test file available: `ldap-simpleauth.pcap`
   - Common in enterprise environments

2. **PostgreSQL Harvester** (HIGH PRIORITY)
   - MD5, cleartext, crypt, SASL authentication
   - Test files: `pgsql.pcap`, `pgsql-nopassword.pcap`
   - Hash extraction for offline cracking

3. **MySQL Harvester** (HIGH PRIORITY)
   - SHA1-based authentication hash
   - Test files: `mysql.pcap`, `mysql2.pcap`
   - Hash extraction with salt

4. **HTTP POST/GET Parameter Extraction** (HIGH PRIORITY)
   - Extract credentials from form submissions
   - Test files: `http-post-auth.pcap`, `http-get-auth.pcap`
   - Catches web application logins

5. **SNMP Harvester** (MEDIUM PRIORITY)
   - Community string extraction (v1, v2c)
   - Username extraction (v3)
   - Test files: `snmp-v1.pcap`, `snmp-v3.pcap`

6. **POP3 Harvester** (MEDIUM PRIORITY)
   - USER/PASS command extraction
   - Test file: `pop3.pcap`
   - Similar to existing IMAP implementation

7. **Kerberos AS-REP Harvester** (MEDIUM PRIORITY)
   - Extracts AS-REP encrypted tickets
   - Supports etypes: 17 (AES128), 18 (AES256), 23 (RC4)
   - Hashcat modes: 18200, 19600, 19700

8. **Kerberos TGS-REP Harvester** (MEDIUM PRIORITY)
   - Extracts service ticket hashes
   - Used for Kerberoasting attacks
   - Hashcat modes: 13100, 19600, 19700

9. **Enhanced HTTP Digest** (MEDIUM PRIORITY)
   - Extract all parameters for Hashcat
   - Hashcat mode: 11400

10. **PII Extraction** (LOW PRIORITY)
    - Email address extraction
    - Credit card number detection
    - Test file: `smtp-creditcards.pcap`

## Testing Guide

### Run All Validation Tests
```bash
cd decoder/stream/credentials
go test -v -run TestAllPCAPFilesExist
go test -v -run TestPCAPFileReadability
```

### Run Specific Protocol Tests (when implemented)
```bash
# NTLM tests
go test -v -run TestNTLMSSP

# Kerberos tests
go test -v -run TestKerberos

# HTTP Digest tests
go test -v -run TestHTTPDigest
```

### Run All Tests (including skipped)
```bash
go test -v
```

## References

### Projects
- [BruteShark Project](https://github.com/odedshimon/BruteShark)
- [CredSLayer Project](https://github.com/ShellCode33/CredSLayer)
- [Hashcat Hash Modes](https://hashcat.net/wiki/doku.php?id=example_hashes)

### Protocol Documentation
- [NTLM Protocol Documentation](http://davenport.sourceforge.net/ntlm.html)
- [Kerberos RFC 4120](https://www.rfc-editor.org/rfc/rfc4120)
- [HTTP Digest RFC 7616](https://www.rfc-editor.org/rfc/rfc7616)
- [LDAP RFC 4511](https://www.rfc-editor.org/rfc/rfc4511)
- [PostgreSQL Protocol](https://www.postgresql.org/docs/current/protocol.html)
- [MySQL Protocol](https://dev.mysql.com/doc/dev/mysql-server/latest/PAGE_PROTOCOL.html)
- [SNMP RFC 3411](https://www.rfc-editor.org/rfc/rfc3411)

## License

Test PCAP files are from the BruteShark and CredSLayer projects and are used for testing purposes.

