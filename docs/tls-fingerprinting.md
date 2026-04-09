---
description: Identify client and server that are using encrypted connections
---

# TLS Fingerprinting

## TLS Audit Records

Watch a quick demo of creating and exploring the **TLSClientHello** audit records on the command-line

{% embed url="https://asciinema.org/a/KfhJRM3P4b0GsMtVCtelzWMbK" caption="" %}

## JA4 Fingerprinting

JA4 is the successor to JA3, developed by FoxIO-LLC. It addresses JA3's limitations with modern browsers that randomize TLS extension order (like Chrome), and adds QUIC protocol support. Unlike JA3's MD5 hash, JA4 fingerprints are human-readable.

### JA4 Format

JA4 consists of three parts separated by underscores:

```text
{ja4_a}_{ja4_b}_{ja4_c}
```

**JA4_a** (10 characters): `{protocol}{version}{sni}{cipher_count:2d}{ext_count:2d}{alpn_first}`
- `protocol`: `t` for TCP/TLS, `q` for QUIC
- `version`: `13` (TLS 1.3), `12` (TLS 1.2), `11` (TLS 1.1), `10` (TLS 1.0), `s3` (SSL 3.0)
- `sni`: `d` (domain present) or `i` (IP/missing)
- `cipher_count`: Number of cipher suites (excluding GREASE), 2 digits
- `ext_count`: Number of extensions (excluding GREASE), 2 digits
- `alpn_first`: First two characters of first ALPN, or `00` if none

**JA4_b** (12 characters): Truncated SHA256 of sorted cipher suites (GREASE filtered, comma-separated hex)

**JA4_c** (12 characters): Truncated SHA256 of sorted extensions (GREASE + SNI + ALPN filtered, comma-separated hex), followed by signature algorithms (if present) separated by underscore

**Example:**

```text
t13d1516h2_8daaf6152771_e5627efa2ab1
```

This fingerprint indicates:
- `t`: TCP/TLS connection
- `13`: TLS 1.3
- `d`: Domain present in SNI
- `15`: 15 cipher suites
- `16`: 16 extensions
- `h2`: HTTP/2 (first ALPN)

### JA4S Format (Server Hello)

JA4S fingerprints the server's response:

```text
{ja4s_a}_{ja4s_b}_{ja4s_c}
```

**JA4S_a** (7 characters): `{protocol}{version}{ext_count:2d}{alpn}`
- `protocol`: `t` for TCP/TLS, `q` for QUIC
- `version`: `13` (TLS 1.3), `12` (TLS 1.2), etc.
- `ext_count`: Number of extensions (excluding GREASE), 2 digits
- `alpn`: First and last character of selected ALPN, or `00` if none

**JA4S_b** (4 characters): Cipher suite in hex

**JA4S_c** (12 characters): Truncated SHA256 of extensions (SNI and ALPN filtered, NOT sorted per spec)

### Advantages over JA3

1. **Resistant to TLS extension randomization**: JA4 sorts extensions, so Chrome's randomization doesn't affect the fingerprint
2. **Human-readable**: The JA4_a component is immediately interpretable
3. **QUIC support**: Works with QUIC protocol connections
4. **Includes ALPN**: Captures application protocol negotiation details

### References

- [JA4+ GitHub Repository](https://github.com/FoxIO-LLC/ja4)
- [JA4+ Technical Specification](https://blog.foxio.io/ja4%2B-network-fingerprinting)

### License

JA4 (TLS Client Fingerprinting) is licensed under BSD 3-Clause.
JA4S, JA4H, JA4X, JA4T, JA4SSH and other JA4+ methods are licensed under FoxIO License 1.1.
See `internal/ja4/LICENSE-JA4` for full license text.

---

### Client Hello Audit Record

```protobuf
message TLSClientHello {
    int64 Timestamp                   = 1;
    int32  Type                       = 2;
    int32  Version                    = 3;
    int32  MessageLen                 = 4;
    int32  HandshakeType              = 5;
    uint32 HandshakeLen               = 6;
    int32  HandshakeVersion           = 7;
    bytes  Random                     = 8;
    uint32 SessionIDLen               = 9;
    bytes  SessionID                  = 10;
    int32  CipherSuiteLen             = 11;
    int32  ExtensionLen               = 12;
    string SNI                        = 13;
    bool   OSCP                       = 14;
    repeated int32 CipherSuites       = 15;
    repeated int32 CompressMethods    = 16;
    repeated int32 SignatureAlgs      = 17;
    repeated int32 SupportedGroups    = 18;
    repeated int32 SupportedPoints    = 19;
    repeated string ALPNs             = 20;
    string SrcIP                      = 22;
    string DstIP                      = 23;
    string SrcMAC                     = 24;
    string DstMAC                     = 25;
    int32 SrcPort                     = 26;
    int32 DstPort                     = 27;
    repeated int32 Extensions         = 28;
    // Threat intelligence fields
    bool IsKnownMalware               = 30;
    string ThreatCategory             = 31;
    bool HasGreaseExtensions          = 32;
    bool IsSuspiciousCipherOrder      = 34;
    int32 ExtensionCount              = 35;
    // JA4 fingerprint
    string Ja4                        = 36;
}
```

### Server Hello Audit Record

```protobuf
message TLSServerHello {
    int64 Timestamp                    = 1;
    int32  Version                     = 2;
    bytes  Random                      = 3;
    bytes  SessionID                   = 4;
    int32  CipherSuite                 = 5;
    int32  CompressionMethod           = 6;
    bool NextProtoNeg                  = 7;
    repeated string NextProtos         = 8;
    bool OCSPStapling                  = 9;
    bool TicketSupported               = 10;
    bool SecureRenegotiationSupported  = 11;
    bytes SecureRenegotiation          = 12;
    string AlpnProtocol                = 13;
    bool Ems                           = 14;
    repeated bytes Scts                = 15;
    int32 SupportedVersion             = 16;
    bool SelectedIdentityPresent       = 18;
    int32 SelectedIdentity             = 19;
    bytes Cookie                       = 20;
    int32 SelectedGroup                = 21;
    repeated int32 Extensions          = 22;
    string SrcIP                       = 23;
    string DstIP                       = 24;
    string SrcMAC                      = 25;
    string DstMAC                      = 26;
    int32 SrcPort                      = 27;
    int32 DstPort                      = 28;
    // JA4S fingerprint
    string Ja4s                        = 30;
}
```

---

## Migration from JA3

JA3 support has been removed from netcap in favor of JA4. If you have existing JA3-based workflows:

1. **Threat Intelligence**: JA4 fingerprint databases are being developed. In the meantime, you can use the human-readable JA4_a component for basic client identification.

2. **Filtering/Detection Rules**: Update rules to match on `Ja4` field instead of the former `Ja3` field.

3. **Historical Data**: Existing audit records with JA3 fields will remain readable, but new captures will only contain JA4 fingerprints.

### Why JA3 Was Removed

Modern browsers (Chrome, Firefox, Edge) randomize TLS extension order to prevent fingerprinting-based tracking. This makes JA3 fingerprints inconsistent and unreliable for the same browser version. JA4's sorted extension approach provides stable fingerprints regardless of extension ordering.
