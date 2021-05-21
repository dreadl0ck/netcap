---
description: Identify client and server that are using encrypted connections
---

# TLS Fingerprinting

## TLS Audit Records

Watch a quick demo of creating and exploring the **TLSClientHello** audit records on the command-line

{% embed url="https://asciinema.org/a/KfhJRM3P4b0GsMtVCtelzWMbK" caption="" %}

## JA3

JA3 is a technique developed by Salesforce, to fingerprint the TLS client and server hellos.

The official python implementation can be found [here](https://github.com/salesforce/ja3).

More details can be found in their blog post:

{% embed url="https://engineering.salesforce.com/open-sourcing-ja3-92c9e53c3c41" caption="JA3 blog post from salesforce" %}

Support for JA3 and JA3S in netcap is implemented via:

{% embed url="https://github.com/dreadl0ck/ja3" caption="JA3\(S\) go package" %}

The _TLSClientHello_ and _TLSServerHello_ audit records, as well as the _DeviceProfiles_ provide JA3 hashes.

## JA3 Details

JA3 gathers the decimal values of the bytes for the following fields: **SSL Version, Accepted Ciphers, List of Extensions, Elliptic Curves, and Elliptic Curve Formats**.

It then concatenates those values together in order, using a “,” to delimit each field and a “-” to delimit each value in each field.

**The field order is as follows:**

```text
SSLVersion,Ciphers,Extensions,EllipticCurves,EllipticCurvePointFormats
```

**Example:**

```text
769,47–53–5–10–49161–49162–49171–49172–50–56–19–4,0–10–11,23–24–25,0
```

If there are no SSL Extensions in the Client Hello, the fields are left empty.

**Example:**

```text
769,4–5–10–9–100–98–3–6–19–18–99,,,
```

These strings are then MD5 hashed to produce an easily consumable and shareable 32 character fingerprint.

This is the JA3 SSL Client Fingerprint.

JA3 is a much more effective way to detect malicious activity over SSL than IP or domain based IOCs. Since JA3 detects the client application, it doesn’t matter if malware uses DGA \(Domain Generation Algorithms\), or different IPs for each C2 host, or even if the malware uses Twitter for C2, JA3 can detect the malware itself based on how it communicates rather than what it communicates to.

JA3 is also an excellent detection mechanism in locked-down environments where only a few specific applications are allowed to be installed. In these types of environments one could build a whitelist of expected applications and then alert on any other JA3 hits.

For more details on what you can see and do with JA3 and JA3S, please see this Shmoocon 2018 talk: [https://youtu.be/oprPu7UIEuk?t=6m44s](https://youtu.be/oprPu7UIEuk?t=6m44s)

### Client Hello Audit Record

```erlang
message TLSClientHello {
    string Timestamp                  = 1;
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
    string Ja3                        = 21;
    string SrcIP                      = 22;
    string DstIP                      = 23;
    string SrcMAC                     = 24;
    string DstMAC                     = 25;
    int32 SrcPort                     = 26;
    int32 DstPort                     = 27;
    repeated int32 Extensions         = 28;
}
```

## JA3S Details

JA3S is JA3 for the Server side of the SSL/TLS communication and fingerprints how servers respond to particular clients.

JA3S uses the following field order:

```text
SSLVersion,Cipher,SSLExtension
```

With JA3S it is possible to fingerprint the entire cryptographic negotiation between client and it's server by combining JA3 + JA3S. That is because servers will respond to different clients differently but will always respond to the same client the same.

For the Trickbot example:

```text
JA3 = 6734f37431670b3ab4292b8f60f29984 ( Fingerprint of Trickbot )
JA3S = 623de93db17d313345d7ea481e7443cf ( Fingerprint of Command and Control Server Response )
```

For the Emotet example:

```text
JA3 = 4d7a28d6f2263ed61de88ca66eb011e3 ( Fingerprint of Emotet )
JA3S = 80b3a14bccc8598a1f3bbe83e71f735f ( Fingerprint of Command and Control Server Response )
```

In these malware examples, the command and control server always responds to the malware client in exactly the same way, it does not deviate. So even though the traffic is encrypted and one may not know the command and control server's IPs or domains as they are constantly changing, we can still identify, with reasonable confidence, the malicious communication by fingerprinting the TLS negotiation between client and server. Again, please be aware that these are examples, not indicative of all versions ever, and are intended to illustrate what is possible.

### Server Hello Audit Record

```erlang
message TLSServerHello {
    string Timestamp                   = 1;
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
    string Ja3s                        = 29;
}
```

