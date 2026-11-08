# TLS fingerprinting

TLS handshake metadata can describe observable client/server behavior without
decrypting application data. Inspect emitted TLS hello/certificate records and
their fields rather than inferring software identity from a hash alone.

```sh
net capture -read traffic.pcap -out tls-audit -dpi=false
net dump -read tls-audit/TLSClientHello.ncap.gz -fields
net dump -read tls-audit/TLSClientHello.ncap.gz -json
```

Only query files the capture actually produced. Missing/reordered/fragmented
handshakes, stream gaps and protocol versions affect visibility.

| Capability | Boundary |
| --- | --- |
| JA3-style calculation | Fingerprint of observable handshake properties; no bundled JA3 identification corpus |
| Plain JA4 TLS client fingerprint | Included in official builds under its BSD terms |
| JA4+ | Opt-in source feature with separate terms; not official binary coverage |
| QUIC Initial ClientHello | Recognized Initial packets only; not arbitrary encrypted QUIC payloads |
| TLS plaintext | Separate `investigate tls-capture` workflow with supplied secrets and installed `tshark` |

Different programs can share a fingerprint; one program's value can change with
configuration/version. Preserve the original hello fields and provenance for
reproduction. SNI is an advertised name, not proof of account ownership or an
authenticated destination. See [protocol experiments](protocol-experiments.md)
for authorized plaintext analysis and [license boundaries](license.md).

## Certificate observation and assessment

`TLSCertificate.AssessmentBasis` is `capture-time` when a positive observation
timestamp is available; `AssessmentTime` records those exact Unix nanoseconds.
Expiry, not-yet-valid and remaining-day fields use this time, never the analysis
machine's current date (`internal/decoder/stream/tls/certificate_assessment.go`).

| Field / boundary | Meaning |
| --- | --- |
| `ValidityState` | `valid`, `expired`, `not-yet-valid`, or `unavailable`; valid means inside the observed validity period, not trusted by a public CA. |
| `SelfSignatureState` | `verified`, `invalid`, `not-self-issued`, or `unsupported`. `IsSelfSigned` is true only after a cryptographic self-signature check; equal subject/issuer names alone do not establish it. |
| `CertificateSender` | Actual handshake direction: client or server. Mutual-TLS client certificates retain client endpoints. |
| `NotBeforeRFC3339`, `NotAfterRFC3339` | Lossless certificate dates, including dates outside Unix-nanosecond range. The corresponding numeric date is zero when unrepresentable. |
| Occurrences | New records preserve fingerprint, flow, sender, chain index and timestamp occurrences. Repeated content across peers is not collapsed into one server observation. The certificate view separates sender/assessment categories and labels its representative observation time. |
| Legacy files | Missing new fields are legacy-unqualified, not checked-and-clean. Historical files are not rewritten. The WebUI shows the assessment basis explicitly. |
| Verification limit | No hostname, trust-chain or revocation verification is implied; TLS 1.3 encrypted certificate messages remain unavailable without the appropriate plaintext path. |

The certificate API exposes `assessmentTimeNs` as a decimal string; new CSV
assessment/correlation columns are appended to existing columns. Inspect the
header before importing into position-based analysis tools. Re-pin any ML
feature schema rather than treating appended categorical IDs as security scores.
