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
