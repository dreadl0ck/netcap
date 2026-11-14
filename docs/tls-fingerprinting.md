# TLS fingerprinting

TLS handshakes show which clients and servers talk to each other, even when the traffic is encrypted. Netcap records the client hello, the server hello and the certificates, and calculates a JA4 fingerprint for every client hello.

```sh
net capture -read traffic.pcap -out tls-audit -dpi=false
net dump -read tls-audit/TLSClientHello.ncap.gz -fields
net dump -read tls-audit/TLSClientHello.ncap.gz -json
```

Handshakes that are missing, reordered or fragmented, and gaps in the stream, reduce what you see.

## Example: check client fingerprints against a known-bad list

Malware often uses its own TLS library, so its client hello looks different from your browsers. To find hosts that use a fingerprint from a threat list, export the fingerprints with the host and the server name, then search them for the entries on your list:

```sh
net dump -read tls-audit/TLSClientHello.ncap.gz -csv -select SrcIP,DstIP,SNI,Ja4 > client-hellos.csv

# bad-ja4.txt holds one fingerprint per line, taken from your threat list
grep -F -f bad-ja4.txt client-hellos.csv
```

Each hit shows the internal host (`SrcIP`), the destination (`DstIP` and `SNI`) and the fingerprint. Netcap does not ship a list that maps fingerprints to software, so you bring your own, for example the FoxIO JA4 database or fingerprints you collected from tools you know.

Different programs can share a fingerprint, and one program can change its fingerprint between versions. Treat a match as a lead and check the host.

## What Netcap records

| Data                           | Availability                                                                                      |
| ------------------------------ | ------------------------------------------------------------------------------------------------- |
| JA4 client fingerprint (`Ja4`) | Official builds                                                                                   |
| JA4+ (JA4S, JA4T and others)   | Source builds with the `ja4plus` tag, under separate terms                                        |
| QUIC Initial ClientHello       | Recognised Initial packets only                                                                   |
| TLS plaintext                  | The separate `investigate tls-capture` workflow, with your session secrets and `tshark` installed |

See [protocol experiments](protocol-experiments.md) for plaintext analysis of traffic you are authorised to inspect, and the [licence notes](license.md) for the JA4+ terms.

## Certificate observation and assessment

Every `TLSCertificate` record is assessed at capture time. When the capture has a timestamp, `AssessmentBasis` is `capture-time` and `AssessmentTime` holds that time in Unix nanoseconds. The expiry fields use this time and never today's date, so an old capture shows what was true when it was recorded.

To list certificates that had expired when the traffic was captured:

```sh
net dump -read tls-audit/TLSCertificate.ncap.gz -csv \
  -filter 'ValidityState == "expired"' \
  -select SrcIP,DstIP,SubjectCommonName,IssuerCommonName,NotAfterRFC3339
```

| Field                                 | Meaning                                                                                                                                                     |
| ------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `ValidityState`                       | `valid`, `expired`, `not-yet-valid` or `unavailable`. `valid` means the certificate was inside its validity period. It does not mean a public CA trusts it. |
| `SelfSignatureState`                  | `verified`, `invalid`, `not-self-issued` or `unsupported`.                                                                                                  |
| `IsSelfSigned`                        | True only after Netcap verified the self-signature. Equal subject and issuer names are not enough.                                                          |
| `CertificateSender`                   | Who sent the certificate: client or server. Client certificates from mutual TLS keep the client's endpoints.                                                |
| `NotBeforeRFC3339`, `NotAfterRFC3339` | The exact dates, including dates outside the Unix-nanosecond range. The numeric date is zero when it cannot be represented.                                 |
| Repeated certificates                 | Each occurrence is its own record with fingerprint, flow, sender, chain index and timestamp. The same certificate seen from different peers is not merged.  |
| Captures without assessment           | The assessment fields are empty because the certificate was not assessed. The web UI shows the assessment basis.                                            |

Netcap does not check the hostname, the trust chain or revocation. TLS 1.3 encrypts the certificate messages, so you only see them with the plaintext workflow above.

The certificate API returns `assessmentTimeNs` as a decimal string. The assessment columns come after the existing CSV columns, so check the header before you import the file into a tool that reads columns by position.
