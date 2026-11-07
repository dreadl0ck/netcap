# Service identification and DPI

Netcap has several identification mechanisms. A port name, a protocol parser,
a banner product and a native DPI label answer different questions.

| Mechanism | Input | Claim |
| --- | --- | --- |
| IANA lookup | Port and transport | Registered service name; not confirmation of actual protocol |
| Stream selector | Captured framing/signatures | Eligible parser chosen by evidence specificity |
| Built-in service signatures | Bounded passive greeting bytes | SSH, HTTP/1, SMTP or FTP recognition and supported banner fields |
| Native DPI | Native flow classifier | Application/category label available in this build |
| NVD lookup | Concrete software identity/version | Applicability candidate evaluated under stored CPE conditions |

## Choose a build

```sh
net --version
net capture -read traffic.pcap -out classified -dpi=false
```

The version output reports whether DPI is compiled in. DPI-enabled release
archives include native libraries; nodpi builds do not become DPI-enabled merely
by setting a flag. `lpi`, `ndpi` and Go module choices depend on the installed
build. Inspect `capture -h` for supported selection options.

Native contexts have their own flow/context/idle budgets. A label is not a full
decode of every transaction or proof that the named program executed. A TLS or
QUIC classification does not imply decrypted HTTP/2/3 application content.

## Independent service signatures

Official builds no longer read Nmap's `nmap-service-probes`. The replacement
`netcap-service-signatures` schema 1 uses bounded protocol parsers with declared
provenance. The initial built-in catalogue covers SSH identification, HTTP/1
response status, unambiguous SMTP and FTP greetings. Bare `220` is insufficient
to distinguish the last two. Catalogue inventory/status reports degraded or
missing optional inputs instead of silently claiming Nmap coverage parity.

Custom catalogue operations validate the same format. A managed signed release
and a local user override have separate ownership; do not contaminate the signed
archive directory. Legacy probe APIs return 410.

## Limitations

Encrypted bytes, incomplete greetings, parser ambiguity and stream gaps can
prevent identification. Legacy CMS/DHCP OS catalogues are disabled. HASSH and
UA identification require their local data; classification does not authenticate
the device's advertised software. [TLS fingerprints](tls-fingerprinting.md),
[resolvers](resolvers.md) and [record support](protocol-support.md) explain the
remaining distinctions.
