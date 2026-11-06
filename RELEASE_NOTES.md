## Reviewed community databases

`net util -download-dbs` installs the layout-3 community database using trust
records bundled with the client; no extra configuration is required. Upgrade
existing installations with `net util -update-dbs`. Legacy v1/v2 distribution
endpoints are retired and return HTTP 410.

| Area | Change |
| --- | --- |
| Current CVE coverage | Complete 2002–2026 NVD feeds; published snapshot contains 420,062 records, including 85,687 CVE-2026 IDs |
| CVE matching | SQLite schema 2 evaluates structured CPE product/version applicability; text candidates no longer establish a vulnerability finding |
| Reference links | NVD advisory and exploit reference URLs remain available without bundling exploit payloads |
| Installation | Exact source/output verification, bounded archive extraction and staged activation preserve the previous installation on failure |
| Community contents | NVD, DB-IP City/ASN, IANA services and UA-parser regexes, with source provenance and licence notices |
| Service identification | Built-in protocol signatures replace the Nmap database reader |
| Removed enrichment | Legacy CMS and DHCP OS catalogues are disabled; HASSH catalogue enrichment is unavailable in this snapshot |

Schema-1 readers must upgrade before consuming the new database. Private
publishers can override community trust with `NC_DBS_APPROVALS` and
`NC_DBS_APPROVALS_SHA256`. The bundled registry approves this exact snapshot;
later registry changes require a compatible client update or explicit override.

## Capture and investigation improvements

| Area | Change |
| --- | --- |
| HTTP and SMB | Recover request-only and post-gap HTTP evidence, preserve request/response attribution, and reassemble SMB file evidence |
| Host identities | Correlate DHCP, NetBIOS, LDAP, Kerberos and DCE/RPC observations without assigning identities to unrelated hosts |
| TLS and QUIC | Reassemble fragmented hellos and QUIC Initials; recognize mail protocol TLS upgrades |
| Authentication evidence | Recover SMTP, IMAP, POP3, LDAP and NTLM authentication conversations |
| Offline workflows | File capture exits without starting the Web UI by default; `net triage` summarizes existing audit output |
| Linux archives | Bundle the ELF loader and runtime libraries beside `net`; keep the entire extracted directory together |

## Reliability fixes

| Area | Change |
| --- | --- |
| Processing status | Track admitted queued, in-flight and post-processing work; return idle after completion, failure or cancellation without hiding active captures |
| Read-only previews | Opening results or retaining live-capture context no longer implies an active capture |
| Incomplete transport headers | Avoid port-formatting panics while retaining connection packet counts, bytes and direction |
| Unsupported IP protocols | Retain separate connection accounting without requiring a decoded transport header |
| Behavioral baselines | Preserve valid rate windows starting at Unix time zero across baseline saves |
| Investigation evidence | Retain capture-scoped evidence across persisted investigations |
| Stream lifecycle | Preserve stream ownership during cancellation |
| WebUI startup | Report synchronous listener bind failures |
