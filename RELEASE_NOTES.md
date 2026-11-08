## Capture analysis and application firewall

`v0.16.0` includes the qualified changes since v0.15.4. The `net` archives
include `net firewall`; standalone firewall binaries and deployment examples
are distributed separately with this release.

| Area | Change |
| --- | --- |
| Analyst workflows | Source-bound catalogue, occurrence navigation, host identities, software applicability evidence, endpoint/log review, reproduction downloads and explicit chart/artifact completeness status in CLI, WebUI and MCP |
| Capture inspection | Bounded PCAP/PCAPNG inspection and `net split` packet/time subsets and time shards; time-only exports work without a native BPF runtime |
| Rules and delivery | Capture-time scoped ordered rules, credential occurrence context, readiness/finalization checks and a durable alert outbox with CLI delivery controls |
| Streaming | Bounded incremental HTTP/1 transactions, capture-time expiry, shared TCP page limits and live application-detection checkpoints |
| Protocol recovery | Correct BGP directions, bounded Syslog framing, CIP context, RADIUS reachability, SMB compounds, legacy PCAP versions and retained round-2 transport/fragment/VoIP qualifications |
| Application firewall | Routed HTTP/HTTPS and API inspection, scoped identities/approvals, Coraza/HTTP3 build profile, SMB/FTP gateways, typed response actions, transactional control/recovery, embedded policy console and Helm deployment examples |
| Firewall qualification | Owned multi-protocol soak, image/chart contracts and digest-bound candidate/review tooling; inclusion does not assert an independently approved production appliance or promote OCI images |
| Dependencies | Matched YARA-X Go/C API 1.22.0, Alpine 3.24.4 and digest-pinned Linux builders; qualified dependency updates and refreshed Go/Rust/native notices |
| Gopacket | Upstream v1.7.2 replaced by `dreadl0ck/gopacket` at `f2eeabc1ff6e`; live-only close wakeups, bounded readers and portable descriptor lifecycle checks; fork attribution is in `legal/THIRD_PARTY_NOTICES.txt` |
| Performance | Shared single-pass entropy calculation; ARM64 entropy and SIMD text-classification experiments remain bounded by their measured replay coverage |
| Enrichment | Signed optional catalogues remain opt-in; NetAPI popularity filtering defaults on with PSL-aware matching, while no popularity corpus is bundled |

## Runtime and source delivery

| Artifact | Scope |
| --- | --- |
| Linux amd64 glibc/musl, DPI and no-DPI | Bundled native library closure, inventory, supplier notices and exact source links; matched YARA-X 1.22.0 |
| macOS arm64 DPI | Minimum OS 26.0; Developer ID signed and notarized; execution qualified on the current macOS 26.6 host |
| macOS arm64 no-DPI | Minimum Mach-O target 15.0; Developer ID signed and notarized; execution qualified on the current macOS 26.6 host, not on a clean macOS 15 machine |
| Windows amd64 no-DPI | Driver-free offline client build; native Npcap interface/live-capture qualification remains unavailable; YARA-X is excluded |
| Source and provenance | Netcap tag source, third-party source archive, macOS supplier source/recipe archive, checksums and qualification receipts accompany the binaries |

Keep `lib/` beside the macOS executable and the full Linux launcher/runtime
directory intact. CLI notarization uses Apple's online ticket lookup; raw
Mach-O/ZIP files do not support stapling. JA4+ remains source-only and opt-in.

Install signed data with `net util -download-dbs`, refresh it with
`net util -update-dbs`, and request optional enrichment with
`net util --download-enrichment`.

Full changes: https://github.com/dreadl0ck/netcap/compare/v0.15.4...v0.16.0

## Earlier module consumption and catalogue integration fixes

`v0.15.4` repairs module consumption and optional enrichment integration from
v0.15.3. Install the reviewed optional channel with `net util --download-enrichment`.

| Area | Fix |
| --- | --- |
| Go modules | Eight case-colliding GitBook asset pairs retain both original blobs under distinct filenames; module-zip checks guard release and documentation CI |
| DHCP | CLI and service collector configurations enable option-55 lookups through admitted catalogues; stale legacy JSON remains inactive |
| Service catalogue API | `/api/service-signatures` and capture initialization use the same verified optional installation |
| Database summary | Device catalogue availability is read from the installation without mutating capture globals; `scope: installation` distinguishes availability from a capture's loaded state |

## Optional signed enrichment

`v0.15.3` adds an independent, opt-in signed enrichment channel. Core database
download/update commands and their defaults remain compatible with v0.15.2.

```sh
net util --download-enrichment
```

| Area | Contract |
| --- | --- |
| Installation | `NC_ENRICHMENT_ROOT`, default `$NC_CONFIG_ROOT/enrichment`; separate signed scope, bounded member verification and monotonic sequence checks |
| Service signatures | Four independently authored SSH/HTTP/SMTP/FTP rules; verified installed catalogue is ready, absent/invalid data uses the four builtins with degraded status; no Nmap corpus or coverage-parity claim |
| Passive web technology | Bounded origin-transaction advertisements; WordPress/Drupal builtins and reviewed optional Hugo/Joomla descriptors; no active probes or inferred exact versions from major-only headers |
| Device catalogues | Optional historical FingerBank option-55 candidates under ODbL/DbCL, and IEEE vendor prefixes with the recorded secondary nonassertion acceptance; absent data retains the bounded MAC fallback |
| CISA KEV | Attributed CVE enrichment and source links; federal deadlines are identified as federal deadlines and Unknown ransomware labels are not negative assertions |
| Attribution and source offer | `/api/enrichment/attribution`, device database summaries, full packaged notices and digest-addressed public `/enrichment/signed/v1/` archive/member downloads; complete rebuild inputs in the release source archives |
| Popularity filtering | Explicit external CSV only, off by default; PSL-aware filtered Maltego transforms; no popularity dataset bundled, mirrored or approved |
| Publisher recovery | Authenticate and recount the previous signed SQLite before refresh; missing caches cannot reset the count-drop baseline |

The historical resolver ZIP is removed from current source delivery. Historical
Git revisions remain available; removal does not establish retrospective rights
clearance. Device counts and synthetic fixtures do not establish classification
accuracy or parity with retired corpora.

## Signed core updates and portable runtimes

`v0.15.0` and `v0.15.1` were runtime-qualification candidates; `v0.15.2` is the
binary release with the completed macOS closure and Alpine supplier notices.

`net util -download-dbs` installs the signed community release without extra
configuration. `net util -update-dbs` refreshes an existing installation. The
publisher can now refresh reviewed sources without shipping a new client for
each exact snapshot. v0.14.0 retains its frozen compatibility archive; legacy
v1/v2 endpoints remain retired with HTTP 410.

| Area | Change |
| --- | --- |
| Authentication | Embedded Ed25519 root verifies the root-authorized publisher key and signed opaque release payload |
| Freshness and rollback | Expiring updates, future timestamps, lower key epochs/sequences and same-sequence equivocation are rejected; verified installed data remains usable offline |
| Publication policy | Reviewed source origins, transformations, static revision pins, full notices and required filenames; complete nonempty annual NVD feeds, per-year counts and count-drop gates |
| Community contents | NVD schema 2, DB-IP City/ASN, IANA services, UA-parser and restored HASSH from a pinned BSD-licensed source |
| Installation | Cross-process update lock, bounded verification, Windows activation without symlink privileges and preservation of previous data on failure |
| Operations | Dedicated non-root publisher image, separate host signer, daily refresh timer and readiness/freshness monitoring |

Private publishers retain explicit `NC_DBS_APPROVALS` and
`NC_DBS_APPROVALS_SHA256` overrides. Retired CMS/DHCP corpora and Exploit-DB
payloads remain excluded from core delivery; optional catalogues use the separate
channel above.

## Packaging and dependency fixes

| Area | Change |
| --- | --- |
| Dependencies | Upgrade klauspost/compress, Vite, Vitest/mocker, shell-quote and source-map-js to patched versions |
| Linux WebUI | Pass the actual built WebUI as an explicit Docker build context instead of embedding only its placeholder |
| Runtime provenance | Record every bundled loader/library hash, supplying package/image and corresponding-source link; retain package copyright and licence notices |
| macOS runtime | Bundle and relocate native libraries instead of depending on old Homebrew paths; include exact supplier sources and build recipes. DPI requires macOS 26+, nodpi macOS 15+ |
| Source bundle | Include the qualified libtrace 4.0.23, wandio 4.2.6 and libwandder 2.0.8 sources; correct the prior runtime-version notices |
| Geolocation | Missing optional GeoLite2 fallback data logs at debug level; explicitly selected or corrupt providers retain actionable errors |
| Windows | On-demand qualification runs the actual client, signed download/update and structured CVE lookup on a Windows runner |
