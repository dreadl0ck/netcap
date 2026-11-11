## Analyst web UI

`v0.16.5` ships the shared web UI `@dreadl0ck/netcap-ui` 0.13.3 on the v0.16.4
analysis engine. Capture, decoder and audit-record behavior is unchanged.

| Area | Change |
| --- | --- |
| Charts | Categorical charts show the 20 most frequent values, with ties broken by name. `/api/chart/data` answers `204 No Content` when no plottable values exist in scope and `200` with an empty series for `format=json`; read and configuration failures stay `500` |
| Dashboards | Charts without data in the selected scope are hidden and the grid closes the gap. The grid follows its container width, keeps rows aligned and stacks below 768 px; pie legends scroll and axis labels truncate |
| Connections and services | Behavioral context is collapsed by default and lists observations as a table. Directional byte bars and an aligned packet table replace stacked statistics; service details show endpoint, traffic split, identity and an expandable banner |
| Offline rules | Pack, validation and evaluation are three steps with status. Limits are shown in readable units; results summarise alerts, records, matched rules and elapsed time |
| Copy | Removes repeated disclaimers, the HTTP reassembly completeness note and raw nanosecond timestamps; actionable statuses remain |

## Capture evidence and resource fixes

`v0.16.4` includes the capture-evidence and resource fixes following v0.16.3.

| Area | Change |
| --- | --- |
| Raw IP | Accept historical on-disk link value 12 as well as LINKTYPE_RAW 101; retain original capture link values during filtered evidence export |
| HTTP and identity | Export bounded multipart fields (1 MiB total, 1,024 parts, no temporary files); retain LDAP computer names as directory subjects without inventing an IP binding; distinguish a unique scoped hostname claim from untimed aliases |
| ICMP | Export quoted IPv4 source/destination/protocol in separate fields, including JSON/protobuf/CSV; quotations do not create observed peers |
| 443 policy | Avoid duplicate generic observations for recognizable HTTP requests and exclude client-source-port-only matches |
| Memory | Size out-of-order payload buffers to captured bytes instead of reserving 1,900 bytes for every small segment; release burst allocations and retain at most 1,024 free pages per unbudgeted assembler; avoid oversized empty/small HTTP body allocations and repeated request-body copies |
| Scan performance | Index large host port sets and classify retained TCP prefixes only when their bytes grow, preserving detector match counts |

The 148-capture MTA replay retains all baseline carved-file hashes and has no
missing tshark HTTP requests. Both Raw-IP injection witnesses decode; the FKIE
DSB witness retains all 10 tshark-visible TLS HTTP requests. CTU-13 scenario 3
completes 495,056 packets with no SSH role-swap alerts; the ACM forwarder produces
two DNS tunnel incidents with destination port 53.

With `GOMEMLIMIT=4GiB`, the full 1.7 GB ACM capture completes 4,156,081 packets
at 5.48 GB peak RSS on macOS, replacing the earlier 11 GB OOM on a smaller slice.
GeekLounge 151022 retains all 2,274,747 packets at 5.75 GB peak RSS under the same
soft limit. With `GOMEMLIMIT=8GiB`, its peak is 8.88 GB; a soft GC target is not
a hard process-memory guarantee. The matched four-vCPU Linux 2018-12-18 benchmark
improves from a v0.15.2 median of 4.34 s to 3.56 s, retaining every baseline artifact
hash.

The historical 5,510-unit inventory includes 415 failed HTML downloads under
`sc-html-failed`; these are not packet captures. Unsupported formats, damaged
inputs and unavailable archive sources retain separate dispositions.
The qualification receipt is `internal/collector/testdata/recheck-v0163.json`.

## Recheck reliability and portable runtimes

`v0.16.3` includes the full recheck-fix branch following v0.16.2.

| Area | Change |
| --- | --- |
| TCP and output finalization | Fix queued-overlap page ownership, preserve readable audits on cleanup errors, remove drain-only reader goroutines, and close independent writers concurrently |
| Linux archives and memory | Relocate absolute ELF dependencies, resolve launcher symlinks, avoid unused host/connection maps, and apply cgroup-aware Go GC headroom while respecting explicit `GOMEMLIMIT` |
| Protocol recovery | Restore HTTP/SMTP artifacts, support larger FTP transfers, preserve responder-originated HTTP/TLS and post-close commands, and recover additional SMB-carried DCE/RPC |
| Identity and links | Add NBNS and IEEE 802.15.4 audit records, retain scoped hostname assertions, reject domain/PTR hostname pollution, and handle SLL2 RARP |
| TLS secrets | Decode supported authenticated TLS 1.2/1.3 HTTP from embedded pcapng NSS key logs; mark decrypted records explicitly |
| Detection | Retain conflicting-overlap evidence after FIN/RST, aggregate beacon incidents, detect skipped POST polling, cover additional service-control/Netlogon operations, and reduce Redis/SMTP, SSH-role and Apache CVE false positives |
| Input and replay | Identify captures by content, distinguish partial/unsupported exits, report effective gopacket replacements, and add checksum-pinned resumable corpus replay |

Pre-release checks completed 143/143 MTA captures with no missing tshark HTTP
requests or baseline artifact hashes, 67/67 FKIE captures, 26/26 PCAP-ATTACK
captures and 14/14 injection captures. The default IoT-23 1-1 replay completes
under a 4 GiB Linux container limit. The full 4,695-file Phase B inventory and
original fact-score corpus remain unverified; aggregate MTA capture time remains
18.2% above v0.15.2. Follow-up testing is planned.

Full changes: https://github.com/dreadl0ck/netcap/compare/v0.16.2...v0.16.3

## Stream cleanup and failed-capture diagnostics

`v0.16.2` fixes two regressions found during the v0.16 try/desktop rollout.

| Area | Fix |
| --- | --- |
| TCP reassembly | Closing a direction at its stream byte limit now releases queued `KeepFrom` pages after scatter/gather cleanup; the Brazil replay no longer triggers the assembler panic |
| Failed captures | Admitted source identity and bounded failure metadata remain exportable when processing fails before a capture manifest exists; stale manifests and replaced source aliases are rejected |
| Desktop downloads | Desktop hosts can save reproduction metadata through native dialogs and their local-output mapping instead of fetching a missing capture route |
| Native attribution | Global Ubuntu notices now match the qualified libtrace 4.0.34-1 and wandio 4.2.7-1 suppliers; per-archive inventories and source hashes remain authoritative |

Malformed captures remain partial/error with their observed packet/link/decode
counts. A downloadable diagnostic does not turn a failed capture into a complete
analysis or establish evidence the capture did not contain.

Archives include the seven CLI variants, standalone Linux amd64/arm64 firewall
profiles, exact supplier sources, checksums and qualification receipts. Both
macOS CLI variants are Developer ID signed and notarized. Hosted Windows and
macOS smoke checks do not claim Windows Npcap or full clean-macOS-15 BPF/YARA
certification.

Full changes: https://github.com/dreadl0ck/netcap/compare/v0.16.1...v0.16.2

## Capture analysis and application firewall

`v0.16.1` includes the qualified changes since v0.15.4. The `net` archives
include `net firewall`; standalone firewall binaries and deployment examples
are distributed separately with this release.

`v0.16.0` remains a qualification prerelease. `v0.16.1` restores the tracked
frontend bootstrap required by immutable Go module consumers; module-zip tests
now reject an archive that omits it even when the ZIP itself is valid.
Linux runtime attribution also verifies the bundled YARA-X bytes, version,
source pin and build recipes against the selected builder before packaging.

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

Full changes: https://github.com/dreadl0ck/netcap/compare/v0.15.4...v0.16.1

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
