## v0.16.16 — restore the WebUI dashboard and capture views

| Area | Change |
| --- | --- |
| Traffic overview | **All PCAPs** again shows aggregate totals and charts on first visit. Direct capture links retain their selection. |
| Data pages | Hosts, Devices, Connections, HTTP, Services and other inventories load records for the selected capture. Visitor isolation is preserved. |
| Capture review | Audit Records keeps one capture selector. Alerts and Files drop the page-level diagnostics; detailed evidence remains available. |
| MCP alert groups | A change to an alert outside the capped preview now invalidates the group pagination token. |

Release preflight now requires `make try-webui`, which tests the browser against an embedded service build with two local captures. User-visible WebUI changes require explicit maintainer approval.

Full changes: https://github.com/dreadl0ck/netcap/compare/v0.16.15...v0.16.16

## v0.16.15 — clearer findings and isolated showcase sessions

| Area | Change |
| --- | --- |
| Service mode | Capture selection is per browser tab. Private uploads are scoped to the visitor, shared showcase results are read-only, and file previews, downloads, and charts follow the selected capture. |
| Detection | Surfaces SMB probe and backdoor responses, command-bearing HTTP requests, onion names in cleartext traffic, and UDP fan-out. Repeated credential and SMTP observations no longer flood the findings view. |
| Alert accuracy | Uses observed connection direction for port findings, recognizes TLS on 443, and correlates Tor-like certificates with their own flows. Routine inventory is separated from findings. |
| Artifacts | Improves HTML, JavaScript, Flash, and WOFF classification. Displays partial extractions and reports artifact-input loss separately from analysis failures. |
| TLS and vulnerabilities | Records JA3 and JA3S and adds fingerprint filters. Passive CVE findings require an applicable version or version range. |
| Showcase | Bounded Files and Fingerprints views, capture summaries with evidence links, and visible UDP retention limits. Service runs record the detection-rule pack digest. |

Full changes: https://github.com/dreadl0ck/netcap/compare/v0.16.14...v0.16.15

## v0.16.14 — evaluator follow-up

| Area | Change |
| --- | --- |
| try.netcap.io | Service mode uses the CLI's analysis defaults and accepts partial captures without a capture manifest. `make try-parity` replays the 20 try captures; all complete. |
| Durability | Per-file `fsync` is replaced by one filesystem barrier (`syncfs` on Linux) before the output-ready marker. On macOS, durability is relaxed: only the markers are synced. |
| `download-fast` (V1611-3) | Stored TCP completion reads the payload 3 times instead of 18, and the scratch store no longer starts a goroutine per query. macOS: 4.6 s / 185 MB → 3.4 s / 165 MB. |
| MCP-20 | A small upload behind a large capture completes in about 0.5 s (was 4.6–10.6 s); the 15,000-packet fan-out capture takes 21 s (was 129 s). |
| Threshold rules | All 37 shipped thresholds that counted every host together now count per source, source–destination pair, receiving client, victim or distinct destination. Thresholds above 256 count in time buckets; each rule has its own state budget. RADIUS counts Access-Reject records; DNS Beaconing ignores name case (`fold_case`). |
| Rule false positives | Port Scan High Port, LDAP Replication Activity and Missing Security Headers are retired. High Volume SMB Write, WMI Activity, HTTP OPTIONS Enumeration and LDAP Enumeration now need the behaviour they name. `configs/firewall-rules.yml` is removed. Saved copies of old defaults load as the new ones, also through `capture -rules DIR`; saved copies of retired rules are dropped. |
| Alerts | Resolving a group records it once (`resolved_alerts.json` version 2), so large groups no longer break every alert view. Matched records above 256 KiB are replaced by their identity and hash; older alerts above 1 MiB are skipped and counted (`skippedOversizedAlerts`). The WebUI alert list and grouped view stream instead of loading the audit, the Alerts page pages correctly, and an expanded group pages through all of its alerts. |
| Capture input | Records whose caplen exceeds origlen are decoded (`origLenRaisedPackets`); `sip.pcap` processes 4,558 of 4,558 packets instead of none. Token Ring (DLT 6) is decoded. BPF-filtered captures use the bounded reader and write `capture-input.json` with `bpfExcludedPackets`. |

The [qualification ledger](internal/collector/testdata/recheck-v0166.json)
(`recheckV01613`) records the tests and replays; `make recheck-v01613` is the
gate. Linux timing for `download-fast` and the original evaluator sessions remain
to be measured.

Full changes: https://github.com/dreadl0ck/netcap/compare/v0.16.13...v0.16.14

## v0.16.13 — evaluator follow-up

| Area | Change |
| --- | --- |
| MCP-24 timeline | Large captures no longer fail every session tool with HTTP 422. Exhausted timeline metadata is reported as `metadataTruncated` / `eventsMissingMetadata`, filtered timeline responses list `limitations`, and audit records over 16 MiB are skipped and counted. |
| MCP-23 alerts | Paged alert views stream stores of any size; only the 1,048,576-row and 1 MiB-per-alert limits return 413, and each 413 names its limit. |
| MCP-20 scheduling | Small uploads run beside a large capture by default, up to eight per large capture. Set `NETCAP_AUXILIARY_CAPTURE=0` for serial dispatch. |
| V1612-3 rules | SYN Scan Detection counts distinct destination ports, Multiple External Connections distinct non-web destinations, DNS Beaconing queries per host and name, and DNS Tunneling long query names per host. Expect fewer alerts: the MCP-22 synthetic fixture drops from 91 to 88. Saved copies of the old defaults load as the new ones. |
| Rules engine | `group_by` thresholds work without `capture_time`, in bounded state, and accept dotted paths such as `Questions.Name`. Distinct and grouped windows tolerate out-of-order records. WebUI rule saves keep `group_by`. |
| Secrets | SNMP communities no longer raise Cleartext Password Captured; non-default ones raise SNMP Community String Observed. |
| V1612-4 software | Service-signature Software comes from the preferred banner at service flush, so flow order no longer changes it. In live CLI captures, vulnerability and exploit records derived from it appear when the capture stops. |
| V1612-2 evidence | Stream evidence directories get 128-bit names; a name collision no longer aborts large captures. |
| Audit names | VRRP captures no longer fail analysis. Readers accept `VRRP.ncap.gz`, `ApplePktap.ncap.gz` and the v0.16.11 `GTPv1U.ncap.gz`; writers emit `GTP.ncap.gz`. `-y` re-runs into an existing output directory work again. |
| MCP retries | Busy responses carry `Retry-After`; MCP tool errors end in `; retry_after_ms=N`. |
| Partial captures | WebUI and MCP analyses complete again when the capture input is partial (exit 2) or only some packets use an unsupported link type (exit 3); the session reports the reason as `coverage`. v0.16.11 and v0.16.12 failed them. |
| macOS performance | Per-stream evidence uses `fsync` instead of `F_FULLFSYNC`: an 18,000-stream capture drops from 835 s to under a minute. |
| Service mode | Anonymous visitors (try.netcap.io) get 403 on `GET /api/network-interfaces` and on injection rule and event writes; those navigation entries are hidden. A one-time welcome dialog and Imprint/Privacy links are added. |

The [qualification ledger](internal/collector/testdata/recheck-v0166.json)
(`recheckV01612`) records the tests and replays. `make recheck-v01612` is the
regression gate; `make demo-pcaps` checks captures through the try-demo pipeline. The original evaluator sessions, the 200,000-stream capture and
the `download-fast` performance work (V1611-3) remain open.

Full changes: https://github.com/dreadl0ck/netcap/compare/v0.16.12...v0.16.13

## v0.16.12 — evaluator follow-up

| Area | Change |
| --- | --- |
| MCP alerts | Read large alert audits with bounded statistics and raw/grouped pagination. Stdio and Streamable HTTP tests cover the same 27,152-alert fixture. |
| GTP | Seal control-message output under the canonical GTP audit name. A T-PDU-only capture still does not create a control audit. |
| Rule replay | Order finalized offline rule inputs deterministically across capture worker counts. |
| Capture scheduling | Bound post-capture work and offer an opt-in small-upload helper via `NETCAP_AUXILIARY_CAPTURE=1`; default capture dispatch remains serial. |
| HTTP extraction | Reduce retained-fragment read costs for large transfers and preserve the distinction between a complete File audit and an incomplete extracted body. |
| Protobuf | Generic wire decoding remains opt-in. Loading schemas alone does not enable it. |

The [qualification ledger](internal/collector/testdata/recheck-v0166.json)
records the synthetic and public replays. The exact evaluator corpus and harness,
the original large-alert session, and native Windows/Npcap capture remain unverified.

Full changes: https://github.com/dreadl0ck/netcap/compare/v0.16.11...v0.16.12

## W87 evaluator rerun

`v0.16.11` is the build for the full evaluator benchmark rerun.

| Area | Change |
| --- | --- |
| Capture and extraction | Stream disk-backed HTTP artifacts and preserve independently completed output under local reassembly, decoder, or analyzer pressure. Report incomplete coverage explicitly. |
| Reassembly | Avoid disjoint overlap walks, preserve TCP rollover behavior, reduce EOF sort allocations, and validate disk-backed connection indexes and identity. |
| Analysis | Snapshot admitted rules, stabilize capture-time replay, and coordinate post-capture completion, cancellation, and live admission. |
| MCP | Validate page counts, rows, generations and continuation; bound inventory scans and concurrent work; report schema reload failures and preserve the active registry on a failed reload. |
| Detection evidence | Preserve TCP overlap bytes and severity. Qualify possible stale probes only with complete evidence; exclude truncated segment ends and FINs from keep-alive exceptions where their sequence evidence is incomplete. |
| Capture exit status | Exit `2` reports partial coverage. Automation can retain independently sealed output and inspect its coverage before use. `--local-completion-state-loss` applies to application completion working-state refusals; TCP connection-state exhaustion remains fatal. |
| Protobuf | Generic wire decoding is opt-in with explicit `Protobuf` decoder selection. Loading schemas alone does not enable decoding; use `--proto-message-types` to bind a port to a message type. |

The [qualification ledger](internal/collector/testdata/recheck-v0166.json) records
the synthetic 15,000-flow audit equivalence checks and official MCP client runs.
The original evaluator corpus and harness, the ≥64 GB tier, and native
Windows/Npcap live and offline capture remain unqualified. Keep capture options,
input hashes, platform, and artifact selection with the evaluator results.

## MCP reliability and bounded capture state

`v0.16.9` implements all 17 MCP findings from the v0.16.8 recheck and adds
decoder, capture-state and link-reconstruction fixes. Source and synthetic
qualification are recorded in
[`internal/collector/testdata/recheck-v0166.json`](internal/collector/testdata/recheck-v0166.json).

| Area | Change |
| --- | --- |
| MCP identity and isolation | Reuse the running CLI and bundled loader for capture helpers; allocate opaque upload IDs and separate fixed-root outputs; bind secret/device inventories to the requested capture |
| MCP input and lifecycle | Stream bounded uploads to private files; reject special-file sources; publish completion after rules, finalized alerts and timeline indexing; return explicit failed/not-ready errors; delete only terminal owned uploads and scoped artifacts |
| MCP data access | Add byte-bounded inventory pages, search, matched totals, generation checks, structured field/JSON Pointer projection and complete oversized JSON artifacts. Count-only queries scan all matches without transferring record bodies |
| MCP protocol and transport | Publish output schemas and bounded structured results; correct read-only hints, resource URI encoding, PCAP download framing, bearer-scheme case handling, CORS grants and beyond-EOF stream pages. Order stream evidence by capture identity |
| Protobuf / HTTP | Require multi-field protocol evidence for automatic Protobuf identification while preserving configured single-field decoding. Retain one qualified HTTP pair across malformed presentation metadata, including the supplied non-UTF8/NUL witness |
| TLS adapter | Discover the installed `tshark` follower namespace: modern `tls.stream`, or legacy `tcp.stream` after an unsupported-field diagnostic. Preserve explicit zero and reject ambiguous decryptable selections |
| Bounded state | Back TCP control/reassembly payloads, normalized Software observations, vulnerability/exploit deduplication and optional network-layer payloads with private bounded storage. Bound user-agent caches and materialization; backing/output failures prevent readiness |
| Spill performance | Reuse prepared SQL statements, batch frozen UDP walks and stable packet exports, and cache bounded classifier bytes. Latest matched 10,000-flow backed median improves from 3.215 s to 2.811 s with identical audit counts/digests |
| Link reconstruction | Add Darwin USB and bounded `LinkFrame` paths for AX.25, MS/TP, Bluetooth H4, I2C, MPEG-TS, Upper PDU, ALP and MDB. Reconstruct supported ALP/MS/TP/6LoBAC/ROHC payloads and retain source ranges and transformations |
| Upper profiles | Add BACnet NPDU/APDU metadata, MPEG-TS program/PES and H.264/H.265/AAC headers, Bluetooth ACL/L2CAP/ATT/SMP metadata, USB descriptor correlation and explicit `-link-profiles` device mappings. Exact supported variants remain listed in [`docs/protocol-support.md`](docs/protocol-support.md) |
| Windows packaging | Sign production Windows CLI executables before archive/checksum generation; snapshot builds remain unsigned |

| Qualification | Result or remaining gap |
| --- | --- |
| Local checks | Focused package race/vet checks, native DPI comparisons, supplied-capture collector integration, fresh MCP stdio and Linux bundled-loader tests pass; the release qualification asset records packaged-runtime results |
| TCP memory witness | A matched 200,000-SYN synthetic run reduced retained heap to 44,090,648 bytes and peak RSS to 280,322,048 bytes. A separate 32-MiB TCP payload fixture retained 82,128 additional heap bytes; these are synthetic measurements |
| DS-12/DS-14 / H-28 / V168-3 | Still partial: the latest 10,000-flow backed run is 2.17× memory-only time, above the proposed 2× target. Encoded-cache limits are not hard RSS limits; decoded records and optional accumulators retain separate budgets |
| Original witnesses | The original large-capture/GeekLounge corpus, 49 estimator-skipped captures and H-17's three residual frames remain unavailable. No new evaluator-wide MTA score is claimed |
| TLS and exotic profiles | Real `tshark 4.6.6` TLS 1.2/1.3 selection/decryption passes; legacy 4.4 namespace behavior has source/adapter coverage, not an installed-4.4 replay. Advanced/vendor-specific link profiles and independent real inventory still require qualification |
| Windows | Signing/cross-compilation and any packaged startup checks do not establish Windows/Npcap capture-runtime qualification |

## Retest corrections

`v0.16.8` implements the seven findings in `netcap-full-recheck-v0.16.7.md`.
The [issue ledger](internal/collector/testdata/recheck-v0166.json) distinguishes
local regression coverage from the unavailable original evaluator replay.

| Area | Change |
| --- | --- |
| V167-7 | Replace per-byte Unicode lowercasing with bounded incremental ASCII prompt matching. Restore CLI harvester port filtering; Telnet prompt evidence still permits off-port recovery |
| V167-6 | Return malformed first-section PCAPNG errors before configuring the reader; 24,125 full-opener fuzz executions passed without a crash |
| V167-3 | Accept four-byte FCS metadata encoded as `4` or `32`; unfamiliar optional FCS values no longer discard readable interfaces |
| V167-1 | `--quiet` no longer authorizes overwrite; noninteractive replacement requires `-y` |
| V167-4 / CTF-13 | Respect HTTP request-body framing, suppress duplicate banner form extraction when the parsed reader is active, add configured `pswrd`, and harvest bounded top-level JSON credentials. Repeated requests retain separate occurrences |
| V167-5 | Query logins use actual user/password values. Tokens, API keys and sessions use additive `Secret.Kind`, `Value` and `Parameter` fields, including CSV and Web UI display |
| V167-2 | Ship recursive Markdown documentation without `.gitbook` recordings or `.DS_Store`; validate actual archives against a 16 MiB documentation limit |
| Service evidence | Retain ICMP refusal observations that workers process before the quoted UDP attempt. Keep port guesses in `PortName`; `Service.Name` uses observed application/probe evidence |
| TCP and TLS | Track FIN sequence space for half-closed keepalives. Omitted TLS selection requires one decryptable stream; explicit zero remains explicit and ambiguous captures require selection. Community IDs resolve TLS follow indexes |
| Wireless and DNS | Protected management bodies remain opaque. Add readable CNAME/NS/PTR companions while preserving raw bytes |
| D2-13 | Add bounded PPI/DLT 192 decoding with nested Ethernet/raw IP, aligned metadata and wireless FCS provenance |
| Memory | Spill Connection, Host, DeviceProfile, Service and retained UDP state through a shared bounded encoded cache with private SQLite backing. Stream UDP datagrams and directional evidence spans instead of retaining their complete payload/span sets |
| MCP | Expand the local tool registry from 56 to 119 tools; analysis settings, live capture, protocol experiments, packet/artifact evidence and startup-bound operator workflows have backend/parity coverage |

| Qualification | Result or remaining gap |
| --- | --- |
| Local checks | Full portable Go suite, focused race/vet, native DPI/YARA, CLI/MCP E2E, frontend build and TLS 1.2/1.3 selection tests passed |
| Matched synthetic memory | Linux/amd64, 2 CPUs, 200,000 SYN flows: enabling a 1 MiB encoded cache reduced retained heap from 701,117,288 to 422,654,640 bytes and peak RSS from 2,274,717,696 to 1,171,546,112 bytes; runtime increased from 10.61 to 28.25 seconds. This compares this revision's memory and spill modes, not the unavailable evaluator captures |
| DS-12/DS-14 / H-28 | Still partial: TCP reassembly/factory state, optional accumulators and decoded output records remain outside the encoded-cache limit. Spilling is not a hard process-memory bound; the 49 estimator-skipped captures still need external qualification |
| D2-13 | Exotic link types including 3/165/201/209/243/252/266/289/300 remain unsupported; PPI support does not imply support for every possible encapsulated DLT |
| Original witnesses | The evaluator's MTA/CTF/Wireshark corpus, `repro/v167`, 146 crash inputs and residual trigger frames were unavailable. Local synthetic tests do not establish a new MTA score or closure of every reported residual |
| Windows | Cross-compilation only; no Windows host with Npcap was available for runtime qualification |

## Gopacket dependency

| Area | Change |
| --- | --- |
| Packet decoding | Upgrade from upstream v1.7.2 to v1.7.7, retaining the macOS dead-handle Close fix through `dreadl0ck/gopacket@61002f918d93` (upstream PR #178) |
| Copied TCP reassembly | Port sequence-wrap, retained-page accounting, cross-assembler page ownership, oldest-queued expiry, stale control-segment and queued-FIN fixes into `internal/reassembly`; retain netcap's post-close evidence observation and generation-safe pool lifecycle |

## Capture and local API corrections

`v0.16.7` addresses the 53-row v0.16.6 issue report. The
[issue ledger](internal/collector/testdata/recheck-v0166.json) records 45 implemented,
3 implemented with explicit policy, 2 partial, 1 open and 2 by-design dispositions.
These describe source changes and local regressions; the evaluator's complete
MTA/CTF/Wireshark corpus and `/workspace/hunt/repro/` were unavailable locally.

| Area | Change |
| --- | --- |
| Local HTTP and MCP | Offline/live UI is opt-in; per-run authentication, strict Host/Origin checks and same-origin CORS protect the local API. Browser bootstrap uses an HttpOnly SameSite cookie; MCP authenticates its backend requests. Service-mode authentication behavior is unchanged |
| Output and CLI | Finalize gzip CSV through EOF; stage owned outputs and restore them after failed initialization while preserving unrelated files. Preserve leaf-error exit codes, validate decoder selection and operands, parse decimal timestamps without float rounding, and explicitly reject obsolete generation flags |
| Capture formats | Read patched/Kuznetzov PCAP and normalize timestamp carry. Preserve missing timestamps in PCAPNG SPBs; `--pcapng-merge-sections` explicitly enables compatible-interface continuity. Add USB link types 189, 220 and 249; identify unsupported 5View and damaged PCAPNG inputs |
| Packet evidence | Normalize bounded GTP-U, Teredo and L2TPv2 inner traffic; retain tunnel scope. Persist fragment diagnostics and honor the defrag switch. Correct portless Community IDs, IGMPv1/v2 and capture-aware wireless FCS handling; export SSID, ordered IEs and WEP metadata |
| Protocol recovery | Preserve long/non-UTF8 HTTP headers, bounded brotli artifacts, compressed Zabbix, KRB-SAFE, FTP navigation and directional Telnet credentials. Add attributed HTTP form aliases and bounded readable TLS HTTP/2 output. Tighten off-port Modbus recognition |
| DNS, identity and detections | Retain malformed/raw DNS and exact name/TXT bytes; detect binary NULL tunnels. Correct reply-first UDP roles and ICMP-refused service claims, avoid keepalive overlap false positives, aggregate per-URI beacon incidents, and keep port guesses separate from observed protocol labels |
| Enrichment | Verify snapshot authenticity independently of freshness; retain expiry diagnostics, digest pins and capture provenance |
| Performance | Indexed service-flow membership reduces the 40k-UDP-flow regression from 3.21 s to 1.09 s on the isolated Linux runner. Lazy TCP payload readers reduce retained heap for 50k SYNs from 207,694,408 to 183,410,096 bytes |
| Packaging | Enable YARA in Linux DPI/nodpi builds, stamp version/commit through Linux build arguments, include documentation trees and validate README-linked Markdown in actual archives |

| Remaining qualification or policy | Disposition |
| --- | --- |
| DS-12/DS-14 | Open: bounded aggregate-state spilling and qualification of the 49 large captures remain outstanding |
| H-28 | Partial: lazy TCP readers reduce allocation; general per-flow state and full 200k-flow RSS qualification remain |
| D2-13 | Partial: USB 189/220/249 are supported; exotic families including 165/192/209/289/300 remain unsupported |
| H-5 | Conflicting fragment sets remain rejected; first-arrival reconstruction is not implemented |
| H-11 | PCAPNG sections remain isolated unless `--pcapng-merge-sections` is selected |
| DS-2 / NEW-2 | Preserve qualified aliases and LDAP directory matches without inventing IP ownership |
| External replay | Full evaluator replay, including the original TLS capture/key log and large-capture corpus, remains required |

## Recheck fixes

`v0.16.6` fixes the open items from the v0.16.4 full recheck that do not need a
large machine. DS-12 and DS-14 (memory on the 49 estimator-skipped captures) are not addressed.

| Area | Change |
| --- | --- |
| `policy.http-on-443` | Fires only for an answered request with a well-formed `HTTP/1.x` or `HTTP/2.0` version and no reassembly qualification. Unanswered probes, version-less request lines and records qualified by capture loss no longer alert. The h2c preface (`PRI * HTTP/2.0`) is no longer also reported as `policy.non-tls-on-443` |
| Overwrite prompt | With a non-empty output directory and no `-y`, a non-terminal stdin now fails with `pass -y to overwrite` and keeps the previous output. It no longer prints `Overwrite? [Y/n]:` and exits on EOF |
| NBNS | Node-status (type 0x21) responses are decoded. They previously failed in the DNS parser and were dropped, so captures with only NBSTAT traffic had no `NBNS.ncap.gz` |
| Link types | Adds DLT 108 (OpenBSD loopback), 50 (PPP in HDLC), 117 (PFLog) and 119 (Prism). PPP frames with the `0xff03` prefix, including DLT 9, now reach the transport decoders. DLT labels in `capture-input.json` come from the tcpdump registry; several ranges were off by one (289 and 300 printed no or wrong names) |
| Host identity | `Hosts.json` hosts gain `directoryMatches`, the LDAP computer objects whose name equals a host's observed name. No IP is bound from LDAP. A bare name and its FQDN (`web01`, `web01.corp.example`) are one name instead of `conflicting-observations`; two different FQDNs still conflict |
| `c2.beacon` | The TCP-timing and HTTP-timing detectors still emit separate rows. In offline runs each row now carries `corroborated-by:<RecordType>` when the other detector reported the same source, destination and port |
| Tests only | V-8: a rejected fragment set keeps its `fragment-rejected` Connection with no ports, by design. V-7: a malformed 802.11 information element is a decode error and leaves the input `complete`; snaplen truncation is what makes it `partial` |

Not changed: unsupported link types such as 165, 209, 249, 289 and 300 still end as `unsupported`.
The missing `10.3.14.2` fact on 2017-02-11 is probably an ICMP-quoted or ARP-target address,
which netcap deliberately does not report as a peer; the capture was not available to confirm it.

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
