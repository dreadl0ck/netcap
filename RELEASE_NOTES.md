## Module consumption and catalogue integration fixes

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
