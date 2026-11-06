## Signed community database updates

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
`NC_DBS_APPROVALS_SHA256` overrides. CMS/DHCP OS catalogue enrichment remains
disabled; the retired corpora and Exploit-DB payloads are not redistributed.

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
