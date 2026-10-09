# Netcap v0.13.0 and netcap-ui 0.13.0

## Hunting evidence

| Feature | Interface / behavior |
| --- | --- |
| Related evidence | `/api/evidence/related`, `net investigate related`, Connections rows and alert details link DNS, connections, protocol records and alerts |
| Verifiable references | References bind to audit-file content hashes; capture interface/VLAN scope and bounded time windows reject ambiguous joins |
| Capture-time DNS context | `--dns-resolution-context` snapshots matched UDP DNS answers onto Connection observations for rules; names and timestamp overflow are checked |
| Bounded, scoped joins | Per-directory index and result limits report truncation; temporal, interface and VLAN scope checks withhold ambiguous relationships instead of guessing |
| Feature controls | Settings → Features switches evidence linking and network detections independently |
| Alert rendering | Rule alerts without tags render without crashing the Alerts page |

`@dreadl0ck/netcap-ui` 0.13.0 contains the related-evidence views and feature
controls in `cmd/capture/webui/frontend/packages/netcap-ui`, published through
GitHub Packages (`https://npm.pkg.github.com`).

Affected Go packages passed 524 tests. Release archives include macOS ARM64,
Windows AMD64 and Linux AMD64 glibc/musl builds, with DPI-enabled and reduced-feature
variants, SHA-256 checksums and third-party license sources.
