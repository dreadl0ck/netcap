# Packet collection

Use a fresh output directory and keep the original capture. Netcap decodes bytes
present at its input; it cannot reconstruct packets never captured upstream.

## Offline input

```sh
net capture -read traffic.pcap -out analysis -dpi=false -geoDB=false
net capture -read traffic.pcapng -out analysis-ng -http 127.0.0.1:8080
```

The first command exits after flushing. The second explicitly keeps the browser
interface running. `-read` supports the input selection described by its help;
quote shell globs when the application, rather than the shell, should expand them.

Current bounded readers accept classic PCAP versions 2.0–2.4, both byte orders,
and microsecond/nanosecond framing, including gzip input. Historical swapped
captured/wire-length ordering is handled by version; unequal lengths retain
truncation evidence (`internal/collector/capture_legacy_test.go`). Unsupported
versions and truncated/oversized records fail explicitly rather than becoming a
successful empty capture. Reader support does not imply gzip support in every
packet-export path; [inspection and splitting](evidence.md#export-packet-evidence)
document their separate limits.

## Select the observation boundary

| Control | Stage | Consequence |
| --- | --- | --- |
| `-bpf 'udp port 53'` | Packet selection | Nonselected packets never reach decoding; may break stream/handshake context |
| `-include` / `-exclude` | Decoder selection | Controls emitted record types and downstream inputs |
| `dump -filter` | Post-capture record selection | Preserves source audit files and filters one known type |
| `capture -filter` | Legacy capture-time record filter | TCP-only compilation and fail-open error behavior in v0.15.2; not a general filtering/privacy boundary |

[Filtering](FILTERING.md) provides examples. Reducing visible traffic changes
detector coverage, connection attribution and evidence completeness.

## Output and shutdown

Local protobuf output normally produces `TYPE.ncap.gz`, with a header and framed
records. `-json` or `-csv` selects another writer; flags do not imply all formats
are emitted simultaneously. Higher-level records may be written only during
flush/finalization. Let Ctrl-C complete graceful cleanup before copying output.

| Artifact | Purpose |
| --- | --- |
| `*.ncap.gz` | Audit records by type |
| `capture-manifest.json` | Input/configuration identity, scope and admission/drop observations when enabled |
| `Hosts.json` | Capture-derived identities for `net triage` |
| `TCPReassemblyHealth.json` | Reassembly policy/rejection evidence where produced |
| `stream-evidence/` | Directional bytes/manifests when connection evidence is enabled |

Review actual artifacts before scripting their existence; enabled decoders,
traffic and options determine output. [Evidence](evidence.md) explains scope and
health. [Live capture](live-collection.md) covers privileges and interfaces.
