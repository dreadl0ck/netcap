# Troubleshooting

Start with `net --version`, the exact command, its exit status and the output
directory. Preserve the source capture and health artifacts before rerunning
into a fresh directory.

## First Aid

| Symptom | Check |
| --- | --- |
| Flag/command missing | Installed version and `net COMMAND -h`; old `net` earlier in `PATH` |
| Native library cannot load | Complete matching release archive, including `lib/`; OS/runtime/architecture |
| No interface traffic | Driver, permissions, interface/network namespace, BPF and observation point |
| Offline process exits | Normal without explicit `-http`; records flush before exit |
| Local WebUI inaccessible | Bind address/port, startup errors and process lifetime |
| No HTTP/TLS records | Actual input, encryption, decoder selection and reassembly health |
| No enrichment | Database path, signed-source status and data availability |
| Few contacts/records | Sampling/truncation flags, capture drops, parser scope and finalization |
| Rules return no alerts | Rule enabled state, record type, expression errors and actual field values |
| CSV columns unexpected | `-csv`, separator and field names from `dump -fields` |

## Pitfalls

Offline capture exit codes describe input coverage, not whether output files
exist. Inspect `capture-input.json` alongside `capture-manifest.json`.

| Exit | Meaning |
| --- | --- |
| `0` | Readable input consumed; upper-layer decode warnings do not fail the run. Snaplen truncation or recoverable frame errors can still leave a `partial` coverage report. |
| `1` | Fatal setup/runtime error, or input error before any readable packet. |
| `2` | Input framing/read loss after a readable prefix; that prefix is retained. |
| `3` | Unsupported capture content; supported records may still have been written. |

Malformed fragments retain `Connection.Normalization: fragment-rejected` without
inventing transport ports. ICMP error quotations use `QuotedSrcIP`/`QuotedDstIP`;
those addresses are quoted claims, not additional observed network peers.

`Hosts.json` uses `observed-with-unattributed-aliases` when one scoped protocol
hostname is accompanied by untimed profile/discovery names. `hostnameAliases`
and the complete evidence remain available; competing scoped claims still use
`conflicting-observations`. Names are observations, not authenticated identities.

`max-retained-reassembly-bytes` reserves conservative maximum-page credits
(`reassembly.PageAllocationBytes`). Small payload buffers can consume less;
packet contexts, parser state and total process RSS have separate costs.

Use explicit boolean values such as `-dpi=false`. Generic `-gen-config` is
unimplemented despite appearing in help. `net export` starts a metrics exporter;
CSV/JSON conversion uses `net dump`.

## Debug Mode

Use the relevant command's `-debug` option and inspect its actual log paths.
Capture outputs can include `errors.log`, debug logs and health sidecars. Avoid
posting payloads, credentials or an entire private capture in a public issue.
Report version/build tags, input hash, exact error and a minimal reproducer.

## Advanced Debugging

`capture-manifest.json`, `TCPReassemblyHealth.json` and subsystem health files
qualify different boundaries. Missing/null counters are unavailable, not zero.
Compare a known small synthetic capture before diagnosing a larger corpus.
The [evidence guide](evidence.md) explains completeness witnesses.

## Race Detection Builds

For source-level concurrency bugs, run a scoped `go test -race` with the matching
build tags; [testing](tests.md) lists entrypoints. A goroutine timeout wrapper
does not cancel blocked native code, so do not substitute historical timeout
helpers as a production fix for a native hang.
