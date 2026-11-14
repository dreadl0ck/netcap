# Troubleshooting

Start with `net --version`, the exact command you ran, its exit status and the output directory. Keep the source capture and the health files, and rerun into a new directory.

## First Aid

| Symptom                    | Check                                                                        |
| -------------------------- | ---------------------------------------------------------------------------- |
| Flag/command missing       | Installed version and `net COMMAND -h`; old `net` earlier in `PATH`          |
| Native library cannot load | Complete matching release archive, including `lib/`; OS/runtime/architecture |
| No interface traffic       | Driver, permissions, interface/network namespace, BPF and observation point  |
| Offline process exits      | Normal without `-http`; records are written before exit                      |
| Local WebUI inaccessible   | Bind address/port, startup errors and process lifetime                       |
| No HTTP/TLS records        | Actual input, encryption, decoder selection and reassembly health            |
| No enrichment              | Database path, signed-source status and data availability                    |
| Few contacts/records       | Sampling/truncation flags, capture drops, parser scope and finalization      |
| Rules return no alerts     | Rule enabled state, record type, expression errors and actual field values   |
| CSV columns unexpected     | `-csv`, separator and field names from `dump -fields`                        |

## Pitfalls

The exit code of an offline capture reports how much of the input was read, not whether output files exist. Check `capture-input.json` and `capture-manifest.json` too.

| Exit | Meaning                                                                                                                                                         |
| ---- | --------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `0`  | The input was read. Upper-layer decode warnings do not fail the run. Snaplen truncation or recoverable frame errors can still give a `partial` coverage report. |
| `1`  | Fatal setup or runtime error, or an input error before any readable packet.                                                                                     |
| `2`  | Framing or read error after a readable start. Records from the readable part are kept.                                                                          |
| `3`  | Unsupported capture content. Records for the supported part may still be written.                                                                               |

Malformed fragments show `Connection.Normalization: fragment-rejected` and have no transport ports. ICMP error messages quote the original packet in `QuotedSrcIP` and `QuotedDstIP`; those hosts are not additional peers on the network.

`Hosts.json` marks a host `observed-with-unattributed-aliases` when one protocol hostname has a timestamp and other names from profile or discovery traffic do not. `hostnameAliases` keeps all of them. Conflicting hostnames with timestamps are marked `conflicting-observations`. A bare name and its FQDN count as one name. A hostname comes from traffic and is not an authenticated identity. `directoryMatches` lists LDAP computer objects with the same name; it does not bind them to an IP address.

A capture into a non-empty output directory asks before overwriting. When stdin is not a terminal it stops with `pass -y to overwrite` and keeps the previous output.

`max-retained-reassembly-bytes` reserves the maximum page size for each buffer, so small payloads can use less than the limit. Packet contexts, parser state and total process memory are counted separately.

Write Booleans as `-dpi=false`. `-gen-config` appears in help but does nothing. `net export` starts a metrics exporter; to convert records to CSV or JSON use `net dump`.

## Debug Mode

Use the `-debug` option of the command you run and look at its log paths. A capture can write `errors.log`, debug logs and health files. When you report an issue, include the version and build tags, the hash of the input, the exact error and a minimal reproducer. Do not post payloads, credentials or a whole private capture.

## Advanced Debugging

`capture-manifest.json`, `TCPReassemblyHealth.json` and the other health files each describe a different part of the pipeline. A missing or null counter means the value is unavailable, not zero. Reproduce the problem on a small capture before you diagnose a large one. The [evidence guide](evidence.md) explains completeness fields.

## Race Detection Builds

For concurrency bugs in the source, run `go test -race` on the affected package with the matching build tags. [Testing](tests.md) lists the entry points. A goroutine timeout wrapper cannot cancel blocked native code, so it does not fix a hang in a native library.
