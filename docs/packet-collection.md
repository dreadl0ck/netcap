# Packet collection

Keep the original capture and write each analysis to a fresh output directory. Netcap decodes the bytes it is given and cannot recover packets that were never captured.

## Read a capture file

Analyse a PCAP you downloaded, for example an exercise from Malware-Traffic-Analysis.net or a sample from the Wireshark sample captures wiki:

```sh
net capture -read office-lan.pcap -out analysis -dpi=false -geoDB=false
```

The command exits after flushing the output. To browse the results afterwards, add `-http` and the capture keeps serving the web interface:

```sh
net capture -read office-lan.pcapng -out analysis-ng -http 127.0.0.1:8080
```

`-read` accepts classic PCAP (versions 2.0 to 2.4, both byte orders, microsecond or nanosecond timestamps), PCAPNG and gzip-compressed files. Quote shell globs if Netcap should expand them. Truncated or oversized records and unsupported versions fail with an error. If a packet's captured length is shorter than its wire length, Netcap records the truncation.

Gzip input works for reading, but not in every packet-export command. See [inspection and splitting](evidence.md#export-packet-evidence) for those limits.

## Choose what Netcap sees

| Option                  | Effect                                                                                                  |
| ----------------------- | ------------------------------------------------------------------------------------------------------- |
| `-bpf 'udp port 53'`    | Drops all other packets before decoding. Stream and handshake context can be lost.                      |
| `-include` / `-exclude` | Chooses which decoders run, and so which record types are written.                                      |
| `dump -filter`          | Filters one record file after capture. The audit files are left untouched.                              |
| `capture -filter`       | Filters TCP records only, and lets records through if the expression fails. Use `dump -filter` instead. |

See [Filtering](FILTERING.md) for examples. Hiding traffic changes what detectors can see and which connections they can attribute.

## Output and shutdown

By default Netcap writes one `TYPE.ncap.gz` file per record type, each with a header followed by framed records. Use `-json` or `-csv` to pick a different writer. Some higher-level records are only written when the capture is flushed, so stop live captures with Ctrl-C and wait for cleanup to finish before you copy the output.

| File                       | Contents                                                                |
| -------------------------- | ----------------------------------------------------------------------- |
| `*.ncap.gz`                | Audit records by type                                                   |
| `capture-manifest.json`    | Input, configuration, scope, and admission/drop counters when enabled   |
| `Hosts.json`               | Hosts identified in the capture, used by `net triage`                   |
| `TCPReassemblyHealth.json` | Reassembly policy and rejected segments                                 |
| `stream-evidence/`         | Per-direction stream bytes and manifests when connection evidence is on |

Which files you get depends on the decoders, the traffic and the options you set, so check the directory before scripting around a file. [Evidence](evidence.md) covers scope and health. [Live capture](live-collection.md) covers privileges and interfaces.
