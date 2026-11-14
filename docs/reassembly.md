# TCP reassembly and incremental HTTP

An application message can span several TCP segments, share a segment with another message, or arrive out of order or retransmitted. Netcap rebuilds each direction of a TCP stream before it parses the protocol, so a packet boundary is never treated as an HTTP, DNP3 or Modbus message boundary.

```sh
net capture -read traffic.pcap -out streams -reassemble-connections=true \
  -conns -dpi=false
```

## Boundaries and missing bytes

| Condition                       | What happens                                                                                           |
| ------------------------------- | ------------------------------------------------------------------------------------------------------ |
| Missing SYN or initial payload  | The direction or message boundary can be uncertain. Check the parser's state.                          |
| Gap of known size               | A parser may have a rule for resynchronising                                                           |
| Gap of unknown size             | The parser may stop instead of guessing where the next message starts                                  |
| Retransmission                  | Overlapping bytes are dropped or reconciled according to the reassembly policy                         |
| Per-direction buffer limit      | The stream is incomplete once the limit is reached                                                     |
| Connection closes               | Stream records and alerts may only appear when the connection completes or the capture is flushed      |
| Reader payload budget exhausted | The capture aborts. Stream evidence marks bytes Netcap discarded locally separately from network gaps. |

When no decoder claims a stream, Netcap probes it using `DataFragments.ContiguousBytes()`. A signature can only match inside one unbroken run of observed bytes, so gaps never join two partial signatures. If a capture starts mid-stream, Netcap still probes the first observed run.

`-max-stream-bytes` limits the bytes reassembled per direction. The default is 100 MiB, the same as the default limit for extracted files. A page limit of zero means unlimited. See [resource budgets](workers.md). Check the installed `capture -h` and the health files for your build.

### Idle streams in live capture

Live capture runs maintenance on every worker once per second, even when no packets arrive. Change the interval with `-live-maintenance-interval` (`NC_LIVE_MAINTENANCE_INTERVAL`), or use a negative value to turn it off. A stream only expires when both directions have been idle longer than `CloseInactiveTimeOut`. Pending bytes are delivered with gap evidence, and the connection is labelled `idle-expired`.

| Maintenance            | Effect                                                                                                                                |
| ---------------------- | ------------------------------------------------------------------------------------------------------------------------------------- |
| Pending-byte deadline  | Releases old out-of-order bytes with gap evidence                                                                                     |
| Closed-state retention | Removes retained closed connections                                                                                                   |
| Idle expiry            | Closes idle open connections. Zero turns it off. An optional deadline index avoids scanning every active stream.                      |
| Output snapshots       | `-live-flush-interval` (`NC_LIVE_FLUSH_INTERVAL`) flushes writers and current records. Zero turns it off. It does not expire streams. |

### Idle streams when reading a file

Reading a file has no wall-clock timer and does not expire idle streams by default. Set `-capture-time-idle-expiry` (`NC_CAPTURE_TIME_IDLE_EXPIRY`) to run one-second maintenance based on packet timestamps. It runs before the packet that moves the clock forward. The clock is the largest packet timestamp seen so far, and late packets never move it back. Both directions must be idle before a stream expires, and the end of the file flushes whatever is left. `CaptureTimeMaintenance.json` records the policy, `watermarkNs` (as a quoted integer) and `latePackets`. Replay speed and the number of workers do not change these decisions.

### Memory after a connection completes

When a TCP connection completes, Netcap finishes decoding, saves the conversation and extracts the banner. It then releases the raw fragments and reuses the reader slots. Lifetime byte counters and any retained closed-connection state stay available. Pages held for a direction are released when either half closes, or when a stream byte limit closes that direction. This frees memory during capture, but it does not limit still-open streams or decoder caches. Discarded bytes stay missing, so a stream cut short stays cut short.

### Retransmission conflicts

`TCPReassemblyHealth.json` reports overlap packet and byte counts. Network detection also compares retransmissions with the first 4,096 bytes of each direction. If the bytes differ, it raises `tcp.overlap-conflict` and records which arrival came first. After a FIN or RST the prefix is kept until the detection window ends or a new SYN replaces the session. A closed flow can't resume protocol detection. Retransmissions with identical bytes raise nothing.

### HTTP across a TCP close

HTTP headers can't be completed after the connection closes. If a complete header from before the close describes body bytes that arrive after it, extraction can keep the body as an artifact marked incomplete. No normal HTTP transaction is written for it. If gzip integrity fails, Netcap can keep the decoded prefix as a child file linked to the retained wire artifact by `ParentFileID`.

## Validation against public captures

Netcap is checked against public datasets and against tshark. These are the results for the current release:

| Dataset or check                   | Result                                                                                                                                                                                          |
| ---------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Malware-Traffic-Analysis.net (MTA) | 143 of 143 captures processed, no unreadable audit files, no missing baseline artifact hashes                                                                                                   |
| MTA, HTTP requests                 | tshark finds 33,931 requests and Netcap misses none. Netcap writes 34,422 HTTP records, which includes 491 that tshark did not report.                                                          |
| MTA, host and user questions       | 98 correct, 2 wrong, 8 unhandled, with no regressions against the baseline. Both wrong answers expect the nonliteral label `all 3`. This is not the full question score.                        |
| IoT-23 scenario 1-1                | Completes with default settings in a 4 GiB container in 184.7 s. All 1,686,291 packets are admitted, with 0 queue drops, 21 of 21 audits are readable and all 46 baseline file hashes are kept. |
| Large FTP transfer                 | Extracts all 27,888,036 bytes, and the stored and recorded SHA-256 match with 1 and with 4 workers                                                                                              |
| FKIE malware C2 captures           | 67 of 67 processed. tshark finds 1,224 HTTP requests and Netcap misses none, including the FormBook capture with embedded TLS keys.                                                             |
| TCP injection captures             | 14 of 14 processed, with overlap and SYN-ACK conflict alerts. Retransmission, expiry and new-session controls raise no alert.                                                                   |
| HTTP polling                       | The MTA capture from 2025-06-13 raises 2 `c2.beacon` incidents. Irregular timing, Range transfers and GET fitting do not.                                                                       |
| PCAP-ATTACK                        | 26 of 26 processed, with 6 observations: Netlogon bursts, remote service control, Kerberos user diversity and printer notification                                                              |
| CTU-13 scenario 5                  | tshark finds 219 HTTP requests and Netcap misses none, including requests started by the responder                                                                                              |
| SSH and CVE false positives        | IoT-23 3-1 raises 0 `ssh.nonstandard-port` alerts. Nitroba raises 0 of the 3 reported CVEs for Apache 1.3.37, with no duplicate host, product, version and CVE tuples.                          |

The IoT-23 1-1 capture is `CTU-IoT-Malware-Capture-1-1/2018-05-09-192.168.100.103.pcap` from `https://mcfp.felk.cvut.cz/publicDatasets/IoT-23-Dataset/IndividualScenarios/`, SHA256 `8ebcd17af4e2d20b1cf7ad564760756f457a80b791a0757a2b1a624b2724969c`. It retains 620,639 Connection and 602,818 Host records.

In a container, the `net` CLI sets Go's soft memory limit to 75% of the smallest cgroup memory limit it can see. `GOMEMLIMIT` or an existing runtime limit takes precedence. The manifest records the value as `producer.goMemoryLimitBytes`. This leaves room for garbage collection but does not limit how many connections and hosts the decoders hold, so plan memory for very large captures.

| Fixture source                                                                                                                                | Pin                                                                                                                                                                            |
| --------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| [FKIE malware C2](https://github.com/fkie-cad/malware_c2_dataset)                                                                             | Revision `324d555e57161275abf3d5f910b74f40f56ca94c`; `dataset.zip` SHA256 `ba39c32b2ccb74bf37cf43ca061b7e802e5fe499b59144fc971e6a5c82c9b912`; only `.pcapng` members extracted |
| [Fox-IT Quantum Insert](https://github.com/fox-it/quantuminsert)                                                                              | Revision `7b54983bdd3e33ce943e27f5772e010f08606481`, 7 captures under `pcaps/`                                                                                                 |
| [HoneyBadger/Netresec](https://github.com/david415/honeybadger-pcap-files)                                                                    | Revision `f74e56078bbf3244d9713df44ed47879ddca522a`, 4 root captures and 3 under `netresec/`                                                                                   |
| [PCAP-ATTACK](https://github.com/sbousseaden/PCAP-ATTACK)                                                                                     | Revision `9ef5476dd6b083f565a1b9d2e59e4a3ae8be8c95`, 26 captures                                                                                                               |
| [Suricata h2c](https://github.com/OISF/suricata-verify/tree/9a9178a7e4d45ff1d990e8f178c1e2f54b772f39/tests/http2-h2c-doh2-force-proto-change) | `input.pcap` SHA256 `92df1f0a385252357739989381269322fd1de80867f5f4d4d74da8703b711673`                                                                                         |
| [IoT-23 3-1](https://mcfp.felk.cvut.cz/publicDatasets/IoT-23-Dataset/IndividualScenarios/CTU-IoT-Malware-Capture-3-1/2018-05-21_capture.pcap) | SHA256 `c674dc0c8d584fa66e6f00c60df973c5fbacad551c850a76d75ec9952641d00b`                                                                                                      |
| [Nitroba](https://for572.com/nitrobapcap)                                                                                                     | SHA256 `f783d89ee1f6862a10e34923fb16165fdcc85811036a5a3f2a79fed8f019484a`                                                                                                      |

To run the same check on a directory of captures, use `scripts/recheck-mta.py --inputs <directory> --group <name> --binary <net> --output <new-directory>`. It records a SHA256 for every input file. `--resume` continues an interrupted run if the binary and capture checksums are unchanged. The 148 MTA PCAPs in the report resolve to 143 upstream captures, because the `2016-07-07` entry publishes 1 PCAP and 6 malicious emails, not 6 PCAPs.

## Incremental transactions

By default, HTTP/1 is decoded when the connection completes. `-incremental-http` (`NC_INCREMENTAL_HTTP`) decodes each transaction as soon as it finishes. A completed keep-alive transaction then produces an HTTP record and an application alert while its TCP connection is still open. This was tested with 40 requests on one open connection at 1 and 4 workers. The setting also applies to service-mode captures and is recorded in manifests.

| Input or condition                                                            | What happens                                                                                                                                                                                                                                                  |
| ----------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Observed SYN handshake, clear direction, HTTP/1 header within 64 KiB          | Normal decoder selection applies, including the IPP decoder. A selected HTTP/1 decoder runs incrementally. Any other selected decoder runs at completion.                                                                                                     |
| Fixed-length or chunked requests and responses, pipelining, HEAD, 1xx replies | Framing works across arbitrary segment boundaries. Each completed transaction is decoded once. Interim responses stay with the final response.                                                                                                                |
| Response that ends when the connection closes                                 | Waits until the connection completes. Without a server FIN, the record carries `response-end-not-observed`.                                                                                                                                                   |
| Gap or local discard                                                          | Netcap flushes the partial tail with its loss counts and discard reasons, then resets framing. Requests and bytes never join across the gap. A transaction that was already written is not changed by later loss, but the final health file records the loss. |
| Malformed or ambiguous framing                                                | The rest of the stream waits for the full parser at completion. Bytes after an untrusted boundary don't become clean incremental transactions.                                                                                                                |
| `CONNECT`, `Upgrade` or `101` after HTTP/1                                    | The remaining bytes are decoded at completion, including HTTP/2 and TLS upgrade inspection. Retired HTTP/1 bytes are not replayed.                                                                                                                            |
| HTTP/2 preface, missing handshake, unclear roles, other protocols             | Decoded at completion as usual. `TCPIncrementalHealth.json` lists what is supported, how many streams were completion-only, how many incremental transactions there were, and how many gap resets and deferred tails occurred.                                |

Without `-conns`, Netcap releases parsed data and reader prefixes during capture. Only the initial service banner stays in the reader. With `-conns`, records are still written incrementally, but the full raw conversation is retained up to `-max-retained-tcp-bytes`. Generic harvesters that read whole conversations don't run over released prefixes. HTTP's own extraction, identity and software detection still run for each transaction, and deferred upgrades keep their inspectors.

The HTTP/1 parser uses at most 8 MiB of working state per connection, 64 KiB per header or trailer block, 8 KiB per chunk line and 1,024 pending requests. `-max-retained-tcp-state-bytes` (`NC_MAX_RETAINED_TCP_STATE_BYTES`) adds a limit shared by all workers, 64 MiB by default while `-incremental-http` is on. `0` means unlimited and negative values are rejected. It counts parser buffers and bookkeeping, working reservations for transactions, reusable reassembly slots and fixed per-connection credits. Closed connections keep their credit until they are retired. `TCPStreamStateBudget.json` records the current and peak bytes, rejected bytes and whether the limit was reached. If the limit is hit, the capture is cancelled, the manifest status is `error` and the audit is not marked ready. `-max-stream-bytes` is a separate limit on the total bytes per stream, and `0` does not disable these parser limits.

The count leaves out writer queues, decoder and enrichment caches, native memory and allocator and GC overhead, so it does not cap process memory. A failed HTTP write cancels the capture and marks the manifest as failed.

## Shared retention budgets

| Option                                                                | What it limits                                                                                                                                                                                                                             |
| --------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `-max-retained-tcp-bytes` / `NC_MAX_RETAINED_TCP_BYTES`               | Copied TCP reader payload across all workers. Exceeding it aborts the capture.                                                                                                                                                             |
| `-max-retained-reassembly-bytes` / `NC_MAX_RETAINED_REASSEMBLY_BYTES` | TCP page payload arrays plus fixed page metadata across all workers. Memory is reserved before it is allocated, requests for several pages succeed or fail together, and there is no cache of free pages. Exceeding it aborts the capture. |
| `-max-retained-tcp-state-bytes` / `NC_MAX_RETAINED_TCP_STATE_BYTES`   | With `-incremental-http`, parser storage, working reservations and pool and connection credits. Exceeding it aborts the capture.                                                                                                           |
| `-max-buffered-pages-total`                                           | A per-worker pressure threshold that can force gap delivery. It is not a total byte cap.                                                                                                                                                   |

The reader and page limits default to `0` (unlimited). The incremental state limit defaults to 64 MiB. All of them reject negative values. `TCPReassemblyPageBudget.json` records the page limit, current and peak bytes, rejected allocation bytes and whether the limit was reached. `capture-manifest.json` records `maxRetainedReassemblyBytes` as a quoted integer. When a limit is exceeded, the manifest status is `error` and the audit is not marked ready. Stream spans keep the discarded payload bytes with the reason `tcp-reassembly-page-budget` and the status `locally-truncated`. Rejected allocation bytes include page metadata and padding, so they can be larger than the discarded payload bytes.

These limits do not cover connection metadata, packet contexts, parser copies, decoder caches, native libraries or memory waiting for garbage collection. Whether you set a limit or leave it at `0`, process memory is not capped.

## Inspect the evidence

With `-conns`, each `stream-evidence/stream-*/` directory contains `client.bin`, `server.bin` and a manifest. The manifest lists direction, offsets, times, gaps and, for UDP, packet boundaries. The display transcript is separate. If you feed these bytes to another tool, keep the gap markers instead of concatenating the streams as if they were contiguous.

Parsers handle gaps differently. Modbus stops or resynchronises at defined points, and DNP3 and HTTP recovery each have their own rules. Read the protocol's guide before you treat a `lost` or `unmatched` result or a recovered record as complete.

The HTTP API and the web interface expose `reassemblyStatus` and a string `timestampNs`. An empty `reassemblyStatus` doesn't mean the stream was complete. A record without a capture time shows no time. Plain numeric JSON timestamps are not relabelled as exact nanoseconds.

`TCPReassemblyHealth.json` records the checksum policy and rejected segments. Malformed input, encrypted payloads and unsupported protocols can all produce no application records. [Capture health](evidence.md) helps you tell missing visibility from a real negative.
