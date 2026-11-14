# Compression

Capture output is gzip-compressed by default (`TYPE.ncap.gz`). To write plain files, turn compression off:

```sh
net capture -read traffic.pcap -out plain-audit -compress=false -dpi=false
net dump -read plain-audit/UDP.ncap -json
```

The gzip writer is buffered and parallel, so its CPU, memory and I/O cost depends on your workload.

| Topic                    | Guidance                                                                    |
| ------------------------ | --------------------------------------------------------------------------- |
| Storage                  | Measure on your own records; the savings vary                               |
| Streaming readers        | Read complete framed messages and report gzip integrity errors              |
| Truncated capture/output | A file that decompresses cleanly can still come from an incomplete analysis |
| Evidence                 | Record source and output hashes and keep the original compressed file       |

Compression is not encryption or anonymization. Payloads and credentials stay sensitive after gzip. [Record format](specification.md) describes the framing inside the stream.
