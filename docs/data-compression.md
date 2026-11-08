# Compression

Local protobuf capture output normally uses gzip (`TYPE.ncap.gz`). Disable it
explicitly when needed:

```sh
net capture -read traffic.pcap -out plain-audit -compress=false -dpi=false
net dump -read plain-audit/UDP.ncap -json
```

`-compress` is the current flag; historical `-comp` examples are obsolete. The
buffered/parallel gzip implementation trades CPU, buffers and I/O differently
for each workload. Local writer concurrency and distributed collector gzip are
not one universal configuration.

| Concern | Guidance |
| --- | --- |
| Storage | Measure on representative records; there is no universal percentage reduction |
| Streaming readers | Consume complete framed messages and report gzip integrity failures |
| Truncated capture/output | Decompression success alone does not prove full analysis completion |
| Evidence | Record source/output hashes and keep the original compressed file |

Compression is neither encryption nor anonymization. Payloads and credentials
remain sensitive after gzip compression. [Record format](specification.md)
explains the framing inside the stream.
