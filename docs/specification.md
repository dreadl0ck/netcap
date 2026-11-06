# Record format

Netcap audit files contain a protobuf Header followed by length-delimited
protobuf messages of the header's record type. An optional gzip stream wraps
that content. A `.ncap` file is not one giant protobuf object, and a `.ncap.gz`
file must be decompressed before reading its message framing.

| Layer | Contract |
| --- | --- |
| Compression | Optional gzip; preserve CRC/truncation errors |
| Framing | Varint length, then that many encoded message bytes |
| First message | Header identifies record type, creation/build information and payload presence |
| Following messages | Instances of the declared record schema |

Use the release's
[`types/netcap.proto`](https://github.com/dreadl0ck/netcap/blob/v0.15.2/types/netcap.proto)
and generated bindings. Raw capture timestamps are integer Unix nanoseconds;
some exporter-oriented methods/display modes deliberately convert units. Verify
the particular interface instead of assuming every numeric time is milliseconds.

## Inspect a file

```sh
net dump -read analysis/UDP.ncap.gz -header
net dump -read analysis/UDP.ncap.gz -fields
net dump -read analysis/UDP.ncap.gz -json
```

Header/field discovery is preferable to stale schema excerpts. Preserve unknown
protobuf fields where an integration supports round-tripping. Field additions
do not authorize renumbering or reinterpreting historical fields.

## Implement a reader

1. Detect compression from the actual input, not an assumption about its name.
2. Read one bounded varint-delimited Header.
3. Resolve the record type using bindings from a known schema revision.
4. Iterate bounded frames; distinguish clean EOF from a partial varint/message.
5. Surface gzip checksum errors and unsupported schemas instead of silently
   accepting partial evidence.

The Go reader is in `internal/netio`; framing code is in `internal/delimited`.
These internal packages are implementation references, not unrestricted import
paths for external Go modules. [Python readers](python-integration.md) and
[compression](data-compression.md) cover integration details.

NCAP audit records, NVD's SQLite schema 2 and `Hosts.json` are separate contracts.
Do not infer their version numbers or encoding from one another.
