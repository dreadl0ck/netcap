# Record format

A Netcap audit file starts with a protobuf Header, followed by length-delimited protobuf messages of the record type named in the header. A `.ncap.gz` file is the same content wrapped in gzip, so decompress it before you read the framing. A `.ncap` file is not a single protobuf object.

| Layer              | Contract                                                             |
| ------------------ | -------------------------------------------------------------------- |
| Compression        | Optional gzip; report CRC and truncation errors                      |
| Framing            | Varint length, then that many bytes of encoded message               |
| First message      | Header: record type, creation/build information and payload presence |
| Following messages | Instances of the record type declared in the header                  |

The schema is [`types/netcap.proto`](https://github.com/dreadl0ck/netcap/blob/master/types/netcap.proto); use it and its generated bindings. Raw timestamps are integer Unix nanoseconds. Some exporters and display modes convert the unit, so check the interface you use before assuming milliseconds.

## Inspect a file

```sh
net dump -read analysis/UDP.ncap.gz -header
net dump -read analysis/UDP.ncap.gz -fields
net dump -read analysis/UDP.ncap.gz -json
```

Use `-header` and `-fields` to see the current schema instead of copying field lists from documentation. If your tool writes records back, keep unknown protobuf fields. When you extend the schema, never renumber or change the meaning of existing fields.

## Implement a reader

1. Detect compression from the file content, not from its name.
2. Read one varint-delimited Header, with a length limit.
3. Pick the record type using bindings from a known schema revision.
4. Read frames in a loop, with a length limit. Treat a clean EOF as the end, and a partial varint or message as an error.
5. Report gzip checksum errors and unsupported schemas instead of accepting partial data.

The Go reader is in `internal/netio` and the framing code in `internal/delimited`. Both are internal packages, so other Go modules cannot import them. [Python readers](python-integration.md) and [compression](data-compression.md) cover more integration details.

NCAP audit records, the NVD SQLite schema (version 2) and `Hosts.json` have separate formats and version numbers.
