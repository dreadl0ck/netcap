# Investigate a synthetic transfer

This lab follows DNS → HTTP → extracted file → rule alert → packet export.
Python 3 writes PCAP bytes locally; no packets are transmitted. Use the current
repository checkout for `scripts/docs-fixtures.py` and `docs/examples/`, plus
the released Go v0.15.2 `net` executable. Run all commands from that checkout's
root. The fixture script refuses an existing destination directory.

## Create the evidence

<!-- docs:run fixtures -->
```sh
python3 scripts/docs-fixtures.py
```

| Input | Expected evidence |
| --- | --- |
| `doc-fixtures/investigation.pcap` | One DNS A answer for `docs.example.test`, then one HTTP/1 transfer on TCP/8080 |
| `doc-fixtures/benign.pcap` | The same benign DNS exchange, with no HTTP transfer |
| `doc-fixtures/baseline.pcap`, `unchanged.pcap`, `changed.pcap` | Synthetic ARP observations for the [baseline lab](behavioral-monitoring.md#reproducible-baseline-lab) |
| `doc-fixtures/client.bin`, `other-client.bin` | Seven-byte offline [protocol hypotheses](protocol-experiments.md#offline-hypotheses-first) |

The domain is under `.test`; addresses are `192.0.2.10` and `192.0.2.20`.
The generated `sensor.key` is public deterministic lab material, never a real
sensor credential. Inspect the fixture generator before reusing any bytes.

## Capture and inspect

<!-- docs:run investigation -->
```sh
net capture -read doc-fixtures/investigation.pcap -out doc-fixtures/audit \
  -rules docs/examples/http-observation.yml -conns -dpi=false -geoDB=false
net dump -read doc-fixtures/audit/DNS.ncap.gz -json > doc-fixtures/dns.ndjson
net dump -read doc-fixtures/audit/HTTP.ncap.gz -json > doc-fixtures/http.ndjson
net dump -read doc-fixtures/audit/File.ncap.gz -json > doc-fixtures/files.ndjson
net dump -read doc-fixtures/audit/Alert.ncap.gz -json > doc-fixtures/alerts.ndjson
```

Expect two DNS messages, one HTTP record with `/fixture.txt`, a `File` record
whose stored body is `Netcap synthetic evidence.` followed by a newline, and
a `Documentation HTTP Transfer` rule alert. The rule in
[`docs/examples/http-observation.yml`](examples/http-observation.yml) marks a
known fixture; it does not classify the transfer as malicious.

Inspect `IsComplete`, `CompletenessReason` and `Hashes.SHA256` on the file.
Its legacy `Hash` field is MD5. Preserve both the source capture and the actual
stored bytes; a MIME label or filename is not a content-integrity check.

## Follow the relationship

<!-- docs:run related -->
```sh
net investigate related -read doc-fixtures/audit -type HTTP -ordinal 0 \
  > doc-fixtures/related.json
```

Read relationship labels, scope and limitations in `related.json`. Compare the
HTTP record's Community ID with its Connection and DNS evidence. A temporally
related DNS answer is a candidate explanation, not causal proof. A returned
record ID binds file content; do not reuse it after replacing output.

## Verify a benign control

<!-- docs:run control -->
```sh
net capture -read doc-fixtures/benign.pcap -out doc-fixtures/control \
  -rules docs/examples/http-observation.yml -dpi=false -geoDB=false
```

The control must produce no `Documentation HTTP Transfer` alert. Depending on
empty-writer cleanup, `Alert.ncap.gz` can be absent or contain no matching rows.
A successful compile alone does not establish that a rule matches the intended
traffic or avoids benign input.

## Preserve selected packets

<!-- docs:run packet-export -->
```sh
net investigate packet-evidence -read doc-fixtures/investigation.pcap \
  -bpf 'host 192.0.2.10 and tcp port 8080' -out doc-fixtures/http-evidence.zip
```

The ZIP contains `packets.pcapng` and `manifest.json`. Its selection contains
the eight TCP packets, not the two DNS packets. The manifest binds source and
output hashes; preserve the original ten-packet capture for the DNS context.
Existing ZIP destinations are refused.

## Repeatable checks

`make docs-check NETCAP_BIN=/absolute/path/to/net` runs the marked commands in
a temporary workspace and asserts records, file bytes, the positive/benign
rule cases and the selected packet count. It also checks links, shell syntax,
configuration examples and the baseline lifecycle. It never probes an external
target. Source-only features are labeled separately from v0.15.2 examples.

`make docs-source-check` separately checks protobuf excerpts and concrete rule
expressions against the checkout's schema/engine.
