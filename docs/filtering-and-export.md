# CSV, JSON and record inspection

`net dump` reads audit files. It is the command for record inspection and
file-format conversion; `net export` is a Prometheus-oriented exporter.

## Inspect before selecting

```sh
net dump -read analysis/UDP.ncap.gz -header
net dump -read analysis/UDP.ncap.gz -fields
net dump -read analysis/UDP.ncap.gz -json
```

`-fields` lists protobuf names one per line. JSON mode emits newline-delimited
objects, not one enclosing array. Use the record schema for types and meanings.
The structured terminal display is the default; explicitly request CSV or JSON
for machine-readable output.

## Export selected columns

```sh
net dump -read analysis/UDP.ncap.gz -csv -sep ',' \
  -select Timestamp,SrcPort,DstPort > udp.csv
```

CSV's default separator is `;`, so pass `-sep ','` when consumers expect commas.
`-select` orders/selects fields but does not itself request CSV. Nested records,
maps and repeated values require inspection before mapping to a flat table.
Treat CSV output as data; spreadsheet tools may interpret cells as formulas.

## Filter records

```sh
net dump -read analysis/UDP.ncap.gz -filter 'DstPort == 9999' -json
```

Expressions are typed against this file's record type. Keep shell quoting around
the expression, and check errors rather than treating failure as zero matches.
For TCP/UDP numeric ports compare integers; for Connection strings compare
quoted strings. See [Filtering](FILTERING.md).

## Time order

Go v0.15.2 enables timestamp ordering for `dump` through `-sort-time`; inspect
`dump -h` for overrides. Sorting uses bounded-memory temporary files. Stream
completion and concurrent writers mean original file order can differ from
capture time. Sorting changes presentation, not the source evidence or packet
ordering. UTC/string display is separate from raw nanosecond timestamps.

Use a new destination when preserving a prior export: shell `>` truncates an
existing file. This differs from evidence commands that explicitly refuse
replacement. For packet-preserving selection and provenance, use
[`investigate packet-evidence`](evidence.md#export-packet-evidence).
