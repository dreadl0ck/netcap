# Python Integration

For current Go records, the simplest Python boundary is `net dump -json`:
one JSON object per record, with schema-specific fields and base64 byte values.
This avoids coupling a Python reader to stale generated protobuf bindings.

## Usage

```sh
net dump -read example-audit/UDP.ncap.gz -json > udp.ndjson
```

```python
import json

with open("udp.ndjson", encoding="utf-8") as source:
    for line in source:
        record = json.loads(line)
        print(record.get("SrcPort"), record.get("DstPort"))
```

Use [the first capture](quickstart.md) to create this input. Inspect the emitted
JSON before selecting names: JSON naming comes from the record's renderer and
can differ from protobuf/CSV field names.

### Read into pandas dataframe

```python
import pandas as pd

frame = pd.read_json("udp.ndjson", lines=True)
print(frame.columns)
```

Pandas is optional and installed separately. Preserve nanosecond integer times
without converting through floating point; large integers can lose precision.

## Source Code

The separate [pynetcap repository](https://github.com/dreadl0ck/pynetcap)
contains an NCAP reader and DataFrame helpers. Its existence is not a compatibility
guarantee with every record in Go v0.15.2. Verify its generated schemas and a
known fixture before using it for current evidence.

For a direct reader, follow the [record framing](specification.md), generate
Python bindings from the matching `types/netcap.proto`, and distinguish clean
EOF from a truncated frame or gzip integrity failure.
