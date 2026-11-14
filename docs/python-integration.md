# Python readers

The simplest way to read records from Python is `net dump -json`. It writes one JSON object per record and base64-encodes byte values. Your code then does not depend on generated protobuf bindings.

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

The [first capture](quickstart.md) creates this input. Look at the JSON before you pick field names: they come from the record's JSON renderer and can differ from the protobuf and CSV names.

## Find the top talkers with pandas

`Connection` records have one row per connection, with `SrcIP`, `DstIP` and `TotalSize` (bytes in both directions). Export them from the audit directory of a capture:

```sh
net dump -read analysis/Connection.ncap.gz -json > connections.ndjson
```

```python
import pandas as pd

# convert_dates=False keeps TimestampFirst/TimestampLast as integer nanoseconds
conns = pd.read_json("connections.ndjson", lines=True, convert_dates=False)

# Ten hosts that opened the most traffic, in bytes
print(conns.groupby("SrcIP")["TotalSize"].sum().nlargest(10))

# Ten servers that received the most traffic
print(conns.groupby("DstIP")["TotalSize"].sum().nlargest(10))

# Readable start time
conns["start"] = pd.to_datetime(conns["TimestampFirst"], unit="ns")
```

Pandas is optional and installed separately. Keep timestamps as integers until you convert them: going through floating point loses precision on nanosecond values.

## Source code

The separate [pynetcap repository](https://github.com/dreadl0ck/pynetcap) has an NCAP reader and DataFrame helpers. Check that its generated schemas match your Netcap version, and test it on a file you know before you rely on it.

To write your own reader, follow the [record framing](specification.md), generate Python bindings from the matching `types/netcap.proto`, and treat a truncated frame or a gzip integrity error as an error, not as end of file.
