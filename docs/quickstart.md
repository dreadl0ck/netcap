---
description: Analyze a small, synthetic capture and inspect its records.
---

# First capture

This walkthrough uses Go Netcap v0.15.2 and Python 3. It creates two synthetic
Ethernet/IPv4/UDP packets on documentation-only addresses: no traffic is sent.
Install the appropriate [binary distribution](installation.md) first.

## 1. Verify the executable

```sh
net --version
```

Check the printed version, commit and DPI status. Run commands from a writable
working directory. Use a fresh output directory for each analysis.

## 2. Create a benign PCAP

```python
import socket
import struct
from pathlib import Path

def checksum(data):
    if len(data) % 2:
        data += b"\0"
    total = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    while total >> 16:
        total = (total & 65535) + (total >> 16)
    return (~total) & 65535

frames = []
for index in range(2):
    payload = b"netcap documentation fixture"
    udp = struct.pack("!HHHH", 40000, 9999, 8 + len(payload), 0) + payload
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(udp), index,
                     0, 64, 17, 0, socket.inet_aton("192.0.2.10"),
                     socket.inet_aton("192.0.2.20"))
    ip = ip[:10] + struct.pack("!H", checksum(ip)) + ip[12:]
    ethernet = bytes.fromhex("0200000000200200000000100800")
    frames.append(ethernet + ip + udp)

with Path("example.pcap").open("xb") as output:
    output.write(struct.pack("<IHHIIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
    for index, frame in enumerate(frames):
        output.write(struct.pack("<IIII", 1700000000 + index, 0,
                                 len(frame), len(frame)))
        output.write(frame)
```

Save as `example.py` and run `python3 example.py`. Exclusive creation refuses
to replace an existing `example.pcap`.

## 3. Analyze the file

```sh
net capture -read example.pcap -out example-audit -dpi=false -geoDB=false
```

The process exits after flushing records. `-dpi=false` makes this example usable
with nodpi builds; `-geoDB=false` avoids a GeoIP prerequisite. Some other
enrichment may report unavailable local data. [Database updates](database-updates.md)
are optional for this packet-only exercise.

Expect `example-audit/UDP.ncap.gz` with two UDP records, along with other enabled
record files and health artifacts. Empty protocol files are not proof of a
problem: this fixture deliberately has no HTTP, TLS, DNS or credentials.

## 4. Inspect and export

```sh
net dump -read example-audit/UDP.ncap.gz -header
net dump -read example-audit/UDP.ncap.gz -fields
net dump -read example-audit/UDP.ncap.gz -json
net dump -read example-audit/UDP.ncap.gz -csv -sep ',' \
  -select Timestamp,SrcPort,DstPort > udp.csv
```

The header identifies `NC_UDP`. Field discovery prints one protobuf field name
per line. JSON mode emits one object per record; the CSV header is
`Timestamp,SrcPort,DstPort`. Port values are 40000 → 9999. Timestamp formatting
depends on display options; raw record timestamps are Unix nanoseconds.

## 5. Open the local WebUI

Analyze again into another fresh directory:

```sh
net capture -read example.pcap -out example-browser -dpi=false -geoDB=false \
  -http 127.0.0.1:8080
```

Open `http://127.0.0.1:8080`. The explicit HTTP flag keeps the process running;
stop it with Ctrl-C when finished. Do not publish this unauthenticated local API
directly to the Internet. [Web interface](web-interface.md) explains modes and
the hosting boundary.

## Next steps

| Question | Continue with |
| --- | --- |
| How do I capture an interface? | [Live capture](live-collection.md) |
| How do I select packets or records? | [Filtering](FILTERING.md) |
| What happened on a connection? | [Evidence linking](evidence.md) |
| Which data enriches an observation? | [Resolvers](resolvers.md) |
