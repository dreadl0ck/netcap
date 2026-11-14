---
description: Record some of your own traffic, analyze it with Netcap and read the records.
---

# First capture

You will record a few seconds of your own traffic with `tcpdump`, analyze the file with `net` and read the records. Install a [binary distribution](installation.md) first. You also need `tcpdump`, `dig` and `curl`.

## 1. Check the executable

```sh
net --version
```

Note the version, commit and DPI status. Run the commands from a writable directory and use a new output directory for each analysis.

## 2. Record some traffic

List your interfaces with `net util -interfaces`, then start a capture on the one you use for the network:

```sh
sudo tcpdump -i en0 -w office-lan.pcap
```

In a second terminal, make a DNS lookup and a plain HTTP request:

```sh
dig example.com
curl http://neverssl.com
```

Stop `tcpdump` with Ctrl-C. Use `eth0` or `wlan0` instead of `en0` on most Linux machines. The file contains everything your machine sent on that interface, so keep it private.

If you would rather not record anything, use a small public capture such as `http.cap` from Wireshark's sample captures wiki and substitute its name for `office-lan.pcap` below.

## 3. Analyze the file

```sh
net capture -read office-lan.pcap -out office-audit -dpi=false -geoDB=false
```

The command exits after it has written all records. `-dpi=false` lets the command run with nodpi builds and `-geoDB=false` skips the GeoIP database. Enrichment that needs other local databases may report them as unavailable; [database updates](database-updates.md) are optional here.

`office-audit/` now holds one file per record type that occurred in the capture, such as `UDP.ncap.gz`, `TCP.ncap.gz`, `DNS.ncap.gz` and `HTTP.ncap.gz`, plus health files. A type that is missing did not appear in your traffic.

## 4. Inspect and export

```sh
net dump -read office-audit/UDP.ncap.gz -header
net dump -read office-audit/UDP.ncap.gz -fields
net dump -read office-audit/UDP.ncap.gz -json
net dump -read office-audit/UDP.ncap.gz -csv -sep ',' \
  -select Timestamp,SrcPort,DstPort > udp.csv
net dump -read office-audit/DNS.ncap.gz -json
```

The header shows the record type, `NC_UDP`. `-fields` prints one field name per line. `-json` prints one object per record. The CSV header is `Timestamp,SrcPort,DstPort`, and your DNS lookups show up with destination port 53. Raw record timestamps are Unix nanoseconds; the displayed format depends on the options you use.

## 5. Open the local WebUI

Analyze again into a new directory and serve the result:

```sh
net capture -read office-lan.pcap -out office-browser -dpi=false -geoDB=false \
  -http 127.0.0.1:8080
```

Open `http://127.0.0.1:8080`. The process keeps running until you stop it with Ctrl-C. The local API has no authentication, so do not expose it to the Internet. [Web interface](web-interface.md) describes the modes and hosting.

## Next steps

| Question                            | Continue with                      |
| ----------------------------------- | ---------------------------------- |
| How do I capture an interface?      | [Live capture](live-collection.md) |
| How do I select packets or records? | [Filtering](FILTERING.md)          |
| What happened on a connection?      | [Evidence linking](evidence.md)    |
| Which data enriches an observation? | [Resolvers](resolvers.md)          |
