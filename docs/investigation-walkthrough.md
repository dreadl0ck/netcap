# Investigate a file transfer

This walkthrough follows a file downloaded over plain HTTP: the DNS lookup, the HTTP request, the extracted file and the packets that back it up. You need `tcpdump`, `curl`, a web server you control and the `net` executable. [First capture](quickstart.md) covers the basics.

## Record the transfer

On a machine in your LAN, serve a directory that contains `report.txt`:

```sh
python3 -m http.server 8080
```

On your workstation, record the traffic to that server and DNS, then download the file by hostname so the lookup is part of the capture. The server here is `fileserver.lan` at 192.168.1.20:

```sh
sudo tcpdump -i en0 -w file-transfer.pcap 'host 192.168.1.20 or port 53'
```

```sh
curl -O http://fileserver.lan:8080/report.txt
shasum -a 256 report.txt
```

Stop `tcpdump` with Ctrl-C and write down the SHA-256 of the downloaded file.

## Analyze and dump the records

```sh
net capture -read file-transfer.pcap -out transfer-audit -conns -dpi=false -geoDB=false
net dump -read transfer-audit/DNS.ncap.gz -json > dns.ndjson
net dump -read transfer-audit/HTTP.ncap.gz -json > http.ndjson
net dump -read transfer-audit/File.ncap.gz -json > files.ndjson
```

`dns.ndjson` holds the lookup for `fileserver.lan`. `http.ndjson` holds the request for `/report.txt`. `files.ndjson` holds the extracted file, and its content is stored under `transfer-audit/files/`.

## Check the file

Open the `File` record. `Hashes.SHA256` should match the `shasum` output from the download. The older `Hash` field is MD5. `IsComplete` and `CompletenessReason` tell you whether Netcap saw the whole body, for example when packets were lost or the transfer was cut off.

Keep the source capture and the extracted file. Trust the hash for what the bytes are, not the filename or MIME type in the record.

## Follow the connection

```sh
net investigate related -read transfer-audit -type HTTP -ordinal 0 > related.json
```

`related.json` lists the records related to the first HTTP record, with a label for each relationship. Compare the HTTP record's Community ID with the Connection and DNS records. A DNS answer that arrived just before the request is probably the lookup behind it. Record IDs belong to one output directory, so do not reuse them after you analyze into it again.

## Save the packets

```sh
net investigate packet-evidence -read file-transfer.pcap \
  -bpf 'host 192.168.1.20 and tcp port 8080' -out http-evidence.zip
```

The ZIP contains `packets.pcapng` with the selected TCP packets and `manifest.json` with hashes of the source capture and the output. The DNS packets are not selected, so keep the original capture for the lookup. `net` refuses to overwrite an existing ZIP.
