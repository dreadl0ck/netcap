---
description: Extract transferred files and save them to disk
---

# File Extraction

## Bounded extraction and analysis

`-file-config FILE` loads strict YAML over the defaults in
`internal/decoder/stream/file/config.go`; invalid or unsupported settings fail
instead of silently falling back. Capture admission freezes extraction policy
and private analyzer snapshots. Service helper jobs receive an immutable
`artifact-config.yml` snapshot.

```yaml
file_extraction:
  size_limits:
    max_file_size: 104857600
    max_inflight_bytes: 268435456
    max_files_per_session: 0
  advanced:
    enable_yara_scanning: true
    yara_rules_path: /absolute/path/to/owned-rules
    enable_magika: false
```

```sh
net capture -read traffic.pcap -out ./audit -fileStorage files \
  -file-config extraction.yml -http ""
```

| Boundary | Contract |
| --- | --- |
| Buffers | Raw bodies and each decoded layer use the per-file limit, optional `reassembly.max_buffer_size` ceiling (10 MiB default), and capture-owned in-flight reservations. `max_inflight_bytes` must be at least twice `max_file_size`, at most 1 GiB; `max_file_size` is 1–100 MiB. |
| Stream limits | `-max-stream-bytes=0` disables that reassembly-depth limit, not artifact budgets. Compression/storage policy remains separate. |
| Content fidelity | HTTP files preserve extracted bytes; MIME attachments use structural multipart/base64/quoted-printable parsing. SMTP dot unstuffing and POP3 retained lines preserve binary data/CRLF before extraction. Eight MIME nesting levels and 128 parts are admitted. |
| Publication | Complete blob writes are synced and atomically published without replacing a destination. Duplicate content reuses the blob while retaining File observations. |
| YARA-X | Configured rules must exist and contain enabled rules. Metadata in `yara-rules-meta.json` disables named files. Includes are disabled; independently load bounded sources. Invalid reload retains the previous ruleset and reports failure. |
| Ruleset budget | At most 1,024 enabled files, 1 MiB/source and 16 MiB total; scan results reject more than 4,096 matches. |
| Magika | Optional installed executable, bounded by a 60-second context, 1 MiB stdout and 64 KiB stderr. Executable SHA-256 is recorded; changed executable identity fails. Unix cancellation kills the owned process group. |
| Workers/cache | Two capture-owned workers, 32 queued jobs and 256 MiB active/queued content budget. Cache is capture-local, capped at 1,024 entries/16 MiB. Exhaustion is reported as rejection; this version does not evict retained results. |
| Result identity | `artifact-analysis.json` version 1 binds capture RunID, config/rules/tool digests and content SHA-256. The YARA Go binding version is recorded; its native-library version is not exposed by the binding. |
| Outcomes | Disabled, ready, queued, running, completed, failed, timed-out and cancelled are distinct. Completed YARA carries matched/no-match; Magika carries classified. Queue/cache refusal is counted and recorded in extraction issues, never a clean result. |
| Finalization | Accepted analysis finishes before audit readiness. Analyzer failure preserves the artifact, persists partial coverage and returns an error for requested analysis. Extraction-only partial coverage remains inspectable without converting a successful capture into a scan failure. Result/output persistence failure prevents readiness. |
| Visibility | Files page and file preview show analysis coverage and transfer occurrences; YARA scan APIs distinguish completed scans from failures. `GET /api/artifact-analysis` supports the same explicit input/session selectors as artifact access. Legacy/missing reports are unavailable, not clean. |

Only regular files inside the selected extraction root can be downloaded,
previewed or scanned. Traversal, stored symlinks, nonregular files and unknown
capture selectors are rejected (`internal/artifactio`).

`Hashes.SHA256` identifies exact content; legacy `Hash` remains MD5. Analyzer
enablement requires SHA-256. `IsComplete`/`CompletenessReason` qualify bytes;
`StreamMissingBytes` is unattributed stream loss, not a measured missing-byte
count for every file. General archive recursion remains unsupported.

The original introduction/schema excerpt below describes an older implementation;
the current schema is `types/netcap.proto` and the runtime contract above applies.

## Introduction

Various protocols allow transferring files (e.g: HTTP, POP3) and some are made for the sole purpose of transferring files (FTP, SMB etc).

From a network security monitoring perspective, transferred files are interesting because they can contain malicious software or prohibited content.

Netcap extracts files from HTTP and saves them to disk, for both HTTP responses and HTTP requests.

It uses the **File** audit record type to model the extracted information.

> Future versions will add file extraction support for other protocols as well.

## File Audit Records

The audit record definition for a file looks like this:

```erlang
message File {
    string        Timestamp   = 1;
    string        Name        = 2;
    int64         Length      = 3;
    string        Hash        = 4;
    string        Location    = 5;
    string        Ident       = 6;
    string        Source      = 7;
    string        ContentType = 8;
    PacketContext Context     = 9;
    string        Host        = 10;
    string        ContentTypeDetected = 11;
}
```

As can be seen, the content type indicated by the HTTP header is included, as well as the content type that was detected. In addition, the source of the File is specified (e.g: from HTTP, Mail attachment etc), as well the identifier of the connection where it originated from.

The Hash field currently holds an MD5 hash of the file, Location points to the path on disk where the file is stored.

> This will likely be replaced with a stronger hash function in the future.

## Usage

File capture is enabled by default and will store extracted files in the **files** subdirectory within your output directory. The **-fileStorage** flag allows you to customize this path (relative to the output directory):

```
$ net capture -read traffic.pcap -fileStorage files
```

To disable file extraction, set an empty string:

```
$ net capture -read traffic.pcap -fileStorage ""
```

After capturing, lets inspect the directory contents:

```
$ tree files
files
├── application
│   └── x-gzip
│       └── unknown-193.24.227.12->216.66.80.30-80->60075.gz
├── image
│   └── x-icon
│       └── favicon.ico-193.24.227.12->216.66.80.30-80->60076.ico
└── text
    └── html
        ├── unknown-193.24.227.12->216.66.80.30-80->55031.html
        ├── unknown-193.24.227.12->216.66.80.30-80->55032.html
        ├── unknown-193.24.227.12->216.66.80.30-80->55033.html
        └── unknown-80.237.133.136->192.168.110.10-80->1152.html

6 directories, 6 files
```

As you can see, files are sorted by their MIME types retrieved from classifying them using the go standard library and named after the TCP connection they originated from.

By default, only complete requests and responses are captured, if you also want to extract incomplete data, use the **-writeincomplete** flag:

```
$ net capture -read traffic.pcap -fileStorage files -writeincomplete
```

Dumping a File on the commandline looks like this:

```
$ net dump -read File.ncap.gz -struc
NC_File
Timestamp: "2015-03-08 14:05:29.664213 +0000 UTC"
Name: "ads.bmp"
Length: 126
Hash: "2d5a035011854b04a456b244b15a583b"
Location: "files/image/bmp/ads.bmp-80.239.178.178->192.168.0.51-80->41214.bmp"
Ident: "80.239.178.178->192.168.0.51-80->41214"
Source: "HTTP RESPONSE from /ads.bmp"
Context: <
  SrcIP: "192.168.0.51"
  DstIP: "80.239.178.178"
  SrcPort: "41214"
  DstPort: "80"
>
ContentTypeDetected: "image/bmp"
...
```

For properly exploring files for each host I recommend using the Maltego Integration:

{% content-ref url="maltego-integration.md" %}
[maltego-integration.md](maltego-integration.md)
{% endcontent-ref %}

![](<.gitbook/assets/files (1).png>)
