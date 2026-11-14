# File extraction

Netcap rebuilds files from transfers it can read and writes a `File` record for each one. This is separate from `-payload` and from keeping the source PCAP. Encrypted transfers can't be extracted unless Netcap has a way to read the plaintext.

## Extract files from a capture

Analyse a capture of a browser downloading a file over HTTP, then list the extracted files:

```sh
net capture -read http-download.pcap -out file-audit -fileStorage files -dpi=false
net dump -read file-audit/File.ncap.gz -fields
net dump -read file-audit/File.ncap.gz -json
```

Extracted files are stored in `files` inside the output directory. To change the directory, pass another name to `-fileStorage`. To turn extraction off, use `-fileStorage ''`. `File.ncap.gz` exists only if the capture contained files. Which protocols are covered, and how completely, depends on the decoder.

To check a download, compare `Hashes.SHA256` in the record with `shasum -a 256` of the file you downloaded, or with the hash the vendor publishes. The `Hash` field is MD5, so use `Hashes.SHA256`.

## File records

| Field                            | Meaning                                                               |
| -------------------------------- | --------------------------------------------------------------------- |
| `Name`, source URL/metadata      | The name the sender gave the file. Don't use it as a filesystem path. |
| `Location`                       | Where Netcap stored the file                                          |
| SHA-256 storage basename         | Content hash used as the file name, with the original extension       |
| Declared / detected content type | The advertised MIME type and the classifier result, which can differ  |
| Length, hashes, completeness     | Describe the bytes Netcap actually rebuilt                            |
| Context / connection reference   | Link back to the transfer the file came from                          |

Check `types/netcap.proto` or `dump -fields` for the full list. `IsComplete` and `CompletenessReason` say whether the bytes are complete. `StreamMissingBytes` counts stream loss that can't be attributed to a particular file, so it is not a missing-byte count for each file. Archives such as ZIP are not unpacked recursively.

## Configure extraction

`-file-config FILE` loads a YAML file over the defaults. An invalid or unsupported setting makes the capture fail instead of being ignored.

```yaml
file_extraction:
  size_limits:
    max_file_size: 104857600
    max_inflight_bytes: 268435456
    max_files_per_session: 0
  advanced:
    enable_yara_scanning: true
    yara_rules_path: /absolute/path/to/your-rules
    enable_magika: false
```

```sh
net capture -read http-download.pcap -out ./audit -fileStorage files \
  -file-config extraction.yml -http ""
```

| Setting or behaviour | Details                                                                                                                                                                                                                                                                                                                          |
| -------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Size limits          | `max_file_size` is 1 to 100 MiB. `max_inflight_bytes` is at least twice `max_file_size` and at most 1 GiB. `reassembly.max_buffer_size` optionally caps buffers (default 10 MiB).                                                                                                                                                |
| Stream depth         | `-max-stream-bytes=0` removes the limit on reassembly depth. It does not lift the extraction limits above.                                                                                                                                                                                                                       |
| Content              | HTTP files keep the extracted bytes. Email attachments are parsed as multipart, base64 or quoted-printable. SMTP dot-stuffing is removed and POP3 lines keep binary data and CRLF. Up to 8 MIME nesting levels and 128 parts are read.                                                                                           |
| Storage              | Files are written completely, then published atomically without overwriting an existing file. Identical content shares one stored file, but each transfer still gets its own `File` record.                                                                                                                                      |
| YARA-X               | The rules must exist and contain enabled rules. `yara-rules-meta.json` can disable named files. Includes are disabled. If a reload fails, the previous ruleset stays active and the failure is reported. Limits: 1,024 enabled files, 1 MiB per source, 16 MiB total, 4,096 matches per scan.                                    |
| Magika               | Needs the Magika executable installed. Each run has a 60 second timeout, 1 MiB of stdout and 64 KiB of stderr. Netcap records the executable's SHA-256 and fails if it changes. On Unix a cancelled run kills the whole process group.                                                                                           |
| Workers and cache    | Two workers, 32 queued jobs and 256 MiB of queued and active content. The result cache holds up to 1,024 entries and 16 MiB. When a limit is hit, new jobs are rejected and existing results are kept.                                                                                                                           |
| Result file          | `artifact-analysis.json` (version 1) records the capture run ID, the config, rules and tool digests, and the content SHA-256.                                                                                                                                                                                                    |
| Analysis states      | Disabled, ready, queued, running, completed, failed, timed out, cancelled. A completed YARA run says matched or no match, and a completed Magika run says classified. Jobs refused by the queue or cache are counted and listed in the extraction issues.                                                                        |
| End of capture       | Accepted analysis jobs finish before the output is marked ready. If an analyzer fails, the file is kept, partial coverage is saved and the capture reports an error for the analysis you asked for. If you only asked for extraction, the capture still succeeds. If the results can't be saved, the output is not marked ready. |
| Web interface        | The Files page and file preview show analysis coverage and where a file was transferred. `GET /api/artifact-analysis` accepts the same input and session selectors as file downloads. Reports that are missing are shown as unavailable.                                                                                         |

Only regular files inside the extraction directory can be downloaded, previewed or scanned. Path traversal, symlinks, other file types and unknown capture selectors are rejected.

## Scan extracted files with YARA

YARA scanning needs a build with YARA support. A `noyara` build can't scan. Keep the web interface running while you analyse the capture:

```sh
net capture -read http-download.pcap -out file-audit \
  -http 127.0.0.1:8080 -dpi=false -geoDB=false
```

1. Open the YARA page and check that the engine is available. An unavailable engine, or a ruleset with no enabled rules, scans nothing.
2. Upload your rule file and enable it. Use your own rules or a public ruleset.
3. Select the analysis and scan the extracted file.

The same steps through the API, after the capture has finished:

```sh
curl -fsS http://127.0.0.1:8080/api/yara/status
curl -fsS -F file=@your-rules.yar http://127.0.0.1:8080/api/yara/rules/upload
net dump -read file-audit/File.ncap.gz -json
curl -fsS -H 'Content-Type: application/json' \
  --data '{"filePath":"<path of the stored file, relative to the files directory>"}' \
  http://127.0.0.1:8080/api/yara/scan-file
```

The web API also has `/api/yara/rules`. MCP offers `get_yara_status`, `list_yara_rules` and `execute_yara_scan`, which scans the files of the selected session and returns when the scan is done. See the [generated contract](mcp/tools.md). There is no `-yara` capture flag, and uploading rules or scanning is separate from capture-time matching.

## Incomplete content

`-writeincomplete` lets supported decoders write incomplete bodies. A stored file can still be incomplete, so check gaps, parser state, declared lengths and [stream evidence](reassembly.md). Compression and transfer encodings mean the stored bytes can differ from what was on the wire.

Transferred files can be executables or malware. Keep them as evidence and don't open them on a machine you care about. Keep the source capture and its hash so you can run the analysis again.
