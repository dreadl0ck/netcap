# File Extraction

File extraction reconstructs available transferred content and emits `File`
metadata. It is distinct from packet payload retention and complete source-PCAP
retention. Encrypted content remains unavailable without a supported plaintext
analysis path.

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

## Usage

```sh
net capture -read traffic.pcap -out file-audit -fileStorage files -dpi=false
net dump -read file-audit/File.ncap.gz -fields
net dump -read file-audit/File.ncap.gz -json
```

Only inspect `File.ncap.gz` when the capture produced file records. The default
storage directory is `files` beneath the analysis output; disable extraction
with `-fileStorage ''`. Protocol coverage and completeness differ by decoder.

## File Audit Records

| Evidence | Interpretation |
| --- | --- |
| `Name`, source URL/metadata | Original advertised name, not a trusted filesystem path |
| `Location` | Stored artifact path |
| SHA-256 storage basename | Content-addressed name with preserved extension |
| Declared/detected content types | Advertised MIME and classifier result can disagree |
| Length/hashes/completeness | Qualify the bytes actually reconstructed |
| Context/connection reference | Link back to the observed transfer |

Current extraction uses SHA-256-based storage names and can retain multiple
hash algorithms. Historical MD5-only examples and connection-derived filenames
are obsolete. Inspect `types/netcap.proto` and emitted fields rather than an
old copied message definition.

## Inspect a synthetic artifact

The [transfer lab](investigation-walkthrough.md) produces a known text file.
Inspect its `Hashes.SHA256`, `IsComplete`, original name and stored `Location`.
`Hash` remains legacy MD5; use the explicit SHA-256 field for the content check.
Magika, MIME detection, executable/script heuristics and YARA are independent
build/configuration-dependent analyses, not interchangeable verdicts.

## YARA workflow

For a YARA-enabled build, keep the local UI running while analyzing a fresh lab
copy:

<!-- docs:serve yara -->
```sh
net capture -read doc-fixtures/investigation.pcap -out doc-fixtures/yara-audit \
  -http 127.0.0.1:8080 -dpi=false -geoDB=false
```

1. Open the YARA page and check engine availability. A `noyara` build cannot
   scan; an unavailable engine or zero enabled rules is not a clean result.
2. Upload [`docs/examples/synthetic-file.yar`](examples/synthetic-file.yar)
   and enable the rule. It looks only for the synthetic body string.
3. Select the lab analysis and scan its extracted file. Expect
   `Netcap_Documentation_Fixture`; this match says nothing about malware.
4. Compare a file without that marker and confirm no match, keeping engine/rule
   status distinct from scan results.

The equivalent local API check, after capture finalization, is below. It creates
`negative.txt` only as a labeled scanner control, not as claimed capture evidence:

<!-- docs:run yara-scan -->
```sh
curl -fsS http://127.0.0.1:8080/api/yara/status > doc-fixtures/yara-status.json
python3 -c 'import json; assert json.load(open("doc-fixtures/yara-status.json"))["available"], "YARA is unavailable"'
curl -fsS -F file=@docs/examples/synthetic-file.yar \
  http://127.0.0.1:8080/api/yara/rules/upload > doc-fixtures/yara-upload.json
net dump -read doc-fixtures/yara-audit/File.ncap.gz -json > doc-fixtures/yara-files.ndjson
python3 -c 'import json,pathlib; r=json.loads(open("doc-fixtures/yara-files.ndjson").readline()); p=pathlib.Path(r["Location"]).resolve(); base=pathlib.Path("doc-fixtures/yara-audit/files").resolve(); json.dump({"filePath":str(p.relative_to(base))},open("doc-fixtures/yara-request.json","w")); (base/"negative.txt").write_text("Synthetic negative scanner control.\n")'
curl -fsS -H 'Content-Type: application/json' --data-binary @doc-fixtures/yara-request.json \
  http://127.0.0.1:8080/api/yara/scan-file > doc-fixtures/yara-positive.json
curl -fsS -H 'Content-Type: application/json' --data-binary '{"filePath":"negative.txt"}' \
  http://127.0.0.1:8080/api/yara/scan-file > doc-fixtures/yara-negative.json
```

`make docs-check` runs this case when YARA is available and reports an explicit
skip otherwise. For native release qualification, require it with
`python3 scripts/check-docs.py --net /absolute/path/to/net --require-yara`.

The WebUI API exposes `/api/yara/status`, `/api/yara/rules` and
`/api/yara/scan-file`; MCP exposes `get_yara_status`, `list_yara_rules` and
`execute_yara_scan`. The latter scans the selected session's files and is
synchronous. Use its [generated contract](mcp/tools.md), not a guessed CLI
`-yara` flag. Uploading rules or scanning is separate from capture-time matching.

## Incomplete content

`-writeincomplete` permits supported paths to write incomplete bodies. A stored
file is not proof of a complete transfer: inspect gaps, parser state, declared
lengths and [stream evidence](reassembly.md). Encodings/decompression can make
stored bytes differ from their on-wire representation.

Transferred files can be executable or hostile. Retain them as evidence; the
fact that Netcap wrote an artifact does not mean it is safe to open. Preserve
the source capture/hash for repeat analysis.
