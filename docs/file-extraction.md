# File Extraction

File extraction reconstructs available transferred content and emits `File`
metadata. It is distinct from packet payload retention and complete source-PCAP
retention. Encrypted content remains unavailable without a supported plaintext
analysis path.

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
