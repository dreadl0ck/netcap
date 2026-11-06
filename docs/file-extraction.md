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

## Incomplete content

`-writeincomplete` permits supported paths to write incomplete bodies. A stored
file is not proof of a complete transfer: inspect gaps, parser state, declared
lengths and [stream evidence](reassembly.md). Encodings/decompression can make
stored bytes differ from their on-wire representation.

Transferred files can be executable or hostile. Retain them as evidence; the
fact that Netcap wrote an artifact does not mean it is safe to open. Preserve
the source capture/hash for repeat analysis.
