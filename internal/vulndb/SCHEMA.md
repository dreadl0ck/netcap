# netcap.sqlite

Vulnerability and exploit database shared by netcap (Go, `internal/vulndb`)
and netcap-rs. One SQLite 3 file with FTS5. Replaces `nvd.bleve` and
`exploit-db.bleve` from netcap < v0.10, which only Go could read.

Any change to a table, a tokenizer or the queries below bumps
`schema_version`; readers refuse other versions.

## Tables

| table | columns | notes |
| --- | --- | --- |
| `meta` | `key`, `value` | `format=netcap-vulndb`, `schema_version=1`, `built_at`, `nvd_start_year`, `nvd_count`, `exploit_count` |
| `nvd` | `id` (unique), `description`, `severity`, `v2_score`, `access_vector`, `attack_complexity`, `confidentiality_impact`, `integrity_impact`, `availability_impact`, `base_score` REAL, `base_severity` | English description of each NVD 2.0 CVE; CVSS v2 fields, empty when absent |
| `nvd_versions` | `nvd_rowid`, `version` | Exact version strings per CVE, from vulnerable CPE matches (`versionStartIncluding` plus up to 20 patch versions before `versionEndExcluding`, else the CPE version field), else the first `\d+\.\d+\.?\d*` in the description |
| `nvd_fts` | `description` | FTS5, external content `nvd`, `tokenize='unicode61'` |
| `exploits` | `id` (unique), `file`, `description`, `date`, `author`, `type`, `platform`, `port` | Exploit-DB `files_exploits.csv` by column name; `file` is relative to the bundled `exploitdb/` folder |
| `exploits_fts` | `description` | FTS5, external content `exploits`, `tokenize='unicode61'` |

## Queries

A term becomes an FTS5 phrase: trim it, drop it if it has no letter or digit,
double every `"`, wrap in `"`. Phrases are joined with ` AND `. Results are
ordered by `bm25(...)`, then `id`, and capped at 10.

| lookup | match | extra condition | empty result when |
| --- | --- | --- | --- |
| vulnerabilities(vendor, product, version) | phrases of vendor, product on `nvd_fts` | `nvd_versions.version = version` exactly | no vendor/product phrase, or version empty |
| exploits(vendor, product, version) | phrases of vendor, product, version on `exploits_fts` | none | no phrase |

There is no score threshold: every hit matches all terms. bleve's thresholds
(1.5 for NVD, 2 for exploits) have no FTS5 equivalent and were dropped.

## Reference results

`go test ./internal/vulndb ./internal/dbs` pins the query semantics on small
fixtures. A full build from the 2002–2026 NVD feeds and Exploit-DB on
2026-10-04 holds 400,976 CVEs, 2,233,579 version rows and 46,698 exploits in
299 MB (bleve: 4.1 GB), built in 22 s with a 70 MB peak footprint.
