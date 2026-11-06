# netcap.sqlite

Vulnerability and exploit database shared by netcap (Go, `internal/vulndb`)
and netcap-rs. One SQLite 3 file with FTS5. Replaces `nvd.bleve` and
`exploit-db.bleve` from netcap < v0.10, which only Go could read.

Incompatible changes to required tables, tokenizers or matching queries bump
`schema_version`; readers refuse other versions. Additive optional tables use
explicit versioned metadata capabilities. Current readers require schema 2.
The optional `nvd.nvd_rowid` primary-key alias preserves the existing `rowid`
queries and is advertised by `meta.nvd_rowid_alias_version=1`.

## Tables

| table | columns | notes |
| --- | --- | --- |
| `meta` | `key`, `value` | `format=netcap-vulndb`, `schema_version=2`, `built_at`, `nvd_start_year`, `nvd_count`, `exploit_count` |
| `nvd` | `nvd_rowid INTEGER PRIMARY KEY` (alias of `rowid`), `id` (unique), `description`, `severity`, `v2_score`, `access_vector`, `attack_complexity`, `confidentiality_impact`, `integrity_impact`, `availability_impact`, `base_score` REAL, `base_severity`, `configurations` TEXT | Full NVD 2.0 applicability tree as JSON; English description and CVSS fields |
| `nvd_versions` | `nvd_rowid`, `version` | Exact version strings per CVE, from vulnerable CPE matches (`versionStartIncluding` plus up to 20 patch versions before `versionEndExcluding`, else the CPE version field), else the first `\d+\.\d+\.?\d*` in the description |
| `nvd_fts` | `description` | FTS5, external content `nvd`, `tokenize='unicode61'` |
| `nvd_references` (optional) | `nvd_id`, `url`, `source`, `tags` | `meta.nvd_references_version=1`; primary key `(nvd_id,url,source)`, WITHOUT ROWID; `nvd_id` names `nvd.id`; `tags` is a JSON string array |
| `nvd_products` | `nvd_rowid`, `part`, `vendor`, `product` | Indexed concrete vulnerable CPE identities; candidate selection only |
| `exploits` | `id` (unique), `file`, `description`, `date`, `author`, `type`, `platform`, `port` | Exploit-DB `files_exploits.csv` by column name; `file` is relative to the bundled `exploitdb/` folder |
| `exploits_fts` | `description` | FTS5, external content `exploits`, `tokenize='unicode61'` |
| `exploit_cves` | `exploit_id`, `cve_id` | Exact CVE references from the Exploit-DB `codes` column; no title-based applicability |

## Queries

A term becomes an FTS5 phrase: trim it, drop it if it has no letter or digit,
double every `"`, wrap in `"`. Phrases are joined with ` AND `. Results are
ordered by `bm25(...)`, then `id`, and capped at 10.

| lookup | match | extra condition | empty result when |
| --- | --- | --- | --- |
| vulnerabilities(vendor, product, version) | concrete CPE part/vendor/product from `nvd_products` | Evaluate stored AND/OR/negation tree with exact versions and inclusive/exclusive numeric bounds | identity/version unknown, no positively matched vulnerable branch, or unsatisfied/unobserved prerequisites |
| exploits(vendor, product, version) | `exploit_cves` joined to applicable CVEs | Deterministic exploit-ID results, capped at 10 | no structured CVE association |
| VulnerabilityCandidates / ExploitCandidates | FTS phrases described above | Historical text/version search only | no phrase; NVD candidates also require a version |

Text candidates never establish applicability. Unknown OS, edition or target
prerequisites remain unknown; numeric range ordering is not guessed for suffix
versions. Display-name aliases are explicit in `applicability.go`. Runtime findings
retain the observed host and match status; unresolved hosts are not enriched.

Schema 1 readers must not consume schema 2. Rebuild from complete NVD feeds;
the community profile excludes Exploit-DB. Download/serve metadata announces
`vulndb_schema=2`. Other readers, including netcap-rs, must implement schema 2
before consuming these snapshots.

Current builders declare `nvd.nvd_rowid INTEGER PRIMARY KEY` and
`nvd_versions.nvd_rowid REFERENCES nvd(nvd_rowid)`, with `foreign_keys=ON`.
Existing named-column queries, `LastInsertId`, and FTS `content_rowid='rowid'`
continue to use the same integer. `TestRowidAliasForeignKeys` and
`TestNVDReferencesBuildAndDeterminism` require zero `PRAGMA foreign_key_check`
rows and preserve version/reference joins and deterministic bytes.

Pitfall: earlier schema-1 files declared `REFERENCES nvd(rowid)` without a named
primary key, which SQLite rejects during `foreign_key_check`. Rejected
schema-1 files require a fresh download; the correction applies only to new files, with no
in-place migration or claim that an existing candidate was repaired.

## External reference capability

`nvd_references_version=1` preserves NVD 2.0 `references[].{url,source,tags}`.
Only absolute HTTP(S) URLs with a host, no credentials, whitespace, controls,
backslashes or malformed escapes are retained. URLs and source attribution remain
verbatim; duplicate `(url,source)` entries merge sorted unique tags. References
are ordered by URL, then source (binary lexical order); absent tags become `[]`.
No reference body is fetched or stored. Exploit-DB CSV and PoC bodies are not inputs
to the `nvd-only-v3` publication profile; its exploit tables remain empty.

| API | Contract |
| --- | --- |
| Go `Vulnerability.References`, `DB.References(cveID)` | `[]Reference`, JSON `references: [{"url":"…","source":"…","tags":["Exploit"]}]` |
| Rust `Vulnerability.references`, `VulnDb::references(cve_id)` | `Vec<Reference>`, same serializable fields |
| Go/Rust `GET /api/vulnerabilities` | Each vulnerability includes `references`; browse-time CVE join against the installed local database, independent of audit protobuf schema |
| No capability/table, unknown capability version, unknown CVE, or no installed API database | `references: []`; existing CVE matching/ranking/counts unchanged |

The API sidecar reflects the installed database, not the historical capture's
snapshot. A present but corrupt capability returns an error. Reference tags and
source are metadata, not a claim that a linked exploit was verified.

`TestNVDReferencesBuildAndDeterminism` checks NVD ingestion, filtering, JSON,
deduplication, stable ordering/bytes and unchanged counts. Generate its optional
fixture with `NETCAP_REFERENCE_FIXTURE_OUT=/tmp/references.sqlite go test
./internal/dbs -run TestNVDReferencesBuildAndDeterminism -count=1`; in netcap-rs,
run `NETCAP_REFERENCE_FIXTURE_OUT=/tmp/references.sqlite cargo test -p
netcap-vulndb --test references actual_go_nvd_build -- --ignored`.

## Reference results

`go test ./internal/vulndb ./internal/dbs` pins the query semantics on small
fixtures. A schema-1 build from the 2002–2026 NVD feeds and Exploit-DB on
2026-10-04 holds 400,976 CVEs, 2,233,579 version rows and 46,698 exploits in
299 MB (bleve: 4.1 GB), built in 22 s with a 70 MB peak footprint.
